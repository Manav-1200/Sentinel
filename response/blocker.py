"""
response/blocker.py
=======================
Automatic IP blocking via nftables (preferred) or iptables (fallback),
triggered on confirmed ATTACK-level verdicts.

Privilege model:
-------------------
Sentinel does not run as root. Live capture already works without it
via `setcap cap_net_raw,cap_net_admin=eip` applied to the Python
binary (see README/dev notes) — and CAP_NET_ADMIN, already granted
for that same reason, is exactly the capability the kernel requires
to modify firewall rules. No sudo, no password prompts, no running
Sentinel as root. This module assumes that capability is already
present (same assumption capture already makes) and will fail loudly
in dry_run-equivalent fashion (logged, non-fatal) if it isn't —
never silently pretend a block succeeded when it didn't.

NOTE: cap_net_admin resets whenever the Python binary is replaced
(pacman update, pyenv switch, etc.) — same caveat you already track
for cap_net_raw. Re-run the setcap command after any Python update.

Backend selection:
---------------------
nftables is tried first (Arch's native firewall subsystem since
replacing iptables-as-default). If the `nft` binary isn't found,
falls back to iptables (via the iptables-nft compat binary, or true
legacy iptables — both expose the same CLI). Detected once at
startup; if you have both installed, nftables always wins, since it's
the more capable/modern backend and — crucially — supports native,
kernel-side timeouts on set elements, which iptables does not.

Why a dedicated table/chain (nftables) rather than editing existing
rules:
-----------------------------------------------------------------------
All of Sentinel's blocks live in their own `inet sentinel` table, with
their own `block` chain and `blocked_ips` set. This means:
  - Sentinel never touches, reorders, or risks corrupting any of your
    OWN existing firewall rules (elsewhere in `nft ruleset`).
  - Cleanly removing ALL of Sentinel's blocks (e.g. on shutdown, or
    for debugging) is one `nft delete table inet sentinel` away.
  - The `blocked_ips` set uses `timeout` on each element
    (response.block_duration_minutes), so the kernel itself expires
    blocks — no polling thread needed for nftables' expiry. This is
    the single biggest reliability win of nftables over iptables here:
    an iptables rule has no concept of "expire yourself in 60
    minutes," so that backend needs a background sweep thread instead
    (see _IptablesBackend below), which is one more thing that can
    silently stop working (e.g. thread dies) without Sentinel noticing.

Safety rules enforced regardless of backend:
------------------------------------------------
  - response.whitelist_ips is checked BEFORE every single block
    attempt, never bypassable by any caller.
  - Private/LAN-range IPs (RFC 1918, loopback, link-local) are never
    blocked unless response.block_private_ranges is explicitly true —
    defaults to false, since blocking your own LAN traffic by mistake
    (e.g. a false-positive on a local device) could break your own
    network access to fix it.
  - response.dry_run logs exactly what WOULD be blocked/unblocked,
    with the same messages as a real action, but issues no actual
    firewall commands — the intended safe default for development,
    matching main.py's --dry-run flag and print_banner()'s existing
    dry-run notice.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("sentinel.blocker")

_NFT_TABLE = "sentinel"
_NFT_CHAIN = "block"
_NFT_SET = "blocked_ips"


@dataclass
class BlockResult:
    """Outcome of a single block/unblock attempt — always returned,
    never raised, so callers (main.py) never need a try/except around
    a block call in the hot detection path."""
    ip: str
    action: str          # "block" or "unblock"
    applied: bool         # True if a real firewall change was made
    reason: Optional[str] = None  # Why it was skipped, if applied=False and not dry_run
    dry_run: bool = False


class IPBlocker:
    """
    Applies and expires IP blocks via nftables or iptables. Construct
    ONE instance and share it across the pipeline (same pattern as
    every other Phase 1-3 tracker/manager) — the background expiry
    thread (iptables backend only) and in-memory blocked-IP bookkeeping
    both depend on a single shared instance.
    """

    def __init__(self, config: dict):
        response_config = config.get("response", {})

        self.dry_run: bool = bool(response_config.get("dry_run", True))
        self.block_duration_minutes: float = float(response_config.get("block_duration_minutes", 60))
        self.whitelist_ips: set[str] = set(response_config.get("whitelist_ips", []))
        self.block_private_ranges: bool = bool(response_config.get("block_private_ranges", False))

        self.blocks_log_path: str = config.get("storage", {}).get("blocks_log", "data/logs/blocks.log")

        self._lock = threading.Lock()
        # ip -> unix expiry timestamp. Authoritative bookkeeping used
        # by BOTH backends for is_blocked()/currently_blocked() and by
        # the iptables backend's expiry sweep. nftables also tracks
        # expiry natively in the kernel via set-element timeouts, but
        # this dict is kept in sync regardless, so callers get a
        # single consistent API no matter which backend is active.
        self._blocked_until: dict[str, float] = {}

        self._backend = self._select_backend()

        self._stop_sweep = threading.Event()
        self._sweep_thread: Optional[threading.Thread] = None
        if isinstance(self._backend, _IptablesBackend) and not self.dry_run:
            # Only the iptables backend needs a polling expiry thread —
            # nftables expires set elements natively in-kernel. See
            # module docstring for why this matters.
            self._sweep_thread = threading.Thread(
                target=self._expiry_sweep_loop, daemon=True, name="sentinel-block-expiry"
            )
            self._sweep_thread.start()

        if not self.dry_run:
            self._backend.setup()

    def block(self, ip: str, reason: str = "") -> BlockResult:
        """
        Block `ip` for response.block_duration_minutes. Safe to call
        repeatedly for the same IP (e.g. a scanner still active past
        its first block) — this simply refreshes/extends the existing
        block rather than erroring or creating a duplicate rule.

        Never raises. A firewall-level failure (backend command
        errored, no backend available at all) is logged and returned
        as applied=False with `reason` set — callers should treat this
        as "detection continues normally, but this attacker is not
        actually being blocked right now," never as fatal.
        """
        skip_reason = self._check_skip(ip)
        if skip_reason is not None:
            logger.info("Not blocking %s: %s", ip, skip_reason)
            return BlockResult(ip=ip, action="block", applied=False, reason=skip_reason, dry_run=self.dry_run)

        expiry = time.time() + (self.block_duration_minutes * 60)

        if self.dry_run:
            logger.info(
                "[DRY RUN] Would block %s for %.0f minutes. Reason: %s",
                ip, self.block_duration_minutes, reason or "n/a",
            )
            with self._lock:
                self._blocked_until[ip] = expiry
            self._log_action("block", ip, reason, dry_run=True)
            return BlockResult(ip=ip, action="block", applied=False, dry_run=True)

        try:
            self._backend.block(ip, self.block_duration_minutes)
        except Exception as e:
            logger.error("Failed to block %s via %s: %s", ip, self._backend.name, e)
            return BlockResult(ip=ip, action="block", applied=False, reason=str(e))

        with self._lock:
            self._blocked_until[ip] = expiry
        logger.warning("Blocked %s for %.0f minutes. Reason: %s", ip, self.block_duration_minutes, reason or "n/a")
        self._log_action("block", ip, reason, dry_run=False)
        return BlockResult(ip=ip, action="block", applied=True)

    def unblock(self, ip: str) -> BlockResult:
        """
        Remove a block early (manual override / operator command).
        Natural expiry (nftables set timeout, or the iptables sweep
        thread) does NOT go through this method — see
        _expiry_sweep_loop for that path — but calling this manually
        is always safe regardless of how the block was created.
        """
        if self.dry_run:
            logger.info("[DRY RUN] Would unblock %s.", ip)
            with self._lock:
                self._blocked_until.pop(ip, None)
            self._log_action("unblock", ip, "manual", dry_run=True)
            return BlockResult(ip=ip, action="unblock", applied=False, dry_run=True)

        try:
            self._backend.unblock(ip)
        except Exception as e:
            logger.error("Failed to unblock %s via %s: %s", ip, self._backend.name, e)
            return BlockResult(ip=ip, action="unblock", applied=False, reason=str(e))

        with self._lock:
            self._blocked_until.pop(ip, None)
        logger.info("Unblocked %s.", ip)
        self._log_action("unblock", ip, "manual", dry_run=False)
        return BlockResult(ip=ip, action="unblock", applied=True)

    def is_blocked(self, ip: str) -> bool:
        """True if `ip` currently has an active (non-expired) block."""
        with self._lock:
            expiry = self._blocked_until.get(ip)
            return expiry is not None and expiry > time.time()

    def currently_blocked(self) -> dict[str, float]:
        """Returns {ip: seconds_remaining} for every active block."""
        now = time.time()
        with self._lock:
            return {
                ip: round(expiry - now, 1)
                for ip, expiry in self._blocked_until.items()
                if expiry > now
            }

    def shutdown(self) -> None:
        """
        Stop the expiry sweep thread (iptables backend only) cleanly.
        Does NOT remove active blocks — an in-progress attack should
        stay blocked across a restart; only the sweep thread itself is
        stopped. Call this from main.py's KeyboardInterrupt handler,
        alongside sniffer.stop().
        """
        self._stop_sweep.set()
        if self._sweep_thread is not None:
            self._sweep_thread.join(timeout=2)

    # ------------------------------------------------------------
    # Internal — safety checks
    # ------------------------------------------------------------

    def _check_skip(self, ip: str) -> Optional[str]:
        """Returns a human-readable reason to skip blocking `ip`, or
        None if it's safe to proceed."""
        if ip in self.whitelist_ips:
            return "IP is in response.whitelist_ips"

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return f"'{ip}' is not a valid IP address"

        if addr.is_loopback:
            return "loopback address, never blocked"

        if (addr.is_private or addr.is_link_local) and not self.block_private_ranges:
            return "private/LAN address and response.block_private_ranges is false"

        return None

    # ------------------------------------------------------------
    # Internal — backend selection
    # ------------------------------------------------------------

    def _select_backend(self):
        if shutil.which("nft") is not None:
            logger.info("Using nftables backend for IP blocking.")
            return _NftablesBackend()
        if shutil.which("iptables") is not None:
            logger.info("Using iptables backend for IP blocking (nft not found).")
            return _IptablesBackend()
        logger.warning(
            "Neither 'nft' nor 'iptables' found on PATH. Auto-blocking will log actions "
            "but cannot actually apply them until one is installed."
        )
        return _NullBackend()

    # ------------------------------------------------------------
    # Internal — iptables-only expiry sweep
    # ------------------------------------------------------------

    def _expiry_sweep_loop(self) -> None:
        """
        Background thread (iptables backend only): every 15 seconds,
        checks for blocks past their expiry and removes the
        corresponding iptables rule. nftables never needs this — its
        set elements expire natively in-kernel — see module docstring.
        """
        while not self._stop_sweep.wait(timeout=15):
            now = time.time()
            with self._lock:
                expired = [ip for ip, expiry in self._blocked_until.items() if expiry <= now]
            for ip in expired:
                try:
                    self._backend.unblock(ip)
                    logger.info("Block on %s expired (%.0f min elapsed) — removed.", ip, self.block_duration_minutes)
                except Exception as e:
                    logger.error("Failed to remove expired block on %s: %s", ip, e)
                finally:
                    with self._lock:
                        self._blocked_until.pop(ip, None)
                    self._log_action("unblock", ip, "expired", dry_run=False)

    # ------------------------------------------------------------
    # Internal — audit logging
    # ------------------------------------------------------------

    def _log_action(self, action: str, ip: str, reason: str, dry_run: bool) -> None:
        os.makedirs(os.path.dirname(self.blocks_log_path), exist_ok=True)
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "ip": ip,
            "reason": reason,
            "dry_run": dry_run,
            "backend": getattr(self._backend, "name", "none"),
        }
        with open(self.blocks_log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")


# ------------------------------------------------------------
# Backends
# ------------------------------------------------------------

class _NftablesBackend:
    """
    Manages a dedicated `inet sentinel` table/chain/set. Blocks are
    added as elements of a `blocked_ips` set with a native timeout —
    the kernel removes expired elements on its own, no polling needed.
    """
    name = "nftables"

    def setup(self) -> None:
        """
        Idempotently creates the table/chain/set if they don't already
        exist. Safe to call every startup — `add table`/`add chain`/
        `add set` are no-ops if the object is already present.
        """
        self._run(["nft", "add", "table", "inet", _NFT_TABLE])
        self._run([
            "nft", "add", "chain", "inet", _NFT_TABLE, _NFT_CHAIN,
            "{", "type", "filter", "hook", "input", "priority", "-10", ";", "}",
        ])
        self._run([
            "nft", "add", "set", "inet", _NFT_TABLE, _NFT_SET,
            "{", "type", "ipv4_addr", ";", "flags", "timeout", ";", "}",
        ])
        # Rule dropping anything in the set — added once; re-adding an
        # identical rule on every startup would create duplicates, so
        # this checks first via the ruleset listing.
        existing = self._run(["nft", "list", "chain", "inet", _NFT_TABLE, _NFT_CHAIN], check=False)
        if existing is not None and f"@{_NFT_SET}" not in existing:
            self._run([
                "nft", "add", "rule", "inet", _NFT_TABLE, _NFT_CHAIN,
                "ip", "saddr", "@" + _NFT_SET, "drop",
            ])

    def block(self, ip: str, duration_minutes: float) -> None:
        self._run([
            "nft", "add", "element", "inet", _NFT_TABLE, _NFT_SET,
            "{", f"{ip} timeout {int(duration_minutes)}m", "}",
        ])

    def unblock(self, ip: str) -> None:
        self._run(["nft", "delete", "element", "inet", _NFT_TABLE, _NFT_SET, "{", ip, "}"], check=False)

    def _run(self, cmd: list[str], check: bool = True) -> Optional[str]:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            if check:
                raise RuntimeError(f"'{' '.join(cmd)}' failed: {result.stderr.strip()}")
            return None
        return result.stdout


class _IptablesBackend:
    """
    Fallback for systems without `nft`. Adds/removes a single DROP
    rule per blocked IP in the INPUT chain. Unlike nftables, iptables
    rules have no concept of expiry — IPBlocker's _expiry_sweep_loop
    handles removing rules once their tracked expiry passes.
    """
    name = "iptables"

    def setup(self) -> None:
        # No dedicated chain here (kept simple/portable for the
        # fallback path) — rules are tagged with a recognisable
        # comment instead, so they're easy to identify and are never
        # confused with the user's own pre-existing rules.
        pass

    def block(self, ip: str, duration_minutes: float) -> None:
        if self._rule_exists(ip):
            return  # Already blocked — refreshing expiry is handled by IPBlocker's own bookkeeping.
        self._run([
            "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP",
            "-m", "comment", "--comment", "sentinel-block",
        ])

    def unblock(self, ip: str) -> None:
        self._run([
            "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP",
            "-m", "comment", "--comment", "sentinel-block",
        ], check=False)

    def _rule_exists(self, ip: str) -> bool:
        result = subprocess.run(
            ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", "sentinel-block"],
            capture_output=True, text=True,
        )
        return result.returncode == 0

    def _run(self, cmd: list[str], check: bool = True) -> None:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0 and check:
            raise RuntimeError(f"'{' '.join(cmd)}' failed: {result.stderr.strip()}")


class _NullBackend:
    """
    Used when neither nft nor iptables is found on PATH. Every call
    raises, so IPBlocker.block()/unblock() correctly report
    applied=False with a clear reason, rather than silently pretending
    to succeed.
    """
    name = "none"

    def setup(self) -> None:
        pass

    def block(self, ip: str, duration_minutes: float) -> None:
        raise RuntimeError("no firewall backend available (neither 'nft' nor 'iptables' found on PATH)")

    def unblock(self, ip: str) -> None:
        raise RuntimeError("no firewall backend available (neither 'nft' nor 'iptables' found on PATH)")

