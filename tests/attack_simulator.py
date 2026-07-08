"""
tests/attack_simulator.py
============================
Generates real, controlled attack traffic so Sentinel's self-labelling
pipeline (pipeline/labeller.py) has genuine attack examples to learn
from, not just corrected false positives on ordinary traffic.

Why this exists (see PHASES.md Phase 2.4):
----------------------------------------------
Testing so far (July 2026) found that EVERY labelled sample in the
database was "benign" — not because anything was broken, but because
every flow tested really was ordinary traffic (DNS, HTTPS, mDNS) that
the anomaly detector occasionally over-flags. The LLM correctly
recognised all of it as benign. That's the safety net working as
designed, but it also means the classifier has never seen a single
real attack example, so it correctly refuses to train (needs 2+
distinct classes — see detection/classifier.py's MIN_DISTINCT_CLASSES
check). This script exists specifically to produce that missing real
attack data.

IMPORTANT — targeting and what actually gets captured:
------------------------------------------------------
Two target modes are supported:

  --target localhost (127.0.0.1)
      Safest option, matches the original Phase 2 plan's safety
      note. HOWEVER: Phase 1 testing found that loopback / same-host
      traffic hairpins at the kernel level and NEVER reaches Scapy's
      capture layer (see PHASES.md 1.4's "real Linux networking
      quirk" note). This mode is included for completeness and for
      testing the simulator's own traffic generation in isolation,
      but Sentinel will NOT see or label any of it. Do not expect
      training data from this mode.

  --target lan
      Sends traffic to your own LAN IP (auto-detected, or pass
      --lan-ip explicitly) FROM THE SAME MACHINE. This is real
      interface traffic, not loopback, so it DOES reach Sentinel's
      capture layer — this is the mode that actually produces
      labelled training data. Still entirely contained to your own
      machine and local network; never sends anything externally.

Safety:
----------
- Refuses to run against ANY address that is not 127.0.0.1 or in a
  private range (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
  This is a hard validation check, not just documentation — see
  _validate_target().
- Flood duration and rate are capped by CLI arguments with sane
  defaults; there is no "unlimited" mode.

Known limitation — port scan simulation is NOT included:
------------------------------------------------------------
A port-scan mode is deliberately left out of this script. As of
today, NO detector in Sentinel can see a port scan at all (see
PHASES.md's Phase 6 backlog: "Port scan tracker" is not yet built —
per-flow Isolation Forest sees only unremarkable individual flows,
and detection/ddos_tracker.py's GlobalRateTracker tracks distinct
SOURCES, not distinct destination PORTS from one source). Simulating
a scan today would produce real traffic but zero labelled samples —
confirmed directly via a real `nmap -sT` scan during Phase 2 testing.
Add a --mode port_scan option here once PortScanTracker exists.

Usage:
    # Safe no-op against loopback (won't be captured by Sentinel,
    # useful only for testing this script itself):
    python tests/attack_simulator.py --mode flood --target localhost

    # Real flood against your own LAN IP -- run this in a second
    # terminal WHILE `python main.py` is running and past warm-up:
    python tests/attack_simulator.py --mode flood --target lan

    # Generate normal/benign traffic (delegates to warmup_traffic.sh
    # if present, otherwise a minimal built-in fallback):
    python tests/attack_simulator.py --mode normal
"""

from __future__ import annotations

import argparse
import ipaddress
import socket
import subprocess
import sys
import time
from pathlib import Path


# Hard safety allowlist — traffic may ONLY be sent to these ranges.
# This is enforced in code, not just documented, per the original
# Phase 2.4 plan's safety note ("never point at external IPs").
_ALLOWED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

DEFAULT_FLOOD_DURATION_SECONDS = 5
DEFAULT_FLOOD_PORT = 9999
# Comfortably above FLOOD_PACKETS_PER_SECOND_THRESHOLD (1000, see
# detection/anomaly.py) and above FLOOD_MIN_PACKETS (20) so the
# deterministic flood guard reliably fires rather than producing a
# borderline case.
DEFAULT_PACKETS_PER_SECOND = 3000


def _validate_target(ip_str: str) -> None:
    """
    Raise ValueError if the given IP is not in an allowed range.
    Called before ANY traffic is sent — this is the actual safety
    enforcement, not just a comment.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        raise ValueError(f"'{ip_str}' is not a valid IP address.")

    if not any(ip in network for network in _ALLOWED_NETWORKS):
        raise ValueError(
            f"Refusing to send traffic to '{ip_str}' — it is not localhost or "
            f"a private-range address. This script will only ever target "
            f"127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, or 192.168.0.0/16. "
            f"Never point attack simulation at external/public IPs."
        )


def _detect_lan_ip() -> str:
    """
    Best-effort auto-detection of this machine's own LAN IP, by
    opening a UDP socket toward a private address and reading back
    the local address the OS chose (no packets are actually sent —
    UDP connect() just performs route resolution).
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("192.168.0.1", 80))
        return s.getsockname()[0]


def simulate_flood(
    target_ip: str,
    port: int = DEFAULT_FLOOD_PORT,
    duration_seconds: int = DEFAULT_FLOOD_DURATION_SECONDS,
    packets_per_second: int = DEFAULT_PACKETS_PER_SECOND,
) -> None:
    """
    Sends a high-rate burst of UDP packets to (target_ip, port) for
    duration_seconds, at approximately packets_per_second.

    This is a UDP flood specifically (not TCP SYN) because it needs
    no raw-socket / root privileges to send, and the flood guard in
    detection/anomaly.py triggers on packets_per_second alone,
    regardless of protocol.

    Nothing needs to be listening on `port` — the goal is traffic
    volume for Sentinel to observe, not a successful connection.
    Packets will generate ICMP "port unreachable" replies if nothing
    is listening; this is expected and harmless.
    """
    _validate_target(target_ip)

    total_packets = duration_seconds * packets_per_second
    interval = 1.0 / packets_per_second
    payload = b"sentinel-attack-simulator-flood-test"

    print(
        f"[attack_simulator] Sending ~{total_packets} UDP packets to "
        f"{target_ip}:{port} over {duration_seconds}s "
        f"(~{packets_per_second} pkts/sec)..."
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    start = time.monotonic()
    try:
        while time.monotonic() - start < duration_seconds:
            sock.sendto(payload, (target_ip, port))
            sent += 1
            # Best-effort pacing -- exact timing isn't critical, the
            # flood guard's threshold has generous headroom (see
            # DEFAULT_PACKETS_PER_SECOND comment above).
            time.sleep(interval)
    finally:
        sock.close()

    elapsed = time.monotonic() - start
    print(f"[attack_simulator] Done. Sent {sent} packets in {elapsed:.2f}s "
          f"(~{sent / elapsed:.0f} pkts/sec actual).")

    if target_ip.startswith("127."):
        print(
            "[attack_simulator] NOTE: target was 127.0.0.1 (loopback) -- per "
            "PHASES.md's documented hairpin-routing finding, this traffic will "
            "NOT reach Sentinel's capture layer and will NOT produce any "
            "labelled samples. Use --target lan for traffic Sentinel can "
            "actually see."
        )


def simulate_normal(config_dir: Path) -> None:
    """
    Generates a burst of normal/benign traffic. Delegates to the
    existing warmup_traffic.sh if present (it already covers DNS,
    HTTPS, ICMP, and discovery traffic variety -- no need to duplicate
    that logic here), falling back to a minimal built-in version if
    the script isn't found (e.g. running from a different working
    directory).
    """
    warmup_script = config_dir / "warmup_traffic.sh"
    if warmup_script.exists():
        print(f"[attack_simulator] Delegating to {warmup_script}...")
        subprocess.run(["bash", str(warmup_script)], check=False)
        return

    print(
        "[attack_simulator] warmup_traffic.sh not found -- running a minimal "
        "built-in fallback (DNS lookups + ICMP pings only)."
    )
    for domain in ("example.com", "wikipedia.org", "github.com"):
        subprocess.run(
            ["curl", "-s", "--max-time", "2", f"https://{domain}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
    for target in ("8.8.8.8", "1.1.1.1"):
        subprocess.run(
            ["ping", "-c", "2", target],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
    print("[attack_simulator] Done.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Sentinel attack simulator -- generates real, controlled attack "
            "and normal traffic against localhost or your own LAN IP ONLY. "
            "Never targets external addresses (enforced, not just documented)."
        )
    )
    parser.add_argument(
        "--mode", choices=["flood", "normal"], required=True,
        help="'flood' generates a UDP flood to trigger the flood-rate guard. "
             "'normal' generates benign traffic variety (delegates to "
             "warmup_traffic.sh if available)."
    )
    parser.add_argument(
        "--target", choices=["localhost", "lan"], default="lan",
        help="For --mode flood: 'localhost' (127.0.0.1, NOT captured by "
             "Sentinel -- see module docstring) or 'lan' (your own LAN IP, "
             "IS captured -- default)."
    )
    parser.add_argument(
        "--lan-ip", type=str, default=None,
        help="Override auto-detected LAN IP (only used with --target lan)."
    )
    parser.add_argument(
        "--port", type=int, default=DEFAULT_FLOOD_PORT,
        help=f"Destination port for the flood (default: {DEFAULT_FLOOD_PORT})."
    )
    parser.add_argument(
        "--duration", type=int, default=DEFAULT_FLOOD_DURATION_SECONDS,
        help=f"Flood duration in seconds (default: {DEFAULT_FLOOD_DURATION_SECONDS})."
    )
    parser.add_argument(
        "--rate", type=int, default=DEFAULT_PACKETS_PER_SECOND,
        help=f"Target packets per second (default: {DEFAULT_PACKETS_PER_SECOND})."
    )

    args = parser.parse_args()

    if args.mode == "normal":
        simulate_normal(Path(__file__).resolve().parent.parent)
        return

    # mode == "flood"
    if args.target == "localhost":
        target_ip = "127.0.0.1"
    else:
        target_ip = args.lan_ip or _detect_lan_ip()
        print(f"[attack_simulator] Using LAN IP: {target_ip}"
              f"{' (auto-detected)' if not args.lan_ip else ''}")

    try:
        simulate_flood(
            target_ip=target_ip,
            port=args.port,
            duration_seconds=args.duration,
            packets_per_second=args.rate,
        )
    except ValueError as e:
        print(f"[attack_simulator] ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()