"""
detection/port_scan_tracker.py
============================
Per-source, cross-flow port-scan detection — for the same structural
reason ddos_tracker.py exists: a per-flow detector fundamentally
cannot see this pattern.

Why this is a separate module from anomaly.py and ddos_tracker.py:
--------------------------------------------------------------------
A classic port scan (e.g. `nmap -sT`) looks, from ONE flow's point of
view, like a single short connection to a single port. Nothing about
one flow in isolation is unusual — the SYN ratio and packet count for
any individual connection can be completely ordinary. The signal only
exists at the level of "how many DISTINCT destination ports has this
ONE source touched recently" — i.e. it requires remembering across
flows, keyed by source, which is exactly what a per-flow Isolation
Forest cannot do.

This is also why ddos_tracker.py's GlobalRateTracker doesn't catch
this: GlobalRateTracker is deliberately source-AGNOSTIC (it looks at
aggregate rate and distinct-SOURCE count, to catch many-sources-one-
target). A port scan is the opposite shape — one-source-many-targets
(specifically many distinct ports) — so it needs its own per-source
sliding window, keyed by src_ip rather than aggregated across all
sources.

Detection logic:
-----------------
For each source IP, track (timestamp, dst_ip, dst_port) tuples in a
sliding window. A scan is flagged when that source has touched at
least N distinct destination ports within the window. Requiring
DISTINCT ports (not just flow count) avoids flagging a single source
that legitimately opens many connections to the same one or two
services (e.g. a busy web client).

distinct_targets_in_window precision fix (July 2026):
--------------------------------------------------------
Real-world testing found the REPORTED distinct_targets_in_window
count to be misleading in a real scan (confirmed live, July 2026): a
real `nmap -sT` scan touching 773 distinct ports on ONE real target
was reported as "773 distinct ports across 2 targets", because the
scanning host also happened to make one unrelated, incidental DNS
query during the same window — that single-port destination got
counted as a second "target" even though it has nothing to do with
the scan pattern.

Important: this ONLY affected the human-readable reasoning text used
in alerts/logs, never the actual ATTACK/SUSPICIOUS verdict — that
threshold is, and always was, based purely on distinct_ports_in_window
(which counts ports globally across the whole window, not per
destination), so no detection or blocking behaviour was ever
incorrect. But an inaccurate "targets" count in a reasoning string
shown to a real operator is still a real precision problem worth
fixing on its own — Sentinel's stated goal is dependable, non-
misleading reporting, not just correct blocking decisions.

First attempt (found to be too narrow, July 2026): counted a
destination as a "target" only if it received MORE THAN ONE distinct
port from that source within the window (vertical fan-out). This
correctly excluded incidental single-port destinations (a DNS lookup,
an NTP request) — but it also excluded a real, different scan shape:
a HORIZONTAL scan, where a source probes the SAME single port across
MANY different destination IPs (e.g. hunting for one specific open
service across a subnet). In that pattern every individual
destination legitimately receives only one port each, so the
vertical-fan-out-only rule incorrectly reported 0 targets even though
10 distinct hosts were genuinely being scanned.

Fix: a destination now counts as a "target" if it shows fan-out in
EITHER direction:
  - Vertical: it received at least MIN_PORTS_PER_TARGET_TO_COUNT
    distinct ports from this source (the original July fix, still
    correctly excludes an isolated single-port destination on its
    own), OR
  - Horizontal: at least one of the ports it received was ALSO seen,
    from this same source, on at least MIN_TARGETS_PER_PORT_TO_COUNT
    other distinct destinations within the window (i.e. this exact
    port is being probed broadly, not just against this one host).

A single incidental destination (one port, and that port touched
nowhere else in the window) still correctly counts as 0 -- neither
condition is met. A same-port sweep across many hosts now correctly
counts every one of those hosts as a target, since the horizontal
condition is met for all of them.
"""

from __future__ import annotations

import threading
from collections import defaultdict, deque
from dataclasses import dataclass
from enum import Enum


class PortScanVerdict(str, Enum):
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    ATTACK = "ATTACK"


@dataclass
class PortScanCheckResult:
    verdict: PortScanVerdict
    src_ip: str
    window_seconds: float
    distinct_ports_in_window: int
    distinct_targets_in_window: int

    def __repr__(self) -> str:
        return (
            f"PortScanCheckResult(verdict={self.verdict.value}, "
            f"src_ip={self.src_ip}, "
            f"distinct_ports={self.distinct_ports_in_window}, "
            f"distinct_targets={self.distinct_targets_in_window})"
        )


class PortScanTracker:
    """
    Tracks, per source IP, how many distinct destination ports have
    been touched in a sliding time window — to detect port-scan
    patterns that no single flow would reveal on its own.

    Usage: call record_new_flow(src_ip, dst_ip, dst_port, timestamp)
    once for every NEW flow as soon as it's created (same cadence and
    call site as GlobalRateTracker.record_new_flow — typically the
    on_new_flow callback in FlowAssembler). Call check(src_ip,
    timestamp) after processing a flow from that source to get the
    current verdict for that specific source.
    """

    # Minimum number of distinct ports a single destination must have
    # received from a source before that destination counts toward
    # distinct_targets_in_window via VERTICAL fan-out (many ports, one
    # host). See module docstring's "distinct_targets_in_window
    # precision fix" section.
    MIN_PORTS_PER_TARGET_TO_COUNT = 2

    # Minimum number of distinct destinations a single port must have
    # been touched on (by the same source) before that port counts as
    # HORIZONTAL fan-out (one port, many hosts) — see module
    # docstring's "Fix" section. A destination that only received a
    # port also seen on this many-or-more OTHER destinations counts as
    # a target even though it individually received just one port.
    MIN_TARGETS_PER_PORT_TO_COUNT = 2

    def __init__(self, config: dict):
        port_scan_config = config.get("port_scan", {})

        self.window_seconds: float = float(port_scan_config.get("window_seconds", 10.0))

        self.attack_distinct_ports_threshold: int = int(
            port_scan_config.get("attack_distinct_ports_threshold", 20)
        )
        self.suspicious_distinct_ports_threshold: int = int(
            port_scan_config.get("suspicious_distinct_ports_threshold", 8)
        )

        # Per-source sliding window: src_ip -> deque of
        # (timestamp, dst_ip, dst_port). Kept separate per source so
        # one noisy source's history never leaks into another's count.
        self._recent_by_source: dict[str, deque[tuple[float, str, int]]] = defaultdict(deque)
        self._lock = threading.Lock()

    def record_new_flow(self, src_ip: str, dst_ip: str, dst_port: int, timestamp: float) -> None:
        """
        Record that a new flow was just created from src_ip to
        dst_ip:dst_port. Call this once per NEW flow (not per
        packet) — same call site as GlobalRateTracker.record_new_flow,
        typically FlowAssembler's on_new_flow callback.
        """
        with self._lock:
            entries = self._recent_by_source[src_ip]
            entries.append((timestamp, dst_ip, dst_port))
            self._evict_old_entries(entries, timestamp)

    def check(self, src_ip: str, current_timestamp: float) -> PortScanCheckResult:
        """
        Compute the current port-scan verdict for src_ip, based on
        distinct destination ports touched within the sliding window
        ending at current_timestamp.

        distinct_ports_in_window (drives the actual verdict) counts
        every distinct port touched anywhere in the window, exactly
        as before — this is unchanged and is not affected by the fix
        below.

        distinct_targets_in_window (reporting only, see module
        docstring) counts a destination as a target if it shows scan
        fan-out in EITHER direction: vertical (>=
        MIN_PORTS_PER_TARGET_TO_COUNT distinct ports on that one
        destination) or horizontal (at least one of its ports was also
        touched, by this source, on >= MIN_TARGETS_PER_PORT_TO_COUNT
        other distinct destinations in the window).
        """
        with self._lock:
            entries = self._recent_by_source.get(src_ip)
            if entries is None:
                return PortScanCheckResult(
                    verdict=PortScanVerdict.NORMAL,
                    src_ip=src_ip,
                    window_seconds=self.window_seconds,
                    distinct_ports_in_window=0,
                    distinct_targets_in_window=0,
                )

            self._evict_old_entries(entries, current_timestamp)
            distinct_ports = len({dst_port for _, _, dst_port in entries})

            ports_per_target: dict[str, set[int]] = defaultdict(set)
            targets_per_port: dict[int, set[str]] = defaultdict(set)
            for _, dst_ip, dst_port in entries:
                ports_per_target[dst_ip].add(dst_port)
                targets_per_port[dst_port].add(dst_ip)

            distinct_targets = 0
            for dst_ip, ports in ports_per_target.items():
                vertical = len(ports) >= self.MIN_PORTS_PER_TARGET_TO_COUNT
                horizontal = any(
                    len(targets_per_port[p]) >= self.MIN_TARGETS_PER_PORT_TO_COUNT for p in ports
                )
                if vertical or horizontal:
                    distinct_targets += 1

        if distinct_ports >= self.attack_distinct_ports_threshold:
            verdict = PortScanVerdict.ATTACK
        elif distinct_ports >= self.suspicious_distinct_ports_threshold:
            verdict = PortScanVerdict.SUSPICIOUS
        else:
            verdict = PortScanVerdict.NORMAL

        return PortScanCheckResult(
            verdict=verdict,
            src_ip=src_ip,
            window_seconds=self.window_seconds,
            distinct_ports_in_window=distinct_ports,
            distinct_targets_in_window=distinct_targets,
        )

    def _evict_old_entries(
        self, entries: deque[tuple[float, str, int]], current_timestamp: float
    ) -> None:
        """
        Drop entries older than window_seconds from the left of the
        deque. MUST be called while holding self._lock.
        """
        cutoff = current_timestamp - self.window_seconds
        while entries and entries[0][0] < cutoff:
            entries.popleft()