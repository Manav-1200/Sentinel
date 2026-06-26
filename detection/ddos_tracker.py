"""
detection/ddos_tracker.py
============================
Aggregate, cross-flow, cross-source rate tracking — specifically for
detecting DDoS-style attacks, which a per-flow detector fundamentally
cannot see.

Why this is a separate module from anomaly.py:
--------------------------------------------------
Every detection mechanism built so far (the Isolation Forest in
anomaly.py, and its explicit flood-rate guard) judges ONE FLOW AT A
TIME, in isolation. This works well for:
  - Port scans: one source, many flows, each individually showing a
    high SYN ratio.
  - DoS floods: one source, one flow, individually showing an extreme
    packet rate.

It fundamentally CANNOT see DDoS: many different sources, each
sending a low, individually-unremarkable amount of traffic, that only
becomes alarming in aggregate. No single flow looks wrong on its own
— the problem only exists at the level of "how much total traffic, and
from how many distinct sources, is hitting me right now."

This module tracks exactly that: a sliding time window of recent flow
arrivals (across ALL flows, not one), so it can compute:
  - Total new-connection rate across every source combined.
  - Number of DISTINCT source IPs seen in that window.

A real DDoS typically spikes BOTH of these simultaneously. A single
busy normal source (e.g. you browsing several sites at once) spikes
total rate but not distinct-source count. A real, organic surge in
legitimate distinct visitors (rare for a personal/home network, but
possible) might raise distinct-source count without an extreme total
rate. Requiring both to be elevated together reduces false positives
compared to either signal alone.
"""

from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class DDoSVerdict(str, Enum):
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    ATTACK = "ATTACK"


@dataclass
class DDoSCheckResult:
    verdict: DDoSVerdict
    window_seconds: float
    total_flows_in_window: int
    distinct_sources_in_window: int

    def __repr__(self) -> str:
        return (
            f"DDoSCheckResult(verdict={self.verdict.value}, "
            f"flows={self.total_flows_in_window}, "
            f"distinct_sources={self.distinct_sources_in_window})"
        )


class GlobalRateTracker:
    """
    Tracks new-flow arrivals across the entire system in a sliding
    time window, to detect DDoS-style patterns that no single flow
    would reveal on its own.

    Usage: call record_new_flow(src_ip, timestamp) once for every NEW
    flow as soon as it's created (not for every packet — one call per
    flow, at creation time). Call check() periodically (e.g. once per
    flow processed, same cadence as per-flow detection) to get the
    current aggregate verdict.
    """

    def __init__(self, config: dict):
        ddos_config = config.get("ddos", {})

        self.window_seconds: float = float(ddos_config.get("window_seconds", 10.0))

        # Thresholds — both must be exceeded together for ATTACK (see
        # module docstring for why requiring both reduces false
        # positives compared to either alone). SUSPICIOUS fires if
        # either one alone is notably elevated.
        self.attack_total_flows_threshold: int = int(
            ddos_config.get("attack_total_flows_threshold", 500)
        )
        self.attack_distinct_sources_threshold: int = int(
            ddos_config.get("attack_distinct_sources_threshold", 20)
        )
        self.suspicious_total_flows_threshold: int = int(
            ddos_config.get("suspicious_total_flows_threshold", 200)
        )
        self.suspicious_distinct_sources_threshold: int = int(
            ddos_config.get("suspicious_distinct_sources_threshold", 10)
        )

        # Each entry is (timestamp, src_ip) for one new flow. A deque
        # is used so old entries can be efficiently dropped from the
        # left as the window slides forward.
        self._recent_flows: deque[tuple[float, str]] = deque()
        self._lock = threading.Lock()

    def record_new_flow(self, src_ip: str, timestamp: float) -> None:
        """
        Record that a new flow was just created, for the purposes of
        aggregate rate tracking. Call this once per NEW flow (not per
        packet) — typically right when a Flow object is first created
        during flow assembly.
        """
        with self._lock:
            self._recent_flows.append((timestamp, src_ip))
            self._evict_old_entries(timestamp)

    def check(self, current_timestamp: float) -> DDoSCheckResult:
        """
        Compute the current aggregate verdict based on flow arrivals
        within the sliding window ending at current_timestamp.
        """
        with self._lock:
            self._evict_old_entries(current_timestamp)
            total_flows = len(self._recent_flows)
            distinct_sources = len({src_ip for _, src_ip in self._recent_flows})

        attack = (
            total_flows >= self.attack_total_flows_threshold
            and distinct_sources >= self.attack_distinct_sources_threshold
        )
        suspicious = (
            total_flows >= self.suspicious_total_flows_threshold
            or distinct_sources >= self.suspicious_distinct_sources_threshold
        )

        if attack:
            verdict = DDoSVerdict.ATTACK
        elif suspicious:
            verdict = DDoSVerdict.SUSPICIOUS
        else:
            verdict = DDoSVerdict.NORMAL

        return DDoSCheckResult(
            verdict=verdict,
            window_seconds=self.window_seconds,
            total_flows_in_window=total_flows,
            distinct_sources_in_window=distinct_sources,
        )

    def _evict_old_entries(self, current_timestamp: float) -> None:
        """
        Drop entries older than window_seconds from the left of the
        deque. MUST be called while holding self._lock.
        """
        cutoff = current_timestamp - self.window_seconds
        while self._recent_flows and self._recent_flows[0][0] < cutoff:
            self._recent_flows.popleft()