"""
detection/brute_force_tracker.py

Per-source, per-destination-service brute-force / credential-stuffing
detector.

Why this exists (mirrors the reasoning behind ddos_tracker.py and
port_scan_tracker.py): Sentinel only ever sees flow/connection
metadata - it never inspects an authentication payload, so it can
never directly observe a "failed login". What it CAN observe is the
connection-level fingerprint of brute-forcing: one source opening
many short-lived connections to the same (destination IP, destination
port) pair, on a port normally associated with authentication (SSH,
RDP, FTP, etc.), far faster than a human typing a password by hand
would produce.

This is deliberately a proxy signal, not proof of a failed login -
worth stating honestly in docs/README rather than overclaiming what
this detector can see.

Design mirrors the existing trackers on purpose:
- per-(src_ip, dst_ip, dst_port) sliding time window
- deterministic, rule-based (no LLM confirmation needed to flag) -
  same reasoning as ddos_tracker/port_scan_tracker: asking the LLM to
  "confirm" an already-deterministic threshold crossing adds a point
  of failure without adding real certainty
- driven by explicit timestamps passed in by the caller (flow.last_seen),
  NOT time.time() - this is what makes the tracker work correctly
  during pcap replay (run_pcap), where "now" is whatever timestamp the
  captured packet actually has, not wall-clock time when Sentinel
  happens to be replaying it. Every other Sentinel tracker follows
  this same convention; a wall-clock-based tracker here would silently
  misbehave the moment someone replays an old pcap.
- config-driven thresholds, so tuning doesn't require a code change
- SUSPICIOUS / ATTACK escalation via the existing Verdict-style
  vocabulary the rest of Sentinel already uses

v1 scope (explicit, not accidental): this tracks raw connection-attempt
RATE only. It does not yet distinguish a fast rate of successful logins
(unlikely, but not impossible - e.g. a legitimate automated deploy
script) from a fast rate of failed ones (RST / incomplete handshake).
That handshake-outcome signal is a documented, intentional v2 addition -
see BruteForceTracker's class docstring "Known limitations" section.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Deque, Dict, Tuple


class BruteForceVerdict(Enum):
    """Mirrors the NORMAL/SUSPICIOUS/ATTACK vocabulary used by
    DDoSVerdict and PortScanVerdict elsewhere in Sentinel, so callers
    in main.py can treat all three trackers uniformly."""
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    ATTACK = "ATTACK"


# (src_ip, dst_ip, dst_port) - the tracker groups connection attempts
# by this full triple, not just src_ip, so it can distinguish "one
# source hammering one SSH server" from "one source making occasional
# unrelated connections to several different services", which should
# NOT be flagged as brute force.
TrackerKey = Tuple[str, str, int]


@dataclass
class BruteForceResult:
    """
    Returned by BruteForceTracker.check() - mirrors the shape of
    PortScanTracker's result object (verdict + the counts that explain
    it + the window it was measured over), which is what main.py's
    handle_attack_response()/labeller.process_brute_force_attack()
    calls consume for their `reasoning`/`extra` payloads.
    """
    verdict: BruteForceVerdict
    src_ip: str
    dst_ip: str
    dst_port: int
    attempts_in_window: int
    window_seconds: float
    repeat_offender_count: int


@dataclass
class _Window:
    """Sliding-window connection-attempt record for one (src, dst, port) triple."""

    # Timestamps of each connection attempt observed in the current
    # window. A deque (not a list) because we constantly evict from
    # the left (old attempts falling out of the window) while
    # appending to the right (new attempts) - O(1) on both ends
    # instead of O(n) for list.pop(0).
    attempts: Deque[float] = field(default_factory=deque)

    # How many times this triple has crossed the ATTACK threshold in
    # total (not just in the current window). Consumed by the response
    # layer for escalating blocks - a first-time offender gets the
    # standard block duration, a repeat offender gets a harsher/faster
    # one (see response/blocker.py's escalation support).
    repeat_offender_count: int = 0

    # Whether this triple is CURRENTLY above the ATTACK threshold, as
    # of the last check(). Needed to only increment
    # repeat_offender_count on the transition INTO ATTACK (a new
    # episode), not on every check() call made while still above
    # threshold - otherwise a caller polling check() repeatedly during
    # one sustained attack would inflate the count. Kept in sync by
    # _evict_expired(), which both record_attempt() and check() funnel
    # through, so neither call path can leave this stale.
    currently_attacking: bool = False


class BruteForceTracker:
    """
    Tracks per-(src_ip, dst_ip, dst_port) connection-attempt rate to
    detect brute-force / credential-stuffing patterns against
    auth-related services.

    Known limitations (documented deliberately, not silently assumed
    away):
    - Cannot see actual authentication outcomes (success/failure)
      since Sentinel does not inspect payloads. "Failed login" is
      inferred only from connection rate, not confirmed.
    - A legitimate but bursty automated client (e.g. a monitoring
      probe, a misconfigured retry loop) hitting an auth port
      repeatedly could false-positive here - the same class of
      limitation the flood-rate guard has against bursty-but-legitimate
      traffic, worth keeping in mind when tuning thresholds per-network.
    - v1 does not yet use RST/incomplete-handshake signals to narrow
      this down to *failed* attempts specifically - see module
      docstring.
    """

    def __init__(self, config: dict):
        """
        Args:
            config: the `brute_force` section of config.yaml. Expected
                keys (all with sensible fallback defaults, matching
                the other trackers' config-fallback pattern):
                    window_seconds (float): sliding window size, default 60
                    suspicious_threshold (int): attempts to flag SUSPICIOUS, default 5
                    attack_threshold (int): attempts to flag ATTACK, default 15
                    watched_ports (list[int]): ports to monitor, default
                        [22, 3389, 21, 23, 3306, 5432] (SSH, RDP, FTP,
                        Telnet, MySQL, Postgres - the common remote-auth
                        targets)
        """
        self.window_seconds: float = config.get("window_seconds", 60)
        self.suspicious_threshold: int = config.get("suspicious_threshold", 5)
        self.attack_threshold: int = config.get("attack_threshold", 15)

        # Config-driven, not hardcoded - see module docstring. Defaults
        # cover the most commonly-brute-forced remote-auth services.
        self.watched_ports: set = set(
            config.get("watched_ports", [22, 3389, 21, 23, 3306, 5432])
        )

        # One sliding window per (src_ip, dst_ip, dst_port) triple.
        # defaultdict so first-touch of a new triple doesn't need
        # special-case handling at the call site.
        self._windows: Dict[TrackerKey, _Window] = defaultdict(_Window)

    def is_watched_port(self, dst_port: int) -> bool:
        """Whether this destination port is one we monitor for
        brute-force patterns. Kept as its own method (rather than
        inlined) so callers have one obvious place to ask the
        question - main.py's per-flow loop uses this to decide
        whether to bother calling record_attempt()/check() at all for
        a given flow."""
        return dst_port in self.watched_ports

    def record_attempt(self, src_ip: str, dst_ip: str, dst_port: int, timestamp: float) -> None:
        """
        Record a single connection attempt. Should be called once per
        new connection observed (i.e. once per flow, from main.py's
        per-flow loop - see run_live_capture/run_pcap), not once per
        packet.

        `timestamp` should be the flow's own timestamp (flow.last_seen),
        matching how ddos_tracker/port_scan_tracker are driven - NOT
        time.time() - see module docstring for why this matters for
        pcap replay correctness.

        No-ops silently if dst_port isn't in watched_ports, so callers
        can call this unconditionally on every new flow without
        pre-filtering themselves first, mirroring the other trackers'
        "let the tracker decide what it cares about" pattern.
        """
        if not self.is_watched_port(dst_port):
            return

        key: TrackerKey = (src_ip, dst_ip, dst_port)
        window = self._windows[key]
        window.attempts.append(timestamp)
        self._evict_expired(window, timestamp)

    def _evict_expired(self, window: _Window, now: float) -> None:
        """Drop attempts that have fallen out of the sliding window.

        Called from both the record path and the check path (mirrors
        the other trackers' dual-path eviction) so a check() call
        after a period of silence doesn't report stale, no-longer-
        relevant counts just because record_attempt() hasn't been
        called recently enough to trigger eviction itself.

        Also resets `currently_attacking` here, not just in check() -
        found while testing: record_attempt() can trigger eviction
        that drops a window back below attack_threshold, but if
        check() was never called in between, `currently_attacking`
        would stay stale from a previous episode. That would make a
        second, genuinely distinct attack episode (after the window
        fully expired) fail to register as new, silently undercounting
        repeat_offender_count. Resetting the flag right where eviction
        happens - the one place both call paths funnel through - fixes
        it at the source instead of in just one of the two callers.
        """
        cutoff = now - self.window_seconds
        while window.attempts and window.attempts[0] < cutoff:
            window.attempts.popleft()

        if len(window.attempts) < self.attack_threshold:
            window.currently_attacking = False

    def check(self, src_ip: str, dst_ip: str, dst_port: int, timestamp: float) -> BruteForceResult:
        """
        Returns the current BruteForceResult for this
        (src_ip, dst_ip, dst_port) triple.

        `timestamp` should be the same flow-driven timestamp passed to
        record_attempt() - see module docstring.

        Safe to call even if record_attempt() was never called for
        this triple - returns NORMAL with attempts_in_window=0, rather
        than raising, since callers may check() speculatively (e.g.
        for a dst_port that isn't actually watched).
        """
        key: TrackerKey = (src_ip, dst_ip, dst_port)
        window = self._windows[key]  # defaultdict - safe even if unseen
        self._evict_expired(window, timestamp)

        count = len(window.attempts)

        if count >= self.attack_threshold:
            # Only increment on the transition into ATTACK (i.e. we
            # were NOT already flagged as attacking, per
            # _evict_expired's up-to-date bookkeeping) - this is what
            # gives repeat_offender_count the semantics the response
            # layer needs: "how many separate attack episodes", not
            # "how many times we happened to poll while one sustained
            # episode was ongoing".
            if not window.currently_attacking:
                window.repeat_offender_count += 1
                window.currently_attacking = True
            verdict = BruteForceVerdict.ATTACK
        elif count >= self.suspicious_threshold:
            verdict = BruteForceVerdict.SUSPICIOUS
        else:
            verdict = BruteForceVerdict.NORMAL

        return BruteForceResult(
            verdict=verdict,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            attempts_in_window=count,
            window_seconds=self.window_seconds,
            repeat_offender_count=window.repeat_offender_count,
        )