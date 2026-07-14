"""
tests/test_cli_display.py
=============================
Unit tests for detection/cli_display.py's new scrolling log and
live Status column.

The critical property under test: the Status column must ALWAYS
reflect blocker.is_blocked(src_ip) at render time, and NEVER a
locally cached or guessed value — this is what makes it impossible
for the column to show BLOCKED while traffic is actually allowed (or
vice versa).
"""

from __future__ import annotations

from unittest.mock import MagicMock
from dataclasses import dataclass, field

import pytest

from detection.cli_display import LiveDetectionDisplay
from detection.anomaly import Verdict
from detection.ddos_tracker import DDoSVerdict


@dataclass
class _FakeDetectionResult:
    verdict: Verdict
    score: float | None
    features: dict = field(default_factory=dict)


@dataclass
class _FakeDDoSCheckResult:
    verdict: DDoSVerdict
    total_flows_in_window: int = 0
    distinct_sources_in_window: int = 0
    window_seconds: float = 10.0


def make_result(verdict=Verdict.NORMAL, src_ip="203.0.113.5", score=0.1):
    return _FakeDetectionResult(
        verdict=verdict,
        score=score,
        features={
            "protocol": 6, "src_ip": src_ip, "src_port": 4444,
            "dst_ip": "192.168.1.10", "dst_port": 80, "total_packets": 5,
        },
    )


class TestStatusColumnAccuracy:
    def test_status_shown_as_blocked_when_blocker_says_blocked(self, capsys):
        blocker = MagicMock()
        blocker.is_blocked.return_value = True
        display = LiveDetectionDisplay(blocker=blocker)
        with display:
            display.add(make_result(verdict=Verdict.ATTACK, src_ip="203.0.113.9"))

        blocker.is_blocked.assert_called_with("203.0.113.9")
        out = capsys.readouterr().out
        assert "BLOCKED" in out

    def test_status_shown_as_allowed_when_blocker_says_not_blocked(self, capsys):
        blocker = MagicMock()
        blocker.is_blocked.return_value = False
        display = LiveDetectionDisplay(blocker=blocker)
        with display:
            display.add(make_result(verdict=Verdict.NORMAL, src_ip="203.0.113.10"))

        out = capsys.readouterr().out
        assert "ALLOWED" in out
        assert "BLOCKED" not in out.replace("ALLOWED", "")  # BLOCKED substring not present outside ALLOWED

    def test_status_is_dash_when_no_blocker_wired(self, capsys):
        display = LiveDetectionDisplay(blocker=None)
        with display:
            display.add(make_result())

        out = capsys.readouterr().out
        assert "—" in out

    def test_status_never_crashes_when_blocker_query_raises(self, capsys):
        blocker = MagicMock()
        blocker.is_blocked.side_effect = RuntimeError("firewall query failed")
        display = LiveDetectionDisplay(blocker=blocker)
        with display:
            display.add(make_result())  # must not raise

        out = capsys.readouterr().out
        assert "UNKNOWN" in out

    def test_status_queried_fresh_every_row_not_cached(self, capsys):
        """
        The same source IP appears twice with different real block
        states in between — the column must reflect each call's
        actual state, not whatever it showed the first time.
        """
        blocker = MagicMock()
        display = LiveDetectionDisplay(blocker=blocker)
        with display:
            blocker.is_blocked.return_value = False
            display.add(make_result(src_ip="203.0.113.20"))
            blocker.is_blocked.return_value = True
            display.add(make_result(src_ip="203.0.113.20"))

        out = capsys.readouterr().out
        assert "ALLOWED" in out
        assert "BLOCKED" in out


class TestScrollingBehaviour:
    def test_every_flow_is_printed_not_overwritten(self, capsys):
        """
        The old Live-table version only kept the last max_rows visible
        — this asserts that all N rows actually appear in stdout
        (i.e. real scrollback), not just the most recent ones.
        """
        display = LiveDetectionDisplay(max_rows=5, blocker=None)
        with display:
            for i in range(12):
                display.add(make_result(src_ip=f"203.0.113.{i}"))

        out = capsys.readouterr().out
        for i in range(12):
            assert f"203.0.113.{i}" in out

    def test_counters_increment_correctly(self):
        display = LiveDetectionDisplay(blocker=None)
        with display:
            display.add(make_result(verdict=Verdict.NORMAL))
            display.add(make_result(verdict=Verdict.ATTACK))
            display.add(make_result(verdict=Verdict.ATTACK))

        assert display.total_flows_seen == 3
        assert display.counts[Verdict.NORMAL] == 1
        assert display.counts[Verdict.ATTACK] == 2

    def test_ddos_status_change_prints_warning(self, capsys):
        display = LiveDetectionDisplay(blocker=None)
        with display:
            display.set_ddos_status(_FakeDDoSCheckResult(
                verdict=DDoSVerdict.ATTACK, total_flows_in_window=500, distinct_sources_in_window=40,
            ))

        out = capsys.readouterr().out
        assert "DDoS" in out

    def test_dropped_packets_warning_only_prints_when_count_grows(self, capsys):
        display = LiveDetectionDisplay(blocker=None)
        with display:
            display.dropped_packet_count = 5
            display.add(make_result())
            capsys.readouterr()  # clear so far
            display.add(make_result())  # count unchanged — should NOT reprint warning

        out = capsys.readouterr().out
        assert "Dropped packets" not in out

    def test_summary_line_printed_every_n_flows(self, capsys):
        display = LiveDetectionDisplay(blocker=None)
        with display:
            for _ in range(50):
                display.add(make_result())

        out = capsys.readouterr().out
        assert "summary after 50 flows" in out