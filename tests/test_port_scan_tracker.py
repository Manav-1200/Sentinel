"""
tests/test_port_scan_tracker.py
==================================
Unit tests for detection/port_scan_tracker.py's PortScanTracker.

Mirrors the structure and philosophy of test_ddos_tracker.py: this is
a sliding-window, per-key detector, so the core things worth proving
are (1) the counting/threshold logic itself, (2) that the window
correctly evicts old entries rather than accumulating forever, and
(3) that per-source tracking is genuinely isolated — one source's
scan must never affect another source's verdict, since that's the
entire reason this exists as a per-source tracker rather than a
single global counter (see ddos_tracker.py's GlobalRateTracker for
the deliberately-opposite, source-agnostic design).
"""

import pytest

from detection.port_scan_tracker import PortScanTracker, PortScanVerdict


@pytest.fixture
def config():
    return {
        "port_scan": {
            "window_seconds": 10.0,
            "suspicious_distinct_ports_threshold": 6,
            "attack_distinct_ports_threshold": 15,
        }
    }


class TestBasicBehaviour:

    def test_empty_tracker_is_normal(self, config):
        tracker = PortScanTracker(config)
        result = tracker.check("10.0.0.1", current_timestamp=100.0)

        assert result.verdict == PortScanVerdict.NORMAL
        assert result.distinct_ports_in_window == 0
        assert result.distinct_targets_in_window == 0

    def test_few_distinct_ports_stays_normal(self, config):
        tracker = PortScanTracker(config)
        for port in range(1, 4):  # 3 distinct ports — below suspicious threshold of 6
            tracker.record_new_flow("10.0.0.1", "192.168.1.50", port, timestamp=100.0)

        result = tracker.check("10.0.0.1", current_timestamp=100.5)
        assert result.verdict == PortScanVerdict.NORMAL
        assert result.distinct_ports_in_window == 3

    def test_repeated_connections_to_same_port_do_not_count_as_distinct(self, config):
        """
        A source opening many connections to the SAME port (e.g. a
        busy legitimate web client) must not look like a scan — only
        DISTINCT ports should count. This is the whole reason the
        module tracks a set of ports, not a raw connection count.
        """
        tracker = PortScanTracker(config)
        for _ in range(20):
            tracker.record_new_flow("10.0.0.1", "192.168.1.50", 443, timestamp=100.0)

        result = tracker.check("10.0.0.1", current_timestamp=100.5)
        assert result.verdict == PortScanVerdict.NORMAL
        assert result.distinct_ports_in_window == 1


class TestThresholdCrossing:

    def test_crossing_suspicious_threshold(self, config):
        tracker = PortScanTracker(config)
        for port in range(1, 7):  # exactly 6 distinct ports — meets suspicious threshold
            tracker.record_new_flow("10.0.0.1", "192.168.1.50", port, timestamp=100.0)

        result = tracker.check("10.0.0.1", current_timestamp=100.5)
        assert result.verdict == PortScanVerdict.SUSPICIOUS
        assert result.distinct_ports_in_window == 6

    def test_below_suspicious_threshold_stays_normal(self, config):
        tracker = PortScanTracker(config)
        for port in range(1, 6):  # 5 distinct ports — one below suspicious threshold of 6
            tracker.record_new_flow("10.0.0.1", "192.168.1.50", port, timestamp=100.0)

        result = tracker.check("10.0.0.1", current_timestamp=100.5)
        assert result.verdict == PortScanVerdict.NORMAL

    def test_crossing_attack_threshold(self, config):
        tracker = PortScanTracker(config)
        for port in range(1, 16):  # exactly 15 distinct ports — meets attack threshold
            tracker.record_new_flow("10.0.0.1", "192.168.1.50", port, timestamp=100.0)

        result = tracker.check("10.0.0.1", current_timestamp=100.5)
        assert result.verdict == PortScanVerdict.ATTACK
        assert result.distinct_ports_in_window == 15

    def test_between_suspicious_and_attack_thresholds_is_suspicious_not_attack(self, config):
        tracker = PortScanTracker(config)
        for port in range(1, 11):  # 10 distinct ports — above suspicious (6), below attack (15)
            tracker.record_new_flow("10.0.0.1", "192.168.1.50", port, timestamp=100.0)

        result = tracker.check("10.0.0.1", current_timestamp=100.5)
        assert result.verdict == PortScanVerdict.SUSPICIOUS


class TestPerSourceIsolation:
    """
    The core design property of a PER-SOURCE tracker: one source
    scanning aggressively must never affect another source's verdict.
    Directly mirrors test_ddos_tracker.py's
    test_same_total_volume_different_verdict_based_on_source_diversity,
    but proving the opposite-shaped property this module is
    responsible for.
    """

    def test_one_source_scanning_does_not_affect_another_source(self, config):
        tracker = PortScanTracker(config)

        # Source A: a genuine scan — 20 distinct ports, well past ATTACK threshold
        for port in range(1, 21):
            tracker.record_new_flow("10.0.0.1", "192.168.1.50", port, timestamp=100.0)

        # Source B: only 2 distinct ports — completely ordinary
        tracker.record_new_flow("10.0.0.2", "192.168.1.50", 443, timestamp=100.0)
        tracker.record_new_flow("10.0.0.2", "192.168.1.50", 80, timestamp=100.0)

        result_a = tracker.check("10.0.0.1", current_timestamp=100.5)
        result_b = tracker.check("10.0.0.2", current_timestamp=100.5)

        assert result_a.verdict == PortScanVerdict.ATTACK
        assert result_b.verdict == PortScanVerdict.NORMAL

    def test_distinct_targets_tracked_independently_of_distinct_ports(self, config):
        """
        A source scanning the SAME port across many different target
        IPs (e.g. looking for one specific open service across a
        subnet) should still show a low distinct_ports_in_window, but
        a high distinct_targets_in_window — these are separate,
        independently useful signals, not the same count reported
        twice.
        """
        tracker = PortScanTracker(config)
        for i in range(10):
            tracker.record_new_flow("10.0.0.1", f"192.168.1.{i}", 22, timestamp=100.0)

        result = tracker.check("10.0.0.1", current_timestamp=100.5)
        assert result.distinct_ports_in_window == 1
        assert result.distinct_targets_in_window == 10


class TestSlidingWindow:

    def test_old_entries_are_evicted_outside_the_window(self, config):
        tracker = PortScanTracker(config)

        # 20 distinct ports at t=0 — would be ATTACK if still in-window
        for port in range(1, 21):
            tracker.record_new_flow("10.0.0.1", "192.168.1.50", port, timestamp=0.0)

        # Checked well outside the 10s window — all those entries should be evicted
        result = tracker.check("10.0.0.1", current_timestamp=50.0)
        assert result.verdict == PortScanVerdict.NORMAL
        assert result.distinct_ports_in_window == 0

    def test_partial_window_eviction(self, config):
        tracker = PortScanTracker(config)

        # 5 ports at t=0 (will fall outside the window by t=15)
        for port in range(1, 6):
            tracker.record_new_flow("10.0.0.1", "192.168.1.50", port, timestamp=0.0)

        # 5 more distinct ports at t=12 (still in-window at t=15, since window=10s)
        for port in range(6, 11):
            tracker.record_new_flow("10.0.0.1", "192.168.1.50", port, timestamp=12.0)

        # At t=15: the t=0 entries are 15s old (outside a 10s window, evicted),
        # the t=12 entries are 3s old (still in-window) — only 5 should remain.
        result = tracker.check("10.0.0.1", current_timestamp=15.0)
        assert result.distinct_ports_in_window == 5

    def test_window_naturally_extends_as_new_flows_are_recorded(self, config):
        """
        record_new_flow itself evicts old entries relative to the
        timestamp it's called with — this proves the eviction logic
        runs on both the write path (record_new_flow) and the read
        path (check), not just one or the other.
        """
        tracker = PortScanTracker(config)
        tracker.record_new_flow("10.0.0.1", "192.168.1.50", 1, timestamp=0.0)

        # Recording a new flow 20s later should evict the t=0 entry
        # during the record_new_flow call itself.
        tracker.record_new_flow("10.0.0.1", "192.168.1.50", 2, timestamp=20.0)

        result = tracker.check("10.0.0.1", current_timestamp=20.5)
        assert result.distinct_ports_in_window == 1  # only port 2 remains


class TestUnknownSource:

    def test_checking_a_source_with_no_recorded_flows_is_normal(self, config):
        """
        check() must handle a source it has never seen via
        record_new_flow() at all — this happens naturally in main.py
        whenever a flow's source hasn't triggered any prior port-scan
        activity. Must not raise, must return a clean NORMAL result.
        """
        tracker = PortScanTracker(config)
        result = tracker.check("10.0.0.99", current_timestamp=100.0)

        assert result.verdict == PortScanVerdict.NORMAL
        assert result.src_ip == "10.0.0.99"
        assert result.distinct_ports_in_window == 0
        assert result.distinct_targets_in_window == 0


class TestConfigDefaults:

    def test_uses_config_provided_thresholds(self, config):
        tracker = PortScanTracker(config)
        assert tracker.window_seconds == 10.0
        assert tracker.suspicious_distinct_ports_threshold == 6
        assert tracker.attack_distinct_ports_threshold == 15

    def test_falls_back_to_defaults_when_port_scan_config_missing(self):
        """
        PortScanTracker.__init__ reads config.get("port_scan", {}),
        so a config dict entirely missing the port_scan section must
        still construct successfully using the module's built-in
        defaults, rather than raising a KeyError.
        """
        tracker = PortScanTracker({})
        assert tracker.window_seconds == 10.0
        assert tracker.suspicious_distinct_ports_threshold == 8
        assert tracker.attack_distinct_ports_threshold == 20