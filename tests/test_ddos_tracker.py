"""
tests/test_ddos_tracker.py
=============================
Unit tests for detection/ddos_tracker.py — the aggregate, cross-source
rate tracker responsible for DDoS detection specifically.

The most important property tested here is the DoS-vs-DDoS
distinction: the SAME total flow volume must produce a different
verdict depending on whether it came from one source (a DoS, already
handled by the per-flow flood-rate guard in anomaly.py) or many
distinct sources (a genuine DDoS pattern, which only this tracker can
see).
"""

import pytest

from detection.ddos_tracker import GlobalRateTracker, DDoSVerdict


@pytest.fixture
def ddos_config():
    return {
        "ddos": {
            "window_seconds": 10.0,
            "attack_total_flows_threshold": 500,
            "attack_distinct_sources_threshold": 20,
            "suspicious_total_flows_threshold": 200,
            "suspicious_distinct_sources_threshold": 10,
        }
    }


class TestBasicBehaviour:

    def test_empty_tracker_is_normal(self, ddos_config):
        tracker = GlobalRateTracker(ddos_config)
        result = tracker.check(1000.0)
        assert result.verdict == DDoSVerdict.NORMAL
        assert result.total_flows_in_window == 0
        assert result.distinct_sources_in_window == 0

    def test_low_volume_few_sources_stays_normal(self, ddos_config):
        tracker = GlobalRateTracker(ddos_config)
        for i in range(20):
            tracker.record_new_flow(f"192.168.1.{i % 3 + 50}", 1000.0 + i * 0.1)
        result = tracker.check(1002.0)
        assert result.verdict == DDoSVerdict.NORMAL


class TestDoSVsDDoSDistinction:
    """
    The core property this module exists for: identical total flow
    volume, different source diversity, must produce different
    verdicts.
    """

    def test_single_source_flood_is_not_ddos_attack(self, ddos_config):
        """
        A single source sending a huge number of flows is a DoS, not
        a DDoS — that pattern is the per-flow flood-rate guard's job
        (see detection/anomaly.py), not this tracker's ATTACK verdict.
        It should still be flagged SUSPICIOUS though, since total
        volume genuinely is elevated.
        """
        tracker = GlobalRateTracker(ddos_config)
        for i in range(600):
            tracker.record_new_flow("10.0.0.99", 1000.0 + i * 0.001)
        result = tracker.check(1001.0)

        assert result.distinct_sources_in_window == 1
        assert result.verdict != DDoSVerdict.ATTACK
        assert result.verdict == DDoSVerdict.SUSPICIOUS

    def test_many_distinct_sources_triggers_ddos_attack(self, ddos_config):
        """A genuine DDoS pattern: many distinct sources, each sending a moderate amount."""
        tracker = GlobalRateTracker(ddos_config)
        for source_idx in range(30):
            for i in range(20):
                tracker.record_new_flow(f"203.0.113.{source_idx}", 1000.0 + i * 0.01)
        result = tracker.check(1001.0)

        assert result.distinct_sources_in_window == 30
        assert result.verdict == DDoSVerdict.ATTACK

    def test_same_total_volume_different_verdict_based_on_source_diversity(self, ddos_config):
        """
        Directly proves the core distinction: 600 total flows from 1
        source vs. 600 total flows from 30 sources must NOT produce
        the same verdict.
        """
        single_source = GlobalRateTracker(ddos_config)
        for i in range(600):
            single_source.record_new_flow("10.0.0.99", 1000.0 + i * 0.001)
        single_result = single_source.check(1001.0)

        many_sources = GlobalRateTracker(ddos_config)
        for source_idx in range(30):
            for i in range(20):
                many_sources.record_new_flow(f"203.0.113.{source_idx}", 1000.0 + i * 0.01)
        many_result = many_sources.check(1001.0)

        assert single_result.total_flows_in_window == many_result.total_flows_in_window == 600
        assert single_result.verdict != many_result.verdict
        assert many_result.verdict == DDoSVerdict.ATTACK
        assert single_result.verdict != DDoSVerdict.ATTACK


class TestSlidingWindow:

    def test_old_entries_are_evicted_outside_the_window(self, ddos_config):
        tracker = GlobalRateTracker(ddos_config)
        for i in range(50):
            tracker.record_new_flow("10.0.0.1", 1000.0 + i * 0.01)

        result_during = tracker.check(1000.5)
        assert result_during.total_flows_in_window == 50

        # window_seconds is 10.0 — checking 15 seconds later should
        # find the window completely empty.
        result_after = tracker.check(1015.0)
        assert result_after.total_flows_in_window == 0

    def test_partial_window_eviction(self, ddos_config):
        tracker = GlobalRateTracker(ddos_config)
        # 5 flows at t=1000, 5 more flows at t=1008 (still within a
        # 10s window of each other at the moment they're recorded).
        for i in range(5):
            tracker.record_new_flow("10.0.0.1", 1000.0 + i * 0.01)
        for i in range(5):
            tracker.record_new_flow("10.0.0.2", 1008.0 + i * 0.01)

        # At t=1009, both batches are still within the last 10 seconds.
        result_both = tracker.check(1009.0)
        assert result_both.total_flows_in_window == 10

        # At t=1011, the first batch (around t=1000) is now older than
        # 10 seconds and should be evicted, leaving only the second batch.
        result_partial = tracker.check(1011.0)
        assert result_partial.total_flows_in_window == 5