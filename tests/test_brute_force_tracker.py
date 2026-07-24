"""
tests/test_brute_force_tracker.py

Mirrors test_port_scan_tracker.py's coverage pattern: threshold
crossing at both boundaries, per-source/per-destination isolation,
sliding-window eviction (both call paths), unknown-source handling,
config defaults/fallback, and repeat-offender episode counting.

Uses explicit, controlled timestamps throughout (not time.time()/
time.sleep()) since BruteForceTracker is driven entirely by the
timestamp passed in, matching how it's actually called from
main.py with flow.last_seen - this also makes the eviction tests
deterministic and fast, rather than relying on real sleeps.
"""

import pytest
from detection.brute_force_tracker import BruteForceTracker, BruteForceVerdict


DEFAULT_CONFIG = {
    "window_seconds": 60,
    "suspicious_threshold": 5,
    "attack_threshold": 15,
    "watched_ports": [22, 3389, 21],
}

T0 = 1_000_000.0  # arbitrary fixed base timestamp


@pytest.fixture
def tracker():
    return BruteForceTracker(DEFAULT_CONFIG)


class TestWatchedPorts:
    def test_watched_port_recognised(self, tracker):
        assert tracker.is_watched_port(22) is True

    def test_unwatched_port_not_recognised(self, tracker):
        assert tracker.is_watched_port(8080) is False

    def test_record_attempt_on_unwatched_port_is_noop(self, tracker):
        tracker.record_attempt("1.2.3.4", "10.0.0.1", 8080, T0)
        result = tracker.check("1.2.3.4", "10.0.0.1", 8080, T0)
        assert result.verdict == BruteForceVerdict.NORMAL
        assert result.attempts_in_window == 0


class TestThresholdCrossing:
    def test_below_suspicious_threshold_is_normal(self, tracker):
        for i in range(4):  # suspicious_threshold is 5
            tracker.record_attempt("1.2.3.4", "10.0.0.1", 22, T0 + i)
        result = tracker.check("1.2.3.4", "10.0.0.1", 22, T0 + 4)
        assert result.verdict == BruteForceVerdict.NORMAL

    def test_at_suspicious_threshold_is_suspicious(self, tracker):
        for i in range(5):
            tracker.record_attempt("1.2.3.4", "10.0.0.1", 22, T0 + i)
        result = tracker.check("1.2.3.4", "10.0.0.1", 22, T0 + 5)
        assert result.verdict == BruteForceVerdict.SUSPICIOUS

    def test_just_below_attack_threshold_is_suspicious(self, tracker):
        for i in range(14):  # attack_threshold is 15
            tracker.record_attempt("1.2.3.4", "10.0.0.1", 22, T0 + i)
        result = tracker.check("1.2.3.4", "10.0.0.1", 22, T0 + 14)
        assert result.verdict == BruteForceVerdict.SUSPICIOUS

    def test_at_attack_threshold_is_attack(self, tracker):
        for i in range(15):
            tracker.record_attempt("1.2.3.4", "10.0.0.1", 22, T0 + i)
        result = tracker.check("1.2.3.4", "10.0.0.1", 22, T0 + 15)
        assert result.verdict == BruteForceVerdict.ATTACK
        assert result.attempts_in_window == 15


class TestIsolation:
    def test_different_sources_tracked_independently(self, tracker):
        for i in range(15):
            tracker.record_attempt("1.2.3.4", "10.0.0.1", 22, T0 + i)
        # A second, unrelated source hitting the same service should
        # still read NORMAL - per-source isolation.
        result = tracker.check("9.9.9.9", "10.0.0.1", 22, T0 + 15)
        assert result.verdict == BruteForceVerdict.NORMAL

    def test_same_source_different_dest_port_tracked_independently(self, tracker):
        for i in range(15):
            tracker.record_attempt("1.2.3.4", "10.0.0.1", 22, T0 + i)
        # Same attacker, but hitting a different watched port on the
        # same host - should not inherit the SSH bucket's count.
        result = tracker.check("1.2.3.4", "10.0.0.1", 3389, T0 + 15)
        assert result.verdict == BruteForceVerdict.NORMAL

    def test_same_source_different_dest_host_tracked_independently(self, tracker):
        for i in range(15):
            tracker.record_attempt("1.2.3.4", "10.0.0.1", 22, T0 + i)
        # Same attacker, same port, different victim host.
        result = tracker.check("1.2.3.4", "10.0.0.2", 22, T0 + 15)
        assert result.verdict == BruteForceVerdict.NORMAL


class TestSlidingWindowEviction:
    def test_attempts_outside_window_are_evicted_on_record(self):
        tracker = BruteForceTracker({**DEFAULT_CONFIG, "window_seconds": 10})
        # All 15 attempts packed within 1.4s, well inside the 10s window.
        for i in range(15):
            tracker.record_attempt("1.2.3.4", "10.0.0.1", 22, T0 + i * 0.1)
        assert tracker.check("1.2.3.4", "10.0.0.1", 22, T0 + 1.4).verdict == BruteForceVerdict.ATTACK

        # A fresh attempt well past the 10s window should trigger
        # eviction of all the old ones, leaving only this one new
        # attempt - well below any threshold.
        far_future = T0 + 1000
        tracker.record_attempt("1.2.3.4", "10.0.0.1", 22, far_future)
        result = tracker.check("1.2.3.4", "10.0.0.1", 22, far_future)
        assert result.verdict == BruteForceVerdict.NORMAL
        assert result.attempts_in_window == 1

    def test_attempts_outside_window_are_evicted_on_check_alone(self):
        # Eviction must also happen on the check() path, not just
        # record_attempt() - mirrors the other trackers' dual-path
        # eviction requirement, so a check() after a silent period
        # doesn't report stale counts.
        tracker = BruteForceTracker({**DEFAULT_CONFIG, "window_seconds": 10})
        for i in range(15):
            tracker.record_attempt("1.2.3.4", "10.0.0.1", 22, T0 + i * 0.1)
        assert tracker.check("1.2.3.4", "10.0.0.1", 22, T0 + 1.4).verdict == BruteForceVerdict.ATTACK

        # No new record_attempt() call here - check() alone must evict.
        far_future = T0 + 1000
        result = tracker.check("1.2.3.4", "10.0.0.1", 22, far_future)
        assert result.verdict == BruteForceVerdict.NORMAL
        assert result.attempts_in_window == 0


class TestUnknownSource:
    def test_check_on_never_seen_triple_is_normal(self, tracker):
        result = tracker.check("255.255.255.255", "10.0.0.1", 22, T0)
        assert result.verdict == BruteForceVerdict.NORMAL
        assert result.attempts_in_window == 0

    def test_repeat_offender_count_on_never_seen_triple_is_zero(self, tracker):
        result = tracker.check("255.255.255.255", "10.0.0.1", 22, T0)
        assert result.repeat_offender_count == 0


class TestConfigDefaults:
    def test_defaults_used_when_config_empty(self):
        tracker = BruteForceTracker({})
        assert tracker.window_seconds == 60
        assert tracker.suspicious_threshold == 5
        assert tracker.attack_threshold == 15
        assert tracker.is_watched_port(22)
        assert tracker.is_watched_port(3389)
        assert not tracker.is_watched_port(80)

    def test_explicit_config_overrides_defaults(self):
        tracker = BruteForceTracker(
            {"suspicious_threshold": 2, "attack_threshold": 4, "watched_ports": [9999]}
        )
        assert tracker.suspicious_threshold == 2
        assert tracker.attack_threshold == 4
        assert tracker.is_watched_port(9999)
        assert not tracker.is_watched_port(22)  # no longer a default once overridden


class TestRepeatOffenderEpisodeCounting:
    def test_single_sustained_attack_counts_as_one_episode(self, tracker):
        for i in range(15):
            tracker.record_attempt("1.2.3.4", "10.0.0.1", 22, T0 + i)

        # Poll check() multiple times while still above threshold -
        # this must NOT inflate repeat_offender_count, since it's
        # still the same episode.
        for i in range(5):
            result = tracker.check("1.2.3.4", "10.0.0.1", 22, T0 + 15 + i)
            assert result.verdict == BruteForceVerdict.ATTACK

        assert result.repeat_offender_count == 1

    def test_second_distinct_episode_increments_count(self):
        tracker = BruteForceTracker({**DEFAULT_CONFIG, "window_seconds": 10})

        for i in range(15):
            tracker.record_attempt("1.2.3.4", "10.0.0.1", 22, T0 + i * 0.1)
        result = tracker.check("1.2.3.4", "10.0.0.1", 22, T0 + 1.4)
        assert result.verdict == BruteForceVerdict.ATTACK
        assert result.repeat_offender_count == 1

        # Second episode, well past the first window's expiry.
        second_base = T0 + 1000
        for i in range(15):
            tracker.record_attempt("1.2.3.4", "10.0.0.1", 22, second_base + i * 0.1)
        result = tracker.check("1.2.3.4", "10.0.0.1", 22, second_base + 1.4)
        assert result.verdict == BruteForceVerdict.ATTACK
        assert result.repeat_offender_count == 2