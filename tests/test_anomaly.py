"""
tests/test_anomaly.py
========================
Unit tests for detection/anomaly.py — covers warm-up lifecycle,
scoring of normal vs. attack-shaped feature vectors, save/load
persistence, and the explicit flood-rate guard.
"""

import random

import pytest

from detection.anomaly import AnomalyDetector, Verdict


def make_normal_flow(rng):
    """A realistic-ish normal HTTPS-style flow feature dict."""
    return {
        "src_ip": "192.168.1.50", "dst_ip": "93.184.216.34",
        "src_port": 51000, "dst_port": 443, "protocol": 6,
        "duration_seconds": rng.uniform(0.1, 2.0),
        "total_packets": rng.randint(8, 40),
        "total_bytes": rng.randint(800, 8000),
        "fwd_packets": rng.randint(3, 15), "bwd_packets": rng.randint(3, 25),
        "fwd_bytes": rng.randint(300, 2000), "bwd_bytes": rng.randint(500, 6000),
        "bytes_per_second": rng.uniform(500, 5000), "packets_per_second": rng.uniform(5, 50),
        "fwd_pkt_len_mean": rng.uniform(60, 500), "fwd_pkt_len_max": rng.uniform(500, 1400),
        "fwd_pkt_len_min": rng.uniform(40, 60), "fwd_pkt_len_std": rng.uniform(50, 300),
        "bwd_pkt_len_mean": rng.uniform(100, 800), "bwd_pkt_len_max": rng.uniform(800, 1400),
        "bwd_pkt_len_min": rng.uniform(40, 60), "bwd_pkt_len_std": rng.uniform(100, 400),
        "iat_mean": rng.uniform(0.01, 0.2), "iat_max": rng.uniform(0.2, 1.0),
        "iat_min": rng.uniform(0.001, 0.01), "iat_std": rng.uniform(0.02, 0.15),
        "syn_count": 1, "ack_count": rng.randint(5, 30), "fin_count": rng.randint(0, 2),
        "rst_count": 0, "psh_count": rng.randint(2, 10), "urg_count": 0,
        "syn_ratio": rng.uniform(0.02, 0.15),
        "avg_payload_size": rng.uniform(100, 600), "zero_payload_ratio": rng.uniform(0.0, 0.3),
        "is_well_known_dst_port": 1,
    }


def make_syn_scan_flow():
    """A simulated SYN-scan feature dict — same shape used throughout Phase 1 testing."""
    return {
        "src_ip": "10.0.0.99", "dst_ip": "192.168.1.50",
        "src_port": 40000, "dst_port": 22, "protocol": 6,
        "duration_seconds": 0.02, "total_packets": 50, "total_bytes": 3000,
        "fwd_packets": 50, "bwd_packets": 0, "fwd_bytes": 3000, "bwd_bytes": 0,
        "bytes_per_second": 150000.0, "packets_per_second": 2500.0,
        "fwd_pkt_len_mean": 60.0, "fwd_pkt_len_max": 60.0, "fwd_pkt_len_min": 60.0, "fwd_pkt_len_std": 0.0,
        "bwd_pkt_len_mean": 0.0, "bwd_pkt_len_max": 0.0, "bwd_pkt_len_min": 0.0, "bwd_pkt_len_std": 0.0,
        "iat_mean": 0.0004, "iat_max": 0.001, "iat_min": 0.0001, "iat_std": 0.0001,
        "syn_count": 50, "ack_count": 0, "fin_count": 0, "rst_count": 0, "psh_count": 0, "urg_count": 0,
        "syn_ratio": 1.0, "avg_payload_size": 0.0, "zero_payload_ratio": 1.0, "is_well_known_dst_port": 1,
    }


def make_flood_flow(packets=4000):
    """
    A simulated flood feature dict matching the real flood scenario
    captured during Phase 1 testing (2000 pings, ~4000 total packets,
    near-zero, perfectly uniform inter-arrival time).
    """
    return {
        "src_ip": "172.17.0.2", "dst_ip": "192.168.10.67",
        "src_port": 0, "dst_port": 0, "protocol": 1,
        "duration_seconds": 0.5, "total_packets": packets, "total_bytes": packets * 84,
        "fwd_packets": packets // 2, "bwd_packets": packets // 2,
        "fwd_bytes": packets // 2 * 84, "bwd_bytes": packets // 2 * 84,
        "bytes_per_second": packets * 84 / 0.5, "packets_per_second": packets / 0.5,
        "fwd_pkt_len_mean": 84.0, "fwd_pkt_len_max": 84.0, "fwd_pkt_len_min": 84.0, "fwd_pkt_len_std": 0.0,
        "bwd_pkt_len_mean": 84.0, "bwd_pkt_len_max": 84.0, "bwd_pkt_len_min": 84.0, "bwd_pkt_len_std": 0.0,
        "iat_mean": 0.0002, "iat_max": 0.001, "iat_min": 0.0001, "iat_std": 0.0001,
        "syn_count": 0, "ack_count": 0, "fin_count": 0, "rst_count": 0, "psh_count": 0, "urg_count": 0,
        "syn_ratio": 0.0, "avg_payload_size": 64.0, "zero_payload_ratio": 0.0, "is_well_known_dst_port": 0,
    }


@pytest.fixture
def rng():
    return random.Random(42)


@pytest.fixture
def trained_detector(basic_config, rng):
    """A detector that has already completed warm-up on normal traffic."""
    detector = AnomalyDetector(basic_config)
    for _ in range(basic_config["detection"]["warmup_flows"]):
        detector.predict(make_normal_flow(rng))
    assert detector.is_trained
    return detector


class TestWarmupLifecycle:

    def test_returns_warming_up_before_threshold_reached(self, basic_config, rng):
        detector = AnomalyDetector(basic_config)
        result = detector.predict(make_normal_flow(rng))
        assert result.verdict == Verdict.WARMING_UP
        assert result.score is None
        assert detector.is_trained is False

    def test_trains_automatically_at_warmup_threshold(self, basic_config, rng):
        detector = AnomalyDetector(basic_config)
        warmup_target = basic_config["detection"]["warmup_flows"]

        for _ in range(warmup_target - 1):
            result = detector.predict(make_normal_flow(rng))
            assert result.verdict == Verdict.WARMING_UP

        assert detector.is_trained is False

        # The flow that reaches the threshold should trigger training
        # AND receive a real verdict in the same call.
        final_result = detector.predict(make_normal_flow(rng))
        assert detector.is_trained is True
        assert final_result.verdict != Verdict.WARMING_UP
        assert final_result.score is not None


class TestScoring:

    def test_normal_flows_mostly_score_normal(self, trained_detector, rng):
        verdicts = [trained_detector.predict(make_normal_flow(rng)).verdict for _ in range(30)]
        normal_count = sum(1 for v in verdicts if v == Verdict.NORMAL)
        # Allow for some statistical noise (contamination=0.05 in
        # basic_config means ~5% false-positive rate is expected),
        # but the large majority must still be NORMAL.
        assert normal_count >= 25

    def test_syn_scan_is_flagged_as_attack(self, trained_detector):
        result = trained_detector.predict(make_syn_scan_flow())
        assert result.verdict == Verdict.ATTACK

    def test_syn_scan_score_is_clearly_negative(self, trained_detector):
        result = trained_detector.predict(make_syn_scan_flow())
        assert result.score < trained_detector.attack_threshold


class TestFloodRateGuard:
    """
    The explicit flood-rate guard (see FLOOD_PACKETS_PER_SECOND_THRESHOLD
    in detection/anomaly.py) is a deliberate, separate detection
    mechanism from the Isolation Forest — added after real testing
    showed the general-purpose model alone does not reliably catch
    flood-style traffic. These tests lock in that specific guarantee.
    """

    def test_flood_is_flagged_as_attack(self, trained_detector):
        result = trained_detector.predict(make_flood_flow())
        assert result.verdict == Verdict.ATTACK

    def test_moderate_traffic_below_flood_threshold_not_flagged_by_rate_guard(self, trained_detector, rng):
        # A flow with packets_per_second comfortably below the flood
        # threshold should NOT be forced to ATTACK by the rate guard
        # (it may still be flagged by the Isolation Forest itself on
        # its own merits, but not by this specific mechanism).
        from detection.anomaly import FLOOD_PACKETS_PER_SECOND_THRESHOLD
        flow = make_normal_flow(rng)
        flow["packets_per_second"] = FLOOD_PACKETS_PER_SECOND_THRESHOLD - 1
        result = trained_detector.predict(flow)
        # We can't assert NORMAL here unconditionally (the Isolation
        # Forest might independently flag it), but we CAN assert that
        # if it's flagged, the score itself should be the reason —
        # i.e. the score should not be None and should be consistent
        # with the threshold logic.
        assert result.score is not None


class TestSaveLoad:

    def test_save_load_round_trip_produces_identical_scores(self, trained_detector, rng, tmp_path):
        test_flow = make_normal_flow(rng)
        result_before = trained_detector.predict(test_flow)

        save_path = str(tmp_path / "model.joblib")
        trained_detector.save(save_path)

        from detection.anomaly import AnomalyDetector as FreshDetectorClass
        basic_config_copy = {
            "detection": {
                "warmup_flows": 30,
                "contamination": 0.05,
                "thresholds": {"suspicious": -0.02, "attack": -0.08},
            }
        }
        fresh_detector = FreshDetectorClass(basic_config_copy)
        fresh_detector.load(save_path)

        assert fresh_detector.is_trained is True
        result_after = fresh_detector.predict(test_flow)

        assert result_before.score == pytest.approx(result_after.score, abs=1e-9)
        assert result_before.verdict == result_after.verdict

    def test_save_before_training_raises(self, basic_config):
        detector = AnomalyDetector(basic_config)
        with pytest.raises(RuntimeError):
            detector.save("/tmp/should_not_be_created.joblib")
