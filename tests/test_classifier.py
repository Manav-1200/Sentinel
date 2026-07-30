"""
tests/test_classifier.py
===========================
Unit tests for detection/classifier.py's AttackClassifier, focused on
the schema-consistency fix history — three real incidents in a row,
each one a different way the SAME underlying bug (training on the
wrong feature schema) could sneak back in. See classifier.py's module
docstring for the full incident writeup.

FakeSample stands in for pipeline.labeller.LabelledSample — only
label, label_source, and features are ever read by train(), so a
minimal object avoids depending on Labeller/sqlite at all here.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from detection.classifier import AttackClassifier
from features.extractor import CURRENT_FEATURE_KEYS


@dataclass
class FakeSample:
    label: str
    label_source: str
    features: dict


def current_schema_features(is_flood: bool, total_packets: int = 10000) -> dict:
    """A sample whose feature-key set exactly matches
    CURRENT_FEATURE_KEYS — i.e. what a real, up-to-date extract() call
    would produce, with plausible flood-vs-benign values on the keys
    that actually matter for that distinction."""
    f = {k: 0.0 for k in CURRENT_FEATURE_KEYS}
    f["protocol"] = 6
    f["total_packets"] = total_packets
    f["duration_seconds"] = 15.0
    f["packets_per_second"] = total_packets / 15.0
    f["total_bytes"] = total_packets * 800
    f["bytes_per_second"] = f["total_bytes"] / 15.0
    if is_flood:
        f["fwd_packets"] = int(total_packets * 0.97)
        f["bwd_packets"] = total_packets - f["fwd_packets"]
        f["fwd_packet_share"] = 0.97
        f["syn_ratio"] = 0.9
        f["ack_ratio"] = 0.05
        f["zero_payload_ratio"] = 0.9
        f["iat_cv"] = 0.05
    else:
        f["fwd_packets"] = int(total_packets * 0.3)
        f["bwd_packets"] = total_packets - f["fwd_packets"]
        f["fwd_packet_share"] = 0.3
        f["syn_ratio"] = 0.02
        f["ack_ratio"] = 0.75
        f["zero_payload_ratio"] = 0.1
        f["iat_cv"] = 1.0
    f["src_ip"], f["dst_ip"], f["src_port"], f["dst_port"] = "10.0.0.1", "10.0.0.2", 1234, 443
    return f


def stale_schema_features(is_flood: bool) -> dict:
    """A pre-fix sample — missing fwd_packet_share/ack_ratio/iat_cv
    and every other key added since, simulating a sample stored before
    features/extractor.py's bulk-transfer/ddos fix landed."""
    return {
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 1234, "dst_port": 443,
        "protocol": 6,
        "total_packets": 10000 if is_flood else 8000,
        "packets_per_second": 3000.0 if is_flood else 500.0,
        "syn_ratio": 0.9 if is_flood else 0.02,
        "zero_payload_ratio": 0.9 if is_flood else 0.1,
        "duration_seconds": 15.0,
        "bytes_per_second": 200000.0,
    }


@pytest.fixture
def config():
    return {"detection": {"min_classifier_samples": 20}}


class TestSchemaConsistencyRegression:
    """
    Regression coverage for the third schema-consistency incident:
    canonical schema must be derived from CURRENT_FEATURE_KEYS, NOT
    from a majority vote across stored samples — a majority vote only
    happens to work once current-schema samples already outnumber
    stale ones, which is never true right after a real
    features/extractor.py change.
    """

    def test_current_schema_wins_even_as_a_small_minority(self, config):
        """
        The exact real-world shape that broke the previous (majority-
        vote) fix: 700 stale-schema samples vastly outnumbering 40
        current-schema ones — matching classifier.py's own documented
        incident ("706 stored samples and only a handful collected
        after the feature change").
        """
        samples = (
            [FakeSample("ddos", "llm", stale_schema_features(True)) for _ in range(350)]
            + [FakeSample("benign", "llm", stale_schema_features(False)) for _ in range(350)]
            + [FakeSample("ddos", "llm", current_schema_features(True)) for _ in range(20)]
            + [FakeSample("benign", "llm", current_schema_features(False)) for _ in range(20)]
        )

        clf = AttackClassifier(config)
        result = clf.train(samples)

        # Must train on the 40 CURRENT-schema samples, not the 700 stale ones.
        assert result.total_samples_used == 40
        assert "fwd_packet_share" in clf._feature_order
        assert "ack_ratio" in clf._feature_order
        assert "iat_cv" in clf._feature_order

    def test_current_schema_wins_as_the_majority_too(self, config):
        """Complementary case: confirms the fix also still works when
        current-schema samples happen to already be the majority —
        the one scenario the old (broken) fix handled correctly."""
        samples = (
            [FakeSample("ddos", "llm", current_schema_features(True)) for _ in range(80)]
            + [FakeSample("benign", "llm", current_schema_features(False)) for _ in range(80)]
            + [FakeSample("ddos", "llm", stale_schema_features(True)) for _ in range(10)]
            + [FakeSample("benign", "llm", stale_schema_features(False)) for _ in range(10)]
        )

        clf = AttackClassifier(config)
        result = clf.train(samples)

        assert result.total_samples_used == 160
        assert "fwd_packet_share" in clf._feature_order

    def test_all_stale_schema_raises_clear_not_enough_data_error(self, config):
        """If every stored sample predates the current schema (e.g.
        right after a fresh features/extractor.py change with zero
        current-schema samples collected yet), train() must raise a
        clear, actionable error — never silently train on stale data,
        and never crash with an unrelated exception (e.g. IndexError
        from an empty most_common() call, the failure mode of the
        previous majority-vote implementation)."""
        samples = (
            [FakeSample("ddos", "llm", stale_schema_features(True)) for _ in range(30)]
            + [FakeSample("benign", "llm", stale_schema_features(False)) for _ in range(30)]
        )

        clf = AttackClassifier(config)
        with pytest.raises(ValueError, match="CURRENT-SCHEMA"):
            clf.train(samples)

    def test_bulk_transfer_correctly_classified_as_benign_not_ddos(self, config):
        """
        End-to-end confirmation of the real incident this whole chain
        of fixes exists for: a large legitimate transfer must be
        classified as benign, using only current-schema training data
        drawn from a realistic minority-of-the-database split.
        """
        samples = (
            [FakeSample("ddos", "llm", stale_schema_features(True)) for _ in range(300)]
            + [FakeSample("benign", "llm", stale_schema_features(False)) for _ in range(300)]
            + [FakeSample("ddos", "llm", current_schema_features(True, total_packets=n))
               for n in range(15000, 15000 + 25 * 200, 200)][:25]
            + [FakeSample("benign", "llm", current_schema_features(False, total_packets=n))
               for n in range(15000, 15000 + 25 * 200, 200)][:25]
        )

        clf = AttackClassifier(config)
        clf.train(samples)

        bulk_download = current_schema_features(is_flood=False, total_packets=68245)
        label, probs = clf.predict(bulk_download)

        assert label == "benign", (
            f"Large legitimate transfer misclassified as {label!r} — "
            f"probabilities: {probs}"
        )

    def test_genuine_flood_still_classified_as_ddos(self, config):
        """Complementary check: the fix must not overcorrect into
        calling every high-volume flow benign — a genuine flood
        pattern (forward-heavy, low ACK ratio, low IAT variability)
        must still be caught."""
        samples = (
            [FakeSample("ddos", "llm", stale_schema_features(True)) for _ in range(300)]
            + [FakeSample("benign", "llm", stale_schema_features(False)) for _ in range(300)]
            + [FakeSample("ddos", "llm", current_schema_features(True, total_packets=n))
               for n in range(15000, 15000 + 25 * 200, 200)][:25]
            + [FakeSample("benign", "llm", current_schema_features(False, total_packets=n))
               for n in range(15000, 15000 + 25 * 200, 200)][:25]
        )

        clf = AttackClassifier(config)
        clf.train(samples)

        flood = current_schema_features(is_flood=True, total_packets=35716)
        label, probs = clf.predict(flood)

        assert label == "ddos", f"Genuine flood misclassified as {label!r} — probabilities: {probs}"