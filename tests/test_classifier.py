"""
tests/test_classifier.py
===========================
Unit tests for detection/classifier.py. Uses real scikit-learn and
xgboost (no stubbing needed — these are genuine, fast-running ML
operations on small synthetic datasets, not network calls).
"""

import random
import tempfile
import os

import pytest

from detection.classifier import AttackClassifier, TRAINING_LABEL_SOURCES


class FakeSample:
    """Mimics pipeline.labeller.LabelledSample's shape — just the
    fields AttackClassifier.train() actually reads."""
    def __init__(self, label, label_source, features):
        self.label = label
        self.label_source = label_source
        self.features = features


@pytest.fixture
def rng():
    return random.Random(42)


def make_port_scan_sample(rng):
    return FakeSample("port_scan", "llm", {
        "total_packets": rng.randint(20, 100),
        "packets_per_second": rng.uniform(1000, 3000),
        "syn_ratio": rng.uniform(0.9, 1.0),
        "zero_payload_ratio": rng.uniform(0.9, 1.0),
        "iat_mean": rng.uniform(0.0001, 0.001),
        "bytes_per_second": rng.uniform(50000, 200000),
    })


def make_ddos_sample(rng):
    return FakeSample("ddos", "llm", {
        "total_packets": rng.randint(500, 5000),
        "packets_per_second": rng.uniform(2000, 10000),
        "syn_ratio": rng.uniform(0.0, 0.2),
        "zero_payload_ratio": rng.uniform(0.0, 0.3),
        "iat_mean": rng.uniform(0.00001, 0.0005),
        "bytes_per_second": rng.uniform(100000, 500000),
    })


def make_unknown_sample(rng):
    """label_source='auto' — must be excluded from training entirely."""
    return FakeSample("unknown", "auto", {
        "total_packets": rng.randint(1, 10),
        "packets_per_second": rng.uniform(1, 10),
        "syn_ratio": rng.uniform(0, 0.1),
        "zero_payload_ratio": rng.uniform(0, 0.1),
        "iat_mean": rng.uniform(0.1, 1.0),
        "bytes_per_second": rng.uniform(10, 100),
    })


@pytest.fixture
def small_config():
    return {"detection": {"min_classifier_samples": 50}}


class TestTrainingGating:
    """
    These tests cover the most important safety property of this
    module: a classifier must refuse to train on insufficient or
    meaningless data, rather than silently producing an unreliable
    model.
    """

    def test_insufficient_samples_raises(self, small_config, rng):
        classifier = AttackClassifier(small_config)
        samples = [make_port_scan_sample(rng) for _ in range(10)]
        with pytest.raises(ValueError, match="Not enough"):
            classifier.train(samples)

    def test_single_distinct_class_raises(self, small_config, rng):
        classifier = AttackClassifier(small_config)
        samples = [make_port_scan_sample(rng) for _ in range(60)]
        with pytest.raises(ValueError, match="distinct label"):
            classifier.train(samples)

    def test_non_llm_samples_excluded_from_count(self, small_config, rng):
        """
        Critical: 'auto' and 'llm_failed' samples must never count
        toward the minimum-sample threshold or be used for training,
        since their label is always 'unknown' by definition and
        carries no real signal.
        """
        classifier = AttackClassifier(small_config)
        samples = (
            [make_port_scan_sample(rng) for _ in range(30)]
            + [make_ddos_sample(rng) for _ in range(30)]
            + [make_unknown_sample(rng) for _ in range(200)]  # should not count
        )
        result = classifier.train(samples)
        assert result.total_samples_used == 60  # only the llm-labelled ones


class TestTrainingAndPrediction:

    @pytest.fixture
    def trained_classifier(self, small_config, rng):
        classifier = AttackClassifier(small_config)
        samples = (
            [make_port_scan_sample(rng) for _ in range(40)]
            + [make_ddos_sample(rng) for _ in range(40)]
        )
        classifier.train(samples)
        return classifier

    def test_classifier_is_trained_after_train(self, trained_classifier):
        assert trained_classifier.is_trained is True

    def test_winning_model_is_one_of_the_two_candidates(self, small_config, rng):
        classifier = AttackClassifier(small_config)
        samples = (
            [make_port_scan_sample(rng) for _ in range(40)]
            + [make_ddos_sample(rng) for _ in range(40)]
        )
        result = classifier.train(samples)
        assert result.winning_model_name in ("RandomForest", "XGBoost")
        assert result.losing_report.model_name in ("RandomForest", "XGBoost")
        assert result.winning_model_name != result.losing_report.model_name

    def test_predict_returns_a_known_label(self, trained_classifier, rng):
        label, probabilities = trained_classifier.predict(make_port_scan_sample(rng).features)
        assert label in ("port_scan", "ddos")

    def test_predict_returns_full_probability_distribution(self, trained_classifier, rng):
        label, probabilities = trained_classifier.predict(make_port_scan_sample(rng).features)
        assert isinstance(probabilities, dict)
        assert set(probabilities.keys()) == {"port_scan", "ddos"}
        # Probabilities should sum to (approximately) 1.0
        assert abs(sum(probabilities.values()) - 1.0) < 1e-6

    def test_predict_before_train_raises(self, small_config):
        classifier = AttackClassifier(small_config)
        with pytest.raises(RuntimeError):
            classifier.predict({"total_packets": 10})

    def test_clearly_separable_classes_classify_correctly(self, trained_classifier, rng):
        """
        With these deliberately well-separated synthetic feature
        ranges, the classifier should correctly distinguish the two
        classes on fresh, unseen samples almost all the time.
        """
        correct = 0
        total = 20
        for _ in range(total):
            sample = make_port_scan_sample(rng)
            predicted, _ = trained_classifier.predict(sample.features)
            if predicted == "port_scan":
                correct += 1
        assert correct >= total * 0.8  # Allow some slack, but expect strong accuracy


class TestSaveLoad:

    def test_save_load_round_trip_produces_identical_prediction(self, small_config, rng, tmp_path):
        classifier = AttackClassifier(small_config)
        samples = (
            [make_port_scan_sample(rng) for _ in range(40)]
            + [make_ddos_sample(rng) for _ in range(40)]
        )
        classifier.train(samples)

        test_features = make_port_scan_sample(rng).features
        label_before, probs_before = classifier.predict(test_features)

        save_path = str(tmp_path / "classifier.joblib")
        classifier.save(save_path)

        fresh = AttackClassifier(small_config)
        fresh.load(save_path)
        label_after, probs_after = fresh.predict(test_features)

        assert label_before == label_after
        for key in probs_before:
            assert abs(probs_before[key] - probs_after[key]) < 1e-9

    def test_save_before_train_raises(self, small_config, tmp_path):
        classifier = AttackClassifier(small_config)
        with pytest.raises(RuntimeError):
            classifier.save(str(tmp_path / "should_not_exist.joblib"))