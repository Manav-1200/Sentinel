"""
tests/test_retrain.py
==========================
Unit tests for training/retrain.py.

cmd_check/cmd_run depend on Labeller and ModelRegistry — rather than
hitting a real DB, we monkeypatch those names inside the retrain
module with lightweight fakes. This tests retrain.py's own logic
(threshold math, decision-making) in isolation from labeller.py and
model_registry.py, which already have their own test coverage.
"""

import pytest

from training import retrain
from training.model_registry import ModelMetadata, ModelRegistry


def _make_metadata(sample_count: int, f1_macro: float = 0.8) -> ModelMetadata:
    return ModelMetadata(
        version="20260101_000000",
        trained_at="2026-01-01T00:00:00+00:00",
        sample_count=sample_count,
        feature_schema_version="abc123",
        model_name="RandomForest",
        f1_macro=f1_macro,
    )


class FakeLabeller:
    """Stand-in for pipeline.labeller.Labeller — no real DB involved."""

    def __init__(self, config: dict):
        self.config = config

    def count_by_label_source(self) -> dict:
        return {"llm": self.config.get("_fake_llm_sample_count", 0)}


class TestSchemaVersion:
    def test_returns_a_short_hex_string(self):
        version = retrain._schema_version(["a", "b", "c"])
        assert len(version) == 12
        int(version, 16)  # raises if not valid hex

    def test_same_keys_produce_same_hash(self):
        v1 = retrain._schema_version(["src_ip", "dst_port", "packet_count"])
        v2 = retrain._schema_version(["src_ip", "dst_port", "packet_count"])
        assert v1 == v2

    def test_key_order_does_not_affect_hash(self):
        v1 = retrain._schema_version(["a", "b", "c"])
        v2 = retrain._schema_version(["c", "a", "b"])
        assert v1 == v2

    def test_different_keys_produce_different_hash(self):
        v1 = retrain._schema_version(["a", "b", "c"])
        v2 = retrain._schema_version(["a", "b", "d"])
        assert v1 != v2


class TestCurrentUsableSampleCount:
    def test_returns_llm_count(self):
        labeller = FakeLabeller({"_fake_llm_sample_count": 42})
        assert retrain._current_usable_sample_count(labeller) == 42

    def test_returns_zero_when_no_llm_samples_present(self):
        labeller = FakeLabeller({})
        assert retrain._current_usable_sample_count(labeller) == 0


class TestCmdCheck:
    """Tests the threshold decision logic via monkeypatched Labeller/ModelRegistry."""

    @pytest.fixture(autouse=True)
    def patch_labeller(self, monkeypatch):
        monkeypatch.setattr(retrain, "Labeller", FakeLabeller)

    def _config(self, tmp_path, sample_count, threshold=100):
        return {
            "_fake_llm_sample_count": sample_count,
            "training": {
                "models_dir": str(tmp_path / "models"),
                "retrain_sample_threshold": threshold,
            },
        }

    def test_not_due_when_below_threshold(self, tmp_path):
        config = self._config(tmp_path, sample_count=50, threshold=100)
        assert retrain.cmd_check(config) is False

    def test_due_when_at_threshold(self, tmp_path):
        config = self._config(tmp_path, sample_count=100, threshold=100)
        assert retrain.cmd_check(config) is True

    def test_due_when_above_threshold(self, tmp_path):
        config = self._config(tmp_path, sample_count=150, threshold=100)
        assert retrain.cmd_check(config) is True

    def test_threshold_is_relative_to_last_promoted_count_not_zero(self, tmp_path):
        config = self._config(tmp_path, sample_count=150, threshold=100)
        registry = ModelRegistry(config["training"]["models_dir"])

        # Simulate a model already promoted at sample_count=120 —
        # only 30 new samples since then, below the threshold of 100.
        class _Dummy:
            def save(self, path):
                open(path, "w").close()

        version = registry.save_candidate(_Dummy(), _make_metadata(sample_count=120))
        registry.promote(version)

        assert retrain.cmd_check(config) is False

    def test_due_again_once_enough_new_samples_accumulate_past_last_promotion(self, tmp_path):
        config = self._config(tmp_path, sample_count=230, threshold=100)
        registry = ModelRegistry(config["training"]["models_dir"])

        class _Dummy:
            def save(self, path):
                open(path, "w").close()

        version = registry.save_candidate(_Dummy(), _make_metadata(sample_count=120))
        registry.promote(version)

        # 230 - 120 = 110 new samples, over the threshold of 100.
        assert retrain.cmd_check(config) is True