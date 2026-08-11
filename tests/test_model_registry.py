"""
tests/test_model_registry.py
==========================
Unit tests for training/model_registry.py.

Uses a fake classifier (just needs .save()) instead of a real
AttackClassifier — keeps these tests fast and independent of
sklearn/xgboost being trained on anything.
"""

import json
import os

import pytest

from training.model_registry import ModelMetadata, ModelRegistry, new_version_string


class FakeClassifier:
    """Minimal stand-in for AttackClassifier — just needs .save()."""

    def __init__(self, marker: str = "fake"):
        self.marker = marker

    def save(self, path: str) -> None:
        with open(path, "w") as f:
            f.write(self.marker)


def _make_metadata(version: str, f1_macro: float = 0.8, sample_count: int = 100) -> ModelMetadata:
    return ModelMetadata(
        version=version,
        trained_at="2026-08-11T00:00:00+00:00",
        sample_count=sample_count,
        feature_schema_version="abc123",
        model_name="RandomForest",
        f1_macro=f1_macro,
    )


@pytest.fixture
def registry(tmp_path):
    return ModelRegistry(str(tmp_path / "models"))


class TestSaveCandidate:
    def test_save_creates_model_and_metadata_files(self, registry):
        version = registry.save_candidate(FakeClassifier(), _make_metadata("v1"))

        version_dir = os.path.join(registry.models_dir, version)
        assert os.path.exists(os.path.join(version_dir, "model.pkl"))
        assert os.path.exists(os.path.join(version_dir, "metadata.json"))

    def test_save_does_not_touch_active_pointer(self, registry):
        registry.save_candidate(FakeClassifier(), _make_metadata("v1"))
        assert registry.get_active_version() is None

    def test_metadata_round_trips_correctly(self, registry):
        meta = _make_metadata("v1", f1_macro=0.913, sample_count=250)
        registry.save_candidate(FakeClassifier(), meta)

        loaded = registry.get_metadata("v1")
        assert loaded.f1_macro == 0.913
        assert loaded.sample_count == 250
        assert loaded.promoted is False


class TestPromoteAndRollback:
    def test_promote_sets_active_version(self, registry):
        registry.save_candidate(FakeClassifier(), _make_metadata("v1"))
        registry.promote("v1")
        assert registry.get_active_version() == "v1"

    def test_promote_marks_metadata_as_promoted(self, registry):
        registry.save_candidate(FakeClassifier(), _make_metadata("v1"))
        registry.promote("v1")
        assert registry.get_metadata("v1").promoted is True

    def test_promoting_a_second_version_switches_active(self, registry):
        registry.save_candidate(FakeClassifier(), _make_metadata("v1"))
        registry.save_candidate(FakeClassifier(), _make_metadata("v2"))
        registry.promote("v1")
        registry.promote("v2")
        assert registry.get_active_version() == "v2"

    def test_rollback_is_just_promoting_an_older_version(self, registry):
        registry.save_candidate(FakeClassifier(), _make_metadata("v1"))
        registry.save_candidate(FakeClassifier(), _make_metadata("v2"))
        registry.promote("v2")
        registry.promote("v1")  # rollback
        assert registry.get_active_version() == "v1"

    def test_promoting_nonexistent_version_raises(self, registry):
        with pytest.raises(ValueError):
            registry.promote("does_not_exist")

    def test_get_active_version_is_none_before_any_promotion(self, registry):
        assert registry.get_active_version() is None

    def test_get_active_metadata_is_none_before_any_promotion(self, registry):
        assert registry.get_active_metadata() is None

    def test_get_active_metadata_returns_correct_version(self, registry):
        registry.save_candidate(FakeClassifier(), _make_metadata("v1", f1_macro=0.5))
        registry.save_candidate(FakeClassifier(), _make_metadata("v2", f1_macro=0.9))
        registry.promote("v2")
        assert registry.get_active_metadata().f1_macro == 0.9


class TestLoadActive:
    def test_raises_if_nothing_promoted_yet(self, registry):
        with pytest.raises(RuntimeError):
            registry.load_active(FakeClassifier, config={})


class TestListVersions:
    def test_empty_registry_returns_empty_list(self, registry):
        assert registry.list_versions() == []

    def test_lists_all_saved_versions(self, registry):
        registry.save_candidate(FakeClassifier(), _make_metadata("v1"))
        registry.save_candidate(FakeClassifier(), _make_metadata("v2"))
        versions = {m.version for m in registry.list_versions()}
        assert versions == {"v1", "v2"}

    def test_sorted_newest_first(self, registry):
        registry.save_candidate(FakeClassifier(), _make_metadata("20260101_000000"))
        registry.save_candidate(FakeClassifier(), _make_metadata("20260601_000000"))
        registry.save_candidate(FakeClassifier(), _make_metadata("20260301_000000"))

        versions = [m.version for m in registry.list_versions()]
        assert versions == ["20260601_000000", "20260301_000000", "20260101_000000"]

    def test_only_active_version_marked_promoted(self, registry):
        registry.save_candidate(FakeClassifier(), _make_metadata("v1"))
        registry.save_candidate(FakeClassifier(), _make_metadata("v2"))
        registry.promote("v1")

        by_version = {m.version: m.promoted for m in registry.list_versions()}
        assert by_version == {"v1": True, "v2": False}


class TestPrune:
    def test_deletes_versions_not_in_keep_list(self, registry):
        registry.save_candidate(FakeClassifier(), _make_metadata("v1"))
        registry.save_candidate(FakeClassifier(), _make_metadata("v2"))
        registry.save_candidate(FakeClassifier(), _make_metadata("v3"))

        deleted = registry.prune(keep_versions=["v2"])

        assert set(deleted) == {"v1", "v3"}
        assert {m.version for m in registry.list_versions()} == {"v2"}

    def test_never_prunes_the_active_version_even_if_not_in_keep_list(self, registry):
        registry.save_candidate(FakeClassifier(), _make_metadata("v1"))
        registry.save_candidate(FakeClassifier(), _make_metadata("v2"))
        registry.promote("v1")

        deleted = registry.prune(keep_versions=["v2"])

        assert "v1" not in deleted
        assert registry.get_active_version() == "v1"

    def test_prune_with_nothing_to_delete_returns_empty_list(self, registry):
        registry.save_candidate(FakeClassifier(), _make_metadata("v1"))
        deleted = registry.prune(keep_versions=["v1"])
        assert deleted == []

    def test_pruned_version_directory_is_actually_removed_from_disk(self, registry):
        registry.save_candidate(FakeClassifier(), _make_metadata("v1"))
        version_dir = os.path.join(registry.models_dir, "v1")
        assert os.path.exists(version_dir)

        registry.prune(keep_versions=[])

        assert not os.path.exists(version_dir)


class TestNewVersionString:
    def test_returns_a_string(self):
        assert isinstance(new_version_string(), str)

    def test_format_is_sortable_timestamp(self):
        version = new_version_string()
        # YYYYMMDD_HHMMSS -> 15 characters, digits and one underscore
        assert len(version) == 15
        assert version[8] == "_"
        assert version.replace("_", "").isdigit()


class TestMetadataPersistence:
    def test_metadata_json_is_human_readable_on_disk(self, registry):
        registry.save_candidate(FakeClassifier(), _make_metadata("v1", f1_macro=0.77))

        meta_path = os.path.join(registry.models_dir, "v1", "metadata.json")
        with open(meta_path) as f:
            raw = json.load(f)

        assert raw["version"] == "v1"
        assert raw["f1_macro"] == 0.77
        assert raw["promoted"] is False