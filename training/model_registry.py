"""
training/model_registry.py
==========================
Versioned storage for trained AttackClassifier models.

Every train run is saved as its own timestamped file — nothing is
overwritten, nothing is deleted automatically. A separate
active_model.json pointer file says which version main.py should
actually load. Rollback is just repointing that file, not moving or
renaming model files around.

Design decisions (see Phase 5 scoping conversation, Aug 2026):
- Timestamp filenames, not sequential IDs — no counter file to keep
  in sync, always unique, sortable by recency for free.
- Keep every version on disk. Pruning is a manual CLI command, never
  automatic — model files are cheap, a bad silent auto-delete isn't.
- Metadata lives next to each model (same JSON, not a separate DB) so
  a models/ directory is self-describing on its own.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Optional


@dataclass
class ModelMetadata:
    """Everything needed to know what a saved model version actually is,
    without having to load and inspect the pickle itself."""
    version: str  # timestamp string, e.g. "20260810_143022"
    trained_at: str  # ISO timestamp
    sample_count: int
    feature_schema_version: str  # hash or version tag of CURRENT_FEATURE_KEYS at train time
    model_name: str  # "RandomForest" or "XGBoost"
    f1_macro: float
    promoted: bool = False


class ModelRegistry:
    """
    Manages a directory of versioned model files:

        models/
          20260810_143022/
            model.pkl
            metadata.json
          20260811_090512/
            model.pkl
            metadata.json
          active_model.json   <- pointer: {"version": "20260810_143022"}
    """

    POINTER_FILENAME = "active_model.json"

    def __init__(self, models_dir: str):
        self.models_dir = models_dir
        os.makedirs(self.models_dir, exist_ok=True)

    def save_candidate(self, classifier, metadata: ModelMetadata) -> str:
        """
        Save a freshly trained classifier as a new version. Does NOT
        touch the active pointer — new versions start as candidates,
        promotion is a separate explicit step (auto or manual).

        Returns the version string.
        """
        version_dir = os.path.join(self.models_dir, metadata.version)
        os.makedirs(version_dir, exist_ok=True)

        classifier.save(os.path.join(version_dir, "model.pkl"))
        with open(os.path.join(version_dir, "metadata.json"), "w") as f:
            json.dump(asdict(metadata), f, indent=2)

        return metadata.version

    def promote(self, version: str) -> None:
        """Point active_model.json at this version. Also usable for
        rollback — just call with an older version string."""
        if not self._version_exists(version):
            raise ValueError(f"Model version '{version}' not found in {self.models_dir}")

        pointer_path = os.path.join(self.models_dir, self.POINTER_FILENAME)
        with open(pointer_path, "w") as f:
            json.dump({"version": version}, f, indent=2)

        # Mark this version's metadata as promoted, for list_versions() display.
        meta = self.get_metadata(version)
        meta.promoted = True
        meta_path = os.path.join(self.models_dir, version, "metadata.json")
        with open(meta_path, "w") as f:
            json.dump(asdict(meta), f, indent=2)

    def get_active_version(self) -> Optional[str]:
        """Returns the currently active version string, or None if
        nothing has ever been promoted."""
        pointer_path = os.path.join(self.models_dir, self.POINTER_FILENAME)
        if not os.path.exists(pointer_path):
            return None
        with open(pointer_path) as f:
            return json.load(f)["version"]

    def get_active_metadata(self) -> Optional[ModelMetadata]:
        version = self.get_active_version()
        if version is None:
            return None
        return self.get_metadata(version)

    def load_active(self, classifier_cls, config: dict):
        """Load the currently active model into a fresh classifier
        instance. Raises RuntimeError if nothing has been promoted yet."""
        version = self.get_active_version()
        if version is None:
            raise RuntimeError(
                "No active model — nothing has been promoted yet. "
                "Run training/retrain.py first."
            )
        classifier = classifier_cls(config)
        classifier.load(os.path.join(self.models_dir, version, "model.pkl"))
        return classifier

    def get_metadata(self, version: str) -> ModelMetadata:
        meta_path = os.path.join(self.models_dir, version, "metadata.json")
        with open(meta_path) as f:
            data = json.load(f)
        return ModelMetadata(**data)

    def list_versions(self) -> list[ModelMetadata]:
        """All versions, newest first."""
        active = self.get_active_version()
        versions = []
        for name in os.listdir(self.models_dir):
            if name == self.POINTER_FILENAME:
                continue
            if os.path.isdir(os.path.join(self.models_dir, name)):
                meta = self.get_metadata(name)
                meta.promoted = (name == active)
                versions.append(meta)
        return sorted(versions, key=lambda m: m.version, reverse=True)

    def prune(self, keep_versions: list[str]) -> list[str]:
        """
        Manually delete every version NOT in keep_versions. Refuses to
        prune the currently active version even if you forget to list
        it, since deleting a running model out from under itself is
        never what you want.

        Returns the list of version strings actually deleted.
        """
        active = self.get_active_version()
        keep = set(keep_versions)
        if active:
            keep.add(active)

        deleted = []
        for meta in self.list_versions():
            if meta.version not in keep:
                shutil.rmtree(os.path.join(self.models_dir, meta.version))
                deleted.append(meta.version)
        return deleted

    # ------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------

    def _version_exists(self, version: str) -> bool:
        return os.path.isdir(os.path.join(self.models_dir, version))


def new_version_string() -> str:
    """Timestamp-based version ID, e.g. '20260810_143022'."""
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")