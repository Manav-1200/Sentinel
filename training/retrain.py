"""
training/retrain.py
==========================
Standalone CLI for retraining the AttackClassifier. Deliberately a
separate process from main.py's live sensor — training is a CPU-heavy,
bursty workload that has no business sharing a process with real-time
packet capture (see Phase 5 scoping conversation, Aug 2026).

Usage:
    python -m training.retrain check      # is a retrain due? (exit 0/1, no training)
    python -m training.retrain run        # retrain only if threshold met
    python -m training.retrain run --force  # retrain regardless of threshold
    python -m training.retrain list       # show all saved versions
    python -m training.retrain promote <version>  # manual promotion / rollback
    python -m training.retrain prune <version> [<version> ...]  # keep only these + active

Promotion logic: a freshly trained candidate is auto-promoted only if
its f1_macro beats the currently active model's. If it's worse, equal,
or there's no active model yet's baseline to compare confidently
against, it's saved as a candidate and left for manual promotion via
`promote`.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from datetime import datetime, timezone

import yaml

from detection.classifier import AttackClassifier
from features.extractor import CURRENT_FEATURE_KEYS
from pipeline.labeller import Labeller
from training.model_registry import ModelMetadata, ModelRegistry, new_version_string


def _load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def _schema_version(keys) -> str:
    """Short hash of the current feature schema, so metadata can show
    at a glance whether a saved model matches today's feature set."""
    joined = ",".join(sorted(keys))
    return hashlib.sha256(joined.encode()).hexdigest()[:12]


def _current_usable_sample_count(labeller: Labeller) -> int:
    counts = labeller.count_by_label_source()
    return counts.get("llm", 0)


def cmd_check(config: dict) -> bool:
    """Returns True if a retrain is due. Prints status either way."""
    labeller = Labeller(config)
    registry = ModelRegistry(config["training"]["models_dir"])

    current_count = _current_usable_sample_count(labeller)
    threshold = config["training"]["retrain_sample_threshold"]
    active_meta = registry.get_active_metadata()
    last_count = active_meta.sample_count if active_meta else 0

    new_samples = current_count - last_count
    due = new_samples >= threshold

    print(f"[sentinel] Usable ('llm') samples now: {current_count}")
    print(f"[sentinel] Usable samples at last promoted train: {last_count}")
    print(f"[sentinel] New samples since then: {new_samples} (threshold: {threshold})")
    print(f"[sentinel] Retrain due: {due}")
    return due


def cmd_run(config: dict, force: bool) -> None:
    if not force and not cmd_check(config):
        print("[sentinel] Threshold not met — skipping. Use --force to retrain anyway.")
        return

    labeller = Labeller(config)
    registry = ModelRegistry(config["training"]["models_dir"])

    samples = labeller.fetch_all()
    classifier = AttackClassifier(config)

    print(f"[sentinel] Training on {len(samples)} total stored samples "
          f"(usable subset filtered internally by AttackClassifier)...")
    result = classifier.train(samples)
    print(f"[sentinel] Winner: {result.winning_model_name} "
          f"(f1_macro={result.winning_report.f1_macro:.4f}, "
          f"used {result.total_samples_used} samples)")

    metadata = ModelMetadata(
        version=new_version_string(),
        trained_at=datetime.now(timezone.utc).isoformat(),
        sample_count=result.total_samples_used,
        feature_schema_version=_schema_version(CURRENT_FEATURE_KEYS),
        model_name=result.winning_model_name,
        f1_macro=result.winning_report.f1_macro,
    )
    version = registry.save_candidate(classifier, metadata)
    print(f"[sentinel] Saved candidate version: {version}")

    active_meta = registry.get_active_metadata()
    if active_meta is None:
        print("[sentinel] No active model yet — auto-promoting first trained model.")
        registry.promote(version)
    elif metadata.f1_macro > active_meta.f1_macro:
        print(f"[sentinel] New model beats active "
              f"({metadata.f1_macro:.4f} > {active_meta.f1_macro:.4f}) — auto-promoting.")
        registry.promote(version)
    else:
        print(f"[sentinel] New model does NOT beat active "
              f"({metadata.f1_macro:.4f} <= {active_meta.f1_macro:.4f}). "
              f"Left as a candidate — promote manually if you want it anyway:\n"
              f"    python -m training.retrain promote {version}")


def cmd_list(config: dict) -> None:
    registry = ModelRegistry(config["training"]["models_dir"])
    versions = registry.list_versions()
    if not versions:
        print("[sentinel] No trained model versions yet.")
        return
    for meta in versions:
        marker = " (ACTIVE)" if meta.promoted else ""
        print(f"{meta.version}{marker}  model={meta.model_name}  "
              f"f1_macro={meta.f1_macro:.4f}  samples={meta.sample_count}  "
              f"schema={meta.feature_schema_version}")


def cmd_promote(config: dict, version: str) -> None:
    registry = ModelRegistry(config["training"]["models_dir"])
    registry.promote(version)
    print(f"[sentinel] Promoted {version} to active.")


def cmd_prune(config: dict, keep: list[str]) -> None:
    registry = ModelRegistry(config["training"]["models_dir"])
    deleted = registry.prune(keep)
    if deleted:
        print(f"[sentinel] Deleted {len(deleted)} version(s): {', '.join(deleted)}")
    else:
        print("[sentinel] Nothing to delete — every version is in the keep list or active.")


def main():
    parser = argparse.ArgumentParser(description="Sentinel classifier retraining CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("check")

    run_parser = sub.add_parser("run")
    run_parser.add_argument("--force", action="store_true",
                             help="Retrain even if the sample threshold isn't met")

    sub.add_parser("list")

    promote_parser = sub.add_parser("promote")
    promote_parser.add_argument("version")

    prune_parser = sub.add_parser("prune")
    prune_parser.add_argument("versions", nargs="+")

    args = parser.parse_args()
    config = _load_config()

    if args.command == "check":
        due = cmd_check(config)
        sys.exit(0 if due else 1)
    elif args.command == "run":
        cmd_run(config, force=args.force)
    elif args.command == "list":
        cmd_list(config)
    elif args.command == "promote":
        cmd_promote(config, args.version)
    elif args.command == "prune":
        cmd_prune(config, args.versions)


if __name__ == "__main__":
    main()