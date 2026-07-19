"""
scripts/clean_stale_schema_labels.py
========================================
Identifies and optionally deletes "llm"-sourced labelled_flows rows
whose stored features predate the July 2026 features/extractor.py
change (which added ack_ratio, fwd_packet_share, bwd_fwd_packet_ratio,
iat_cv). See detection/classifier.py's "Schema-consistency check"
docstring section for the full incident this script supports.

Safe by default: running with no arguments only REPORTS what would be
deleted, and deletes nothing. Pass --confirm to actually delete.

Usage:
    python scripts/clean_stale_schema_labels.py            # dry run, report only
    python scripts/clean_stale_schema_labels.py --confirm   # actually delete stale rows

This only ever touches rows where label_source = 'llm'. It never
touches 'ddos_tracker', 'port_scan_tracker', 'auto', or 'llm_failed'
rows, since those already carry a different (and, for ddos_tracker/
port_scan_tracker, intentionally different) feature schema that
classifier.py already excludes from training on its own terms.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys

import yaml

# The features/extractor.py keys that mark a sample as "current
# schema" — added July 2026 to fix the bulk-transfer/ddos
# misclassification. A sample missing ANY of these predates that
# change and is considered stale.
_CURRENT_SCHEMA_MARKER_KEYS = {"ack_ratio", "fwd_packet_share", "iat_cv"}


def load_db_path(config_path: str = "config.yaml") -> str:
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)
    return config["storage"]["db_path"]


def find_stale_rows(db_path: str) -> list[tuple[int, str]]:
    """
    Returns [(row_id, timestamp), ...] for every label_source='llm'
    row whose all_features JSON is missing any of the current-schema
    marker keys.
    """
    conn = sqlite3.connect(db_path)
    stale = []
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            "SELECT id, timestamp, all_features FROM labelled_flows WHERE label_source = 'llm'"
        )
        for row in cursor.fetchall():
            features = json.loads(row["all_features"])
            if not _CURRENT_SCHEMA_MARKER_KEYS.issubset(features.keys()):
                stale.append((row["id"], row["timestamp"]))
    finally:
        conn.close()
    return stale


def delete_rows(db_path: str, row_ids: list[int]) -> None:
    conn = sqlite3.connect(db_path)
    try:
        placeholders = ", ".join("?" for _ in row_ids)
        conn.execute(f"DELETE FROM labelled_flows WHERE id IN ({placeholders})", row_ids)
        conn.commit()
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Identify and optionally delete stale-schema 'llm'-labelled samples."
    )
    parser.add_argument(
        "--confirm", action="store_true",
        help="Actually delete the identified stale rows. Without this flag, only reports."
    )
    parser.add_argument(
        "--config", type=str, default="config.yaml",
        help="Path to config.yaml (default: config.yaml)."
    )
    args = parser.parse_args()

    db_path = load_db_path(args.config)
    print(f"Checking database: {db_path}\n")

    stale = find_stale_rows(db_path)

    if not stale:
        print("No stale-schema 'llm'-sourced samples found. Nothing to do.")
        return

    print(f"Found {len(stale)} stale-schema 'llm'-sourced samples "
          f"(missing one or more of {sorted(_CURRENT_SCHEMA_MARKER_KEYS)}).")
    print(f"Earliest: {min(r[1] for r in stale)}")
    print(f"Latest:   {max(r[1] for r in stale)}\n")

    if not args.confirm:
        print("Dry run only — no rows deleted. Re-run with --confirm to actually delete them.")
        return

    row_ids = [r[0] for r in stale]
    delete_rows(db_path, row_ids)
    print(f"Deleted {len(row_ids)} stale-schema rows from labelled_flows.")


if __name__ == "__main__":
    main()