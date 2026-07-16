"""
scripts/clean_multicast_ddos_labels.py
==========================================
One-off cleanup for training data poisoned before the multicast/
broadcast classifier-label gate was added to main.py (see main.py's
_is_multicast_or_broadcast_destination()).

Finds labelled_flows rows where label='ddos' AND label_source='llm'
AND dst_ip is a multicast or broadcast address — i.e. cases where the
LLM itself mislabelled ordinary SSDP/mDNS/UPnP LAN discovery chatter
as a DDoS attack, back when the anomaly detector flagged an unusual
burst of it SUSPICIOUS and asked the LLM to analyse it. Every one of
these rows is training-data poison: any future classifier retrain
keeps learning to confidently guess "ddos" on this exact harmless
pattern (which is exactly what was observed live on 2026-07-15).

Deliberately does NOT touch:
  - label_source='ddos_tracker' rows — real, deterministic aggregate
    DDoS detections from detection/ddos_tracker.py. These store a
    synthetic feature dict with no dst_ip field at all (see
    Labeller.process_ddos_attack), so they can never match this
    query in the first place, but it's worth being explicit: this
    script is not second-guessing genuine DDoS findings.
  - Any row labelled "ddos" whose dst_ip is a normal unicast
    address, even if it turns out to be wrong for some other reason —
    that's a different, unrelated question and out of scope here.

Safe by default: running with no flags only LISTS what it would
delete. Nothing is removed until you pass --delete.

Usage:
    python scripts/clean_multicast_ddos_labels.py            # dry run — lists matches only
    python scripts/clean_multicast_ddos_labels.py --delete   # actually deletes them

Recommended: back up the database first —
    cp data/logs/sentinel.db data/logs/sentinel.db.bak
"""

from __future__ import annotations

import argparse
import ipaddress
import sqlite3

import yaml


def is_multicast_or_broadcast(dst_ip) -> bool:
    """Same logic as main.py's _is_multicast_or_broadcast_destination —
    kept in sync deliberately so this cleanup targets exactly the
    traffic pattern the live gate now excludes going forward."""
    try:
        addr = ipaddress.ip_address(dst_ip)
    except (ValueError, TypeError):
        return False
    return addr.is_multicast or str(addr) == "255.255.255.255"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml (default: config.yaml)")
    parser.add_argument("--delete", action="store_true",
                         help="Actually delete the matched rows. Without this flag, only lists them.")
    args = parser.parse_args()

    with open(args.config) as f:
        config = yaml.safe_load(f)
    db_path = config["storage"]["db_path"]

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.execute(
            "SELECT id, timestamp, dst_ip, dst_port, confidence, reasoning "
            "FROM labelled_flows WHERE label = 'ddos' AND label_source = 'llm'"
        )
        rows = cursor.fetchall()
        matches = [row for row in rows if is_multicast_or_broadcast(row["dst_ip"])]

        if not matches:
            print("No multicast/broadcast-destination 'ddos' samples found. Nothing to clean.")
            return

        print(f"Found {len(matches)} mislabelled sample(s):\n")
        for row in matches:
            print(
                f"  id={row['id']:<6} {row['timestamp']}  "
                f"dst={row['dst_ip']}:{row['dst_port']}  "
                f"confidence={row['confidence']}  "
                f"reasoning={row['reasoning']!r}"
            )

        if not args.delete:
            print(
                f"\nDry run only — no rows deleted. "
                f"Re-run with --delete to actually remove these {len(matches)} row(s)."
            )
            return

        ids = [row["id"] for row in matches]
        placeholders = ",".join("?" for _ in ids)
        conn.execute(f"DELETE FROM labelled_flows WHERE id IN ({placeholders})", ids)
        conn.commit()
        print(f"\nDeleted {len(matches)} row(s).")
    finally:
        conn.close()


if __name__ == "__main__":
    main()