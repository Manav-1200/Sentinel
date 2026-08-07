"""
pipeline/retention.py

Implements docs/db_retention_policy.md against the REAL schema
(pipeline/labeller.py's `evidence` and `labelled_flows` tables) —
closes the item tracked in PHASES.md Phase 6 ("DB retention/rotation —
design done, not implemented ... blocked on reading the real DB
schema"). That doc's own "next step" said not to write deletion SQL
until the real column names were available; this module is that
follow-up, now that they are.

One real constraint the design doc flagged but couldn't resolve
without the schema, and still can't fully resolve even with it:
--------------------------------------------------------------------
Incidents (detection/correlation_engine.py) are IN-MEMORY ONLY — they
are never persisted to the DB, and the `evidence` table has no
incident_id or resolved-at column. So "don't delete evidence behind an
open incident" can only be checked by a retention pass running in the
SAME PROCESS as the live CorrelationEngine (exactly like the design
doc proposed — inline from main.py's loop, not a separate process
reading a stale snapshot). RetentionManager is therefore constructed
with a reference to the live CorrelationEngine, the same pattern
Labeller already uses.

A second, smaller consequence of the same gap: there's no persisted
"resolved_at" timestamp to measure 90 days FROM. What's implemented
instead: SUSPICIOUS/ATTACK/UNAVAILABLE evidence rows older than
resolved_incident_evidence_days AND whose src_ip has no currently-OPEN
incident are eligible for deletion. This is a deliberate approximation
of "90 days after resolution" using "90 days old and not currently
part of an open incident" — since incidents never auto-close (see
correlation_engine.py), a source with an open incident is protected
regardless of its evidence's age, which preserves the actual safety
property the design doc cared about (never delete evidence an active
investigation still needs), even without a real resolution timestamp
to anchor the exact 90-day window to.

Tiers implemented (see db_retention_policy.md for full rationale):
--------------------------------------------------------------------
  1. NORMAL/WARMING_UP evidence older than normal_evidence_days.
     These are bulk, low-value-per-row rows — labeller.store_evidence()
     is called for EVERY flow via from_anomaly(), not just
     SUSPICIOUS/ATTACK ones, so this tier is the overwhelming majority
     of table growth in practice.
  2. SUSPICIOUS/ATTACK/UNAVAILABLE evidence older than
     resolved_incident_evidence_days, EXCLUDING any src_ip (or the
     aggregate DDoS bucket) with a currently-open incident. See the
     approximation note above.
  3. labelled_flows, size-capped per label (not time-capped) at
     max_training_samples_per_class, oldest-first eviction once a
     label is OVER cap. Deliberately does NOT touch labels under cap,
     even if very old — see db_retention_policy.md's "why training
     samples get a size cap, not a time cap".

Batching and VACUUM:
--------------------------------------------------------------------
Deletes run in small batches (retention.batch_size, default 500) in a
loop rather than one giant DELETE, so a live SQLite file being
concurrently written by the capture loop never gets held under one
long-running exclusive write. VACUUM reclaims the space DELETE alone
leaves behind, but rewrites the whole file — so it's interval-gated
(retention.vacuum_interval_hours) via a tiny `_retention_meta`
key/value table, and is only ever invoked at the END of a full
run_pass() (after all deletes have committed and released their
locks), never interleaved with the batch loops.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass, field

from detection.correlation_engine import CorrelationEngine, AGGREGATE_KEY

# Verdicts treated as "bulk, low value" — see tier 1 above. Matches
# the two verdicts detection/evidence.py's EvidenceVerdict enum
# defines as "not a finding" (correlation_engine.py's own
# _IGNORED_VERDICTS uses this exact pair for the same reason).
_BULK_VERDICTS = ("NORMAL", "WARMING_UP")

# Verdicts treated as "a real finding" — see tier 2 above. UNAVAILABLE
# (LLM call failed) is included deliberately: correlation_engine.py
# still attaches UNAVAILABLE evidence to an ALREADY-open incident (see
# that module's docstring), so it's part of the same story as the
# SUSPICIOUS/ATTACK evidence around it, not bulk noise like NORMAL is.
_FINDING_VERDICTS = ("SUSPICIOUS", "ATTACK", "UNAVAILABLE")


@dataclass
class RetentionStats:
    """What one run_pass() actually did — returned so callers (and
    tests) can assert on real numbers instead of just "it didn't
    crash". Mirrors reporting/incident_report.py's pattern of
    returning a small result object rather than only printing."""
    bulk_evidence_deleted: int = 0
    finding_evidence_deleted: int = 0
    training_samples_deleted: int = 0
    vacuum_ran: bool = False


class RetentionManager:
    """
    Periodic DB maintenance for Sentinel's SQLite store. Constructed
    once alongside the Labeller (same db_path, same live
    CorrelationEngine) and given a chance to run via maybe_run(),
    called from main.py's per-flow loop the same way
    cli_display.py's own periodic summary line is — see that module's
    _SUMMARY_EVERY_N_FLOWS for the pattern this mirrors.
    """

    def __init__(self, config: dict, correlation_engine: CorrelationEngine):
        self.db_path: str = config["storage"]["db_path"]
        self.correlation_engine = correlation_engine

        retention_config = config.get("retention", {})
        self.enabled: bool = bool(retention_config.get("enabled", True))
        self.normal_evidence_days: float = float(retention_config.get("normal_evidence_days", 7))
        self.resolved_incident_evidence_days: float = float(
            retention_config.get("resolved_incident_evidence_days", 90)
        )
        self.max_training_samples_per_class: int = int(
            retention_config.get("max_training_samples_per_class", 5000)
        )
        self.vacuum_interval_hours: float = float(retention_config.get("vacuum_interval_hours", 24))
        self.batch_size: int = int(retention_config.get("batch_size", 500))

        # How often (in flows processed) main.py should give this a
        # chance to run — checked, not enforced, by main.py's loop;
        # kept here so the interval lives next to the rest of this
        # subsystem's config rather than as a bare constant in main.py.
        self.run_every_n_flows: int = int(retention_config.get("run_every_n_flows", 5000))

        self._ensure_meta_table()

    # ------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------

    def maybe_run(self, flows_processed: int) -> RetentionStats | None:
        """
        Call on every flow with the running total flow count.
        Returns a RetentionStats if a pass actually ran (i.e.
        flows_processed is a multiple of run_every_n_flows and
        retention.enabled is true), else None — mirrors
        cli_display.py's `total_flows_seen % _SUMMARY_EVERY_N_FLOWS`
        gate exactly, so main.py's loop only needs one extra `if`.
        """
        if not self.enabled or flows_processed <= 0:
            return None
        if flows_processed % self.run_every_n_flows != 0:
            return None
        return self.run_pass()

    def run_pass(self, now: float | None = None) -> RetentionStats:
        """
        Run one full maintenance pass: both evidence tiers, the
        training-sample size cap, then VACUUM if due. Safe to call
        directly (e.g. from a manual maintenance script, or a test)
        without waiting for maybe_run()'s flow-count gate.
        """
        now = time.time() if now is None else now
        stats = RetentionStats()

        conn = self._connect()
        try:
            stats.bulk_evidence_deleted = self._delete_bulk_evidence(conn, now)
            stats.finding_evidence_deleted = self._delete_resolved_finding_evidence(conn, now)
            stats.training_samples_deleted = self._cap_training_samples(conn)
        finally:
            conn.close()

        stats.vacuum_ran = self._vacuum_if_due(now)
        return stats

    # ------------------------------------------------------------
    # Tier 1 — bulk NORMAL/WARMING_UP evidence
    # ------------------------------------------------------------

    def _delete_bulk_evidence(self, conn: sqlite3.Connection, now: float) -> int:
        cutoff = now - (self.normal_evidence_days * 86400)
        placeholders = ", ".join("?" for _ in _BULK_VERDICTS)
        return self._batched_delete(
            conn,
            select_ids_sql=f"""
                SELECT id FROM evidence
                WHERE verdict IN ({placeholders}) AND timestamp < ?
                LIMIT ?
            """,
            select_ids_params=[*_BULK_VERDICTS, cutoff],
        )

    # ------------------------------------------------------------
    # Tier 2 — SUSPICIOUS/ATTACK/UNAVAILABLE evidence, protecting
    # anything behind a currently-open incident
    # ------------------------------------------------------------

    def _delete_resolved_finding_evidence(self, conn: sqlite3.Connection, now: float) -> int:
        cutoff = now - (self.resolved_incident_evidence_days * 86400)

        # Protected src_ips: anything with a currently-OPEN incident.
        # Re-derived fresh on every call (incidents can open/close
        # between passes) rather than cached — see module docstring's
        # "no persisted resolved-at timestamp" note for why this is
        # the best available signal.
        open_keys = {incident.key for incident in self.correlation_engine.open_incidents()}
        aggregate_open = AGGREGATE_KEY in open_keys
        protected_src_ips = open_keys - {AGGREGATE_KEY}

        finding_placeholders = ", ".join("?" for _ in _FINDING_VERDICTS)

        # src_ip IS NULL rows are the aggregate DDoS bucket's evidence
        # (ddos_tracker findings have no single attacker — see
        # correlation_engine.py's AGGREGATE_KEY docstring). Protect
        # those specifically if the aggregate incident is open;
        # otherwise they're eligible for deletion like any other
        # old finding.
        if aggregate_open:
            null_src_clause = "AND src_ip IS NOT NULL"
        else:
            null_src_clause = ""

        if protected_src_ips:
            protected_placeholders = ", ".join("?" for _ in protected_src_ips)
            protected_clause = f"AND (src_ip IS NULL OR src_ip NOT IN ({protected_placeholders}))"
            protected_params = list(protected_src_ips)
        else:
            protected_clause = ""
            protected_params = []

        select_sql = f"""
            SELECT id FROM evidence
            WHERE verdict IN ({finding_placeholders})
              AND timestamp < ?
              {null_src_clause}
              {protected_clause}
            LIMIT ?
        """
        params = [*_FINDING_VERDICTS, cutoff, *protected_params]

        return self._batched_delete(conn, select_sql, params)

    # ------------------------------------------------------------
    # Tier 3 — training-sample size cap (labelled_flows)
    # ------------------------------------------------------------

    def _cap_training_samples(self, conn: sqlite3.Connection) -> int:
        cursor = conn.execute("SELECT label, COUNT(*) FROM labelled_flows GROUP BY label")
        counts = dict(cursor.fetchall())

        total_deleted = 0
        for label, count in counts.items():
            overflow = count - self.max_training_samples_per_class
            if overflow <= 0:
                continue
            # Oldest-first eviction within this one label only — a
            # label under cap is never touched, even by this same
            # call, since `overflow` is computed per label.
            total_deleted += self._batched_delete(
                conn,
                select_ids_sql="""
                    SELECT id FROM labelled_flows
                    WHERE label = ?
                    ORDER BY timestamp ASC
                    LIMIT ?
                """,
                select_ids_params=[label],
                table="labelled_flows",
                # Two independent caps here, not one: batch_size bounds
                # each individual DELETE's size (the concurrency-safety
                # concern _batched_delete exists for), while max_total
                # bounds the CUMULATIVE deletion across all batches to
                # exactly `overflow` rows - without max_total the loop
                # would keep paging through this label's rows batch
                # after batch until every row was gone, not just the
                # over-cap ones (caught by the synthetic-data test
                # below: 600 rows, cap 500, this used to delete all 600
                # instead of stopping at 100).
                max_total=overflow,
            )
        return total_deleted

    # ------------------------------------------------------------
    # Shared batching helper
    # ------------------------------------------------------------

    def _batched_delete(
        self,
        conn: sqlite3.Connection,
        select_ids_sql: str,
        select_ids_params: list,
        table: str = "evidence",
        max_total: int | None = None,
    ) -> int:
        """
        Repeatedly selects up to `batch_size` matching row ids and
        deletes exactly those ids, committing after each batch, until
        either a batch comes back empty or `max_total` rows have been
        deleted overall. Never issues one unbounded DELETE — see
        module docstring's "Batching and VACUUM" section for why.

        max_total is a separate concern from batch_size: batch_size
        bounds each individual DELETE's size (the concurrency/locking
        concern), max_total bounds the CUMULATIVE deletion across all
        batches (e.g. the training-sample cap needs to stop after
        exactly `overflow` rows, not keep paging until the query runs
        dry). Tiers 1/2 don't pass max_total since "everything matching
        the age cutoff" IS the intended total there.
        """
        total = 0
        while True:
            remaining = None if max_total is None else max_total - total
            if remaining is not None and remaining <= 0:
                break
            limit = self.batch_size if remaining is None else min(self.batch_size, remaining)

            cursor = conn.execute(select_ids_sql, [*select_ids_params, limit])
            ids = [row[0] for row in cursor.fetchall()]
            if not ids:
                break

            id_placeholders = ", ".join("?" for _ in ids)
            conn.execute(f"DELETE FROM {table} WHERE id IN ({id_placeholders})", ids)
            conn.commit()
            total += len(ids)

            if len(ids) < limit:
                # Short batch means we've exhausted every matching
                # row - no point issuing one more SELECT that would
                # just come back empty.
                break

        return total

    # ------------------------------------------------------------
    # VACUUM gating
    # ------------------------------------------------------------

    def _vacuum_if_due(self, now: float) -> bool:
        conn = self._connect()
        try:
            last_vacuum = self._get_meta(conn, "last_vacuum_ts")
            last_vacuum = float(last_vacuum) if last_vacuum is not None else 0.0

            if (now - last_vacuum) < (self.vacuum_interval_hours * 3600):
                return False

            # VACUUM cannot run inside an open transaction - the
            # preceding delete batches each commit as they go (see
            # _batched_delete), so by the time we get here there is
            # no pending transaction to conflict with this.
            conn.execute("VACUUM")
            self._set_meta(conn, "last_vacuum_ts", str(now))
            conn.commit()
            return True
        finally:
            conn.close()

    # ------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _ensure_meta_table(self) -> None:
        """
        Small key/value table for retention's own bookkeeping
        (currently just last_vacuum_ts). Separate from labelled_flows
        and evidence on purpose - this is metadata ABOUT the database,
        not detection data - mirrors labeller.py's own
        "different consumers, don't conflate schemas" reasoning for
        why evidence and labelled_flows are two tables instead of one.
        """
        conn = self._connect()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS _retention_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def _get_meta(self, conn: sqlite3.Connection, key: str) -> str | None:
        cursor = conn.execute("SELECT value FROM _retention_meta WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row[0] if row else None

    def _set_meta(self, conn: sqlite3.Connection, key: str, value: str) -> None:
        conn.execute(
            "INSERT INTO _retention_meta (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )