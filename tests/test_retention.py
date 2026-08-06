"""
tests/test_retention.py

Unit tests for pipeline/retention.py's RetentionManager. Uses the
REAL Labeller._ensure_schema() to create the DB (via constructing a
throwaway Labeller with llm_analyser=None) rather than hand-rolled
CREATE TABLE statements, so these tests stay honest against schema
drift instead of silently testing against a stale copy of the schema.

Covers the three tiers from db_retention_policy.md/retention.py's
module docstring: bulk NORMAL/WARMING_UP evidence, resolved-incident
finding evidence (and the open-incident protection), and the
training-sample per-label size cap — plus the batching/max_total
behaviour that had a real bug during development (see that fix's
comment in retention.py: an early version deleted every row for an
over-cap label instead of stopping at the overflow amount).
"""

import sqlite3
import time

import pytest

from pipeline.labeller import Labeller
from pipeline.retention import RetentionManager
from detection.correlation_engine import CorrelationEngine, AGGREGATE_KEY
from detection.evidence import from_port_scan
from detection.port_scan_tracker import PortScanCheckResult, PortScanVerdict


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "retention_test.db")
    # Build the real schema via the real code path, not a hand copy.
    Labeller({"storage": {"db_path": path}}, llm_analyser=None)
    return path


def _insert_evidence(db_path, *, evidence_id, verdict, timestamp, src_ip):
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        INSERT INTO evidence
            (evidence_id, detector, timestamp, verdict, reasoning, src_ip, dst_ip, dst_port, payload)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (evidence_id, "anomaly", timestamp, verdict, "test reasoning", src_ip, "10.0.0.1", 80, "{}"),
    )
    conn.commit()
    conn.close()


def _insert_training_sample(db_path, *, label, timestamp):
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        INSERT INTO labelled_flows
            (timestamp, label, label_source, confidence, anomaly_score, verdict, reasoning, all_features)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (str(timestamp), label, "llm", "high", -0.1, "ATTACK", "r", "{}"),
    )
    conn.commit()
    conn.close()


def _count(db_path, sql, params=()):
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute(sql, params).fetchone()[0]
    finally:
        conn.close()


@pytest.fixture
def engine():
    return CorrelationEngine()


@pytest.fixture
def config(db_path):
    return {
        "storage": {"db_path": db_path},
        "retention": {
            "normal_evidence_days": 7,
            "resolved_incident_evidence_days": 90,
            "max_training_samples_per_class": 500,
            "batch_size": 50,
            "vacuum_interval_hours": 24,
        },
    }


class TestBulkEvidenceTier:

    def test_old_normal_evidence_is_deleted(self, db_path, config, engine):
        now = time.time()
        _insert_evidence(db_path, evidence_id="e1", verdict="NORMAL", timestamp=now - 10 * 86400, src_ip="10.0.0.5")

        stats = RetentionManager(config, engine).run_pass(now=now)

        assert stats.bulk_evidence_deleted == 1
        assert _count(db_path, "SELECT COUNT(*) FROM evidence") == 0

    def test_recent_normal_evidence_survives(self, db_path, config, engine):
        now = time.time()
        _insert_evidence(db_path, evidence_id="e1", verdict="NORMAL", timestamp=now - 60, src_ip="10.0.0.5")

        stats = RetentionManager(config, engine).run_pass(now=now)

        assert stats.bulk_evidence_deleted == 0
        assert _count(db_path, "SELECT COUNT(*) FROM evidence") == 1

    def test_warming_up_verdict_is_also_bulk_tier(self, db_path, config, engine):
        now = time.time()
        _insert_evidence(db_path, evidence_id="e1", verdict="WARMING_UP", timestamp=now - 10 * 86400, src_ip="10.0.0.5")

        stats = RetentionManager(config, engine).run_pass(now=now)

        assert stats.bulk_evidence_deleted == 1


class TestFindingEvidenceTier:

    def test_old_finding_with_no_open_incident_is_deleted(self, db_path, config, engine):
        now = time.time()
        _insert_evidence(db_path, evidence_id="a1", verdict="ATTACK", timestamp=now - 200 * 86400, src_ip="1.2.3.4")

        stats = RetentionManager(config, engine).run_pass(now=now)

        assert stats.finding_evidence_deleted == 1

    def test_old_finding_protected_by_open_incident_survives(self, db_path, config, engine):
        now = time.time()
        _insert_evidence(db_path, evidence_id="a1", verdict="ATTACK", timestamp=now - 200 * 86400, src_ip="1.2.3.4")

        fake = PortScanCheckResult(PortScanVerdict.ATTACK, "1.2.3.4", 10.0, 25, 1)
        engine.add_evidence(from_port_scan(fake, now))

        stats = RetentionManager(config, engine).run_pass(now=now)

        assert stats.finding_evidence_deleted == 0
        assert _count(db_path, "SELECT COUNT(*) FROM evidence") == 1

    def test_evidence_becomes_eligible_after_incident_is_resolved(self, db_path, config, engine):
        now = time.time()
        _insert_evidence(db_path, evidence_id="a1", verdict="ATTACK", timestamp=now - 200 * 86400, src_ip="1.2.3.4")

        fake = PortScanCheckResult(PortScanVerdict.ATTACK, "1.2.3.4", 10.0, 25, 1)
        engine.add_evidence(from_port_scan(fake, now))

        manager = RetentionManager(config, engine)
        stats_open = manager.run_pass(now=now)
        assert stats_open.finding_evidence_deleted == 0

        engine.resolve("1.2.3.4")
        stats_resolved = manager.run_pass(now=now + 1)
        assert stats_resolved.finding_evidence_deleted == 1

    def test_recent_finding_survives_regardless_of_incident_status(self, db_path, config, engine):
        now = time.time()
        _insert_evidence(db_path, evidence_id="a1", verdict="ATTACK", timestamp=now - 60, src_ip="1.2.3.4")

        stats = RetentionManager(config, engine).run_pass(now=now)

        assert stats.finding_evidence_deleted == 0

    def test_aggregate_ddos_evidence_protected_while_aggregate_incident_open(self, db_path, config, engine):
        """
        ddos_tracker findings have no src_ip at all (see
        correlation_engine.py's AGGREGATE_KEY) - stored with
        src_ip=NULL. These must be protected the same way a normal
        per-source incident's evidence is, keyed on AGGREGATE_KEY
        instead of a real IP.
        """
        now = time.time()
        conn = sqlite3.connect(db_path)
        conn.execute(
            """
            INSERT INTO evidence
                (evidence_id, detector, timestamp, verdict, reasoning, src_ip, dst_ip, dst_port, payload)
            VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?)
            """,
            ("ddos1", "ddos", now - 200 * 86400, "ATTACK", "r", "10.0.0.1", 80, "{}"),
        )
        conn.commit()
        conn.close()

        from detection.ddos_tracker import DDoSCheckResult, DDoSVerdict
        from detection.evidence import from_ddos

        ddos_result = DDoSCheckResult(
            verdict=DDoSVerdict.ATTACK, window_seconds=10.0,
            total_flows_in_window=600, distinct_sources_in_window=25,
        )
        engine.add_evidence(from_ddos(ddos_result, now))
        assert engine.get_incident(AGGREGATE_KEY) is not None

        stats = RetentionManager(config, engine).run_pass(now=now)

        assert stats.finding_evidence_deleted == 0


class TestTrainingSampleCap:

    def test_label_under_cap_is_untouched(self, db_path, config, engine):
        now = time.time()
        for i in range(10):
            _insert_training_sample(db_path, label="brute_force", timestamp=now - i)

        stats = RetentionManager(config, engine).run_pass(now=now)

        assert stats.training_samples_deleted == 0
        assert _count(db_path, "SELECT COUNT(*) FROM labelled_flows WHERE label='brute_force'") == 10

    def test_label_over_cap_evicts_only_the_overflow(self, db_path, config, engine):
        now = time.time()
        for i in range(600):
            _insert_training_sample(db_path, label="ddos", timestamp=now - i)

        stats = RetentionManager(config, engine).run_pass(now=now)

        # Cap is 500 (see config fixture) - exactly 100 should be
        # evicted, not all 600 (this was a real bug during
        # development - see retention.py's max_total comment).
        assert stats.training_samples_deleted == 100
        assert _count(db_path, "SELECT COUNT(*) FROM labelled_flows WHERE label='ddos'") == 500

    def test_eviction_removes_oldest_rows_first(self, db_path, config, engine):
        now = time.time()
        # Zero-padded so lexicographic ORDER BY (the timestamp column
        # is TEXT, matching production's ISO-8601 strings, which sort
        # correctly lexicographically because they're fixed-width)
        # matches numeric/chronological order for this test too.
        for i in range(600):
            _insert_training_sample(db_path, label="ddos", timestamp=f"{i:04d}")

        RetentionManager(config, engine).run_pass(now=now)

        conn = sqlite3.connect(db_path)
        remaining_timestamps = {
            row[0] for row in conn.execute("SELECT timestamp FROM labelled_flows WHERE label='ddos'")
        }
        conn.close()

        # The 100 oldest ("0000".."0099") should be gone; the 500
        # newest should remain.
        assert "0000" not in remaining_timestamps
        assert "0099" not in remaining_timestamps
        assert "0599" in remaining_timestamps

    def test_different_labels_capped_independently(self, db_path, config, engine):
        now = time.time()
        for i in range(600):
            _insert_training_sample(db_path, label="ddos", timestamp=now - i)
        for i in range(10):
            _insert_training_sample(db_path, label="brute_force", timestamp=now - i)

        RetentionManager(config, engine).run_pass(now=now)

        assert _count(db_path, "SELECT COUNT(*) FROM labelled_flows WHERE label='ddos'") == 500
        assert _count(db_path, "SELECT COUNT(*) FROM labelled_flows WHERE label='brute_force'") == 10


class TestMaybeRun:

    def test_does_nothing_before_the_interval_is_reached(self, db_path, config, engine):
        now = time.time()
        _insert_evidence(db_path, evidence_id="e1", verdict="NORMAL", timestamp=now - 10 * 86400, src_ip="10.0.0.5")

        manager = RetentionManager({**config, "retention": {**config["retention"], "run_every_n_flows": 5000}}, engine)
        result = manager.maybe_run(flows_processed=4999)

        assert result is None
        assert _count(db_path, "SELECT COUNT(*) FROM evidence") == 1

    def test_runs_exactly_on_the_interval(self, db_path, config, engine):
        now = time.time()
        _insert_evidence(db_path, evidence_id="e1", verdict="NORMAL", timestamp=now - 10 * 86400, src_ip="10.0.0.5")

        manager = RetentionManager({**config, "retention": {**config["retention"], "run_every_n_flows": 5000}}, engine)
        result = manager.maybe_run(flows_processed=5000)

        assert result is not None
        assert result.bulk_evidence_deleted == 1

    def test_disabled_via_config_never_runs(self, db_path, config, engine):
        manager = RetentionManager(
            {**config, "retention": {**config["retention"], "enabled": False, "run_every_n_flows": 1}}, engine
        )
        result = manager.maybe_run(flows_processed=1)

        assert result is None


class TestVacuum:

    def test_vacuum_runs_on_first_pass(self, db_path, config, engine):
        stats = RetentionManager(config, engine).run_pass(now=time.time())
        assert stats.vacuum_ran is True

    def test_vacuum_does_not_rerun_within_the_interval(self, db_path, config, engine):
        manager = RetentionManager(config, engine)
        now = time.time()
        first = manager.run_pass(now=now)
        second = manager.run_pass(now=now + 60)  # 1 minute later, interval is 24h

        assert first.vacuum_ran is True
        assert second.vacuum_ran is False

    def test_vacuum_reruns_after_interval_elapses(self, db_path, config, engine):
        manager = RetentionManager(
            {**config, "retention": {**config["retention"], "vacuum_interval_hours": 0.001}}, engine
        )
        now = time.time()
        first = manager.run_pass(now=now)
        second = manager.run_pass(now=now + 10)  # well past a 0.001h (3.6s) interval

        assert first.vacuum_ran is True
        assert second.vacuum_ran is True


class TestIdempotency:

    def test_second_pass_with_nothing_new_deletes_nothing(self, db_path, config, engine):
        now = time.time()
        _insert_evidence(db_path, evidence_id="e1", verdict="NORMAL", timestamp=now - 10 * 86400, src_ip="10.0.0.5")

        manager = RetentionManager(config, engine)
        manager.run_pass(now=now)
        second = manager.run_pass(now=now + 1)

        assert second.bulk_evidence_deleted == 0
        assert second.finding_evidence_deleted == 0
        assert second.training_samples_deleted == 0
