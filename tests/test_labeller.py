"""
tests/test_labeller_evidence.py

Coverage for pipeline/labeller.py's Evidence wiring: store_evidence()
writing to both the evidence DB table and the shared EvidenceBuffer in
one call, and process()'s from_llm() construction at the LLM call site
(including the timestamp fallback and identity passthrough from the
flow's own features dict).
"""

import json
import sqlite3
import pytest

from pipeline.labeller import Labeller
from detection.anomaly import DetectionResult, Verdict
from detection.evidence import EvidenceBuffer, EvidenceVerdict
from detection.llm_analyser import AnalysisResult, AnalysisConfidence


class FakeLLM:
    """Minimal stand-in for LLMAnalyser — no real API calls, no rate limiting."""

    def __init__(self, result: AnalysisResult):
        self._result = result

    def should_analyse(self, score):
        return True

    def analyse(self, features, anomaly_score, verdict):
        return self._result


@pytest.fixture
def labeller(tmp_path):
    config = {"storage": {"db_path": str(tmp_path / "test.db")}}
    buffer = EvidenceBuffer(window_seconds=300.0)
    llm = FakeLLM(AnalysisResult(
        available=True, attack_type="port_scan",
        confidence=AnalysisConfidence.HIGH, reasoning="matches scan pattern",
    ))
    return Labeller(config, llm_analyser=llm, evidence_buffer=buffer)


def _fetch_evidence_rows(labeller):
    conn = sqlite3.connect(labeller.db_path)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM evidence").fetchall()]
    finally:
        conn.close()


class TestCorrelationEngineWiring:
    def test_store_evidence_feeds_the_shared_correlation_engine(self, tmp_path):
        from detection.correlation_engine import CorrelationEngine
        from detection.evidence import from_port_scan, from_brute_force
        from detection.port_scan_tracker import PortScanCheckResult, PortScanVerdict
        from detection.brute_force_tracker import BruteForceResult, BruteForceVerdict

        config = {"storage": {"db_path": str(tmp_path / "test.db")}}
        engine = CorrelationEngine()
        labeller = Labeller(config, llm_analyser=None, correlation_engine=engine)

        # Mirrors how main.py's per-flow loop calls store_evidence()
        # directly for the four tracker-based detectors.
        labeller.store_evidence(
            from_port_scan(PortScanCheckResult(PortScanVerdict.ATTACK, "10.0.0.66", 10.0, 25, 10), timestamp=100.0)
        )
        labeller.store_evidence(
            from_brute_force(
                BruteForceResult(BruteForceVerdict.ATTACK, "10.0.0.66", "10.0.0.99", 22, 20, 60.0, 1),
                timestamp=150.0,
            )
        )

        # The engine passed into Labeller's constructor - not a
        # separate internal one - must be the one that saw both.
        incident = engine.get_incident("10.0.0.66")
        assert incident is not None
        assert incident.detectors_involved == {"port_scan", "brute_force"}

    def test_labeller_creates_its_own_engine_when_none_passed(self, tmp_path):
        # Mirrors the same "never has to check for None" contract as
        # evidence_buffer - a Labeller constructed without a shared
        # engine (e.g. read-only callers) still works standalone.
        config = {"storage": {"db_path": str(tmp_path / "test.db")}}
        labeller = Labeller(config, llm_analyser=None)
        assert labeller.correlation_engine is not None


class TestStoreEvidence:
    def test_writes_to_both_db_and_buffer(self, labeller):
        result = DetectionResult(
            Verdict.SUSPICIOUS, -0.7,
            {"src_ip": "1.2.3.4", "dst_ip": "5.6.7.8", "dst_port": 22},
        )
        labeller.process(result, timestamp=100.0)

        db_rows = _fetch_evidence_rows(labeller)
        buffered = labeller.evidence_buffer.recent(current_timestamp=100.0)

        assert len(db_rows) == 1
        assert len(buffered) == 1
        assert db_rows[0]["detector"] == "llm"
        assert db_rows[0]["src_ip"] == "1.2.3.4"

    def test_payload_json_round_trips_with_enum_converted_to_value(self, labeller):
        result = DetectionResult(Verdict.ATTACK, -0.9, {"src_ip": "9.9.9.9"})
        labeller.process(result, timestamp=200.0)

        row = _fetch_evidence_rows(labeller)[0]
        payload = json.loads(row["payload"])
        # AnalysisConfidence.HIGH must serialise to the plain string
        # "high", not something like "AnalysisConfidence.HIGH".
        assert payload["confidence"] == "high"
        assert payload["attack_type"] == "port_scan"

    def test_evidence_table_and_labelled_flows_both_populated(self, labeller):
        # Both tables should get a row from one process() call - they
        # serve different consumers (classifier training data vs.
        # correlation engine input) and neither should be skipped.
        result = DetectionResult(Verdict.SUSPICIOUS, -0.7, {"src_ip": "1.1.1.1"})
        sample = labeller.process(result, timestamp=1.0)

        assert sample is not None  # labelled_flows got a row
        assert len(_fetch_evidence_rows(labeller)) == 1  # evidence got a row too


class TestProcessSuspicionPromotionStillWorks:
    def test_llm_confirmed_attack_promotes_suspicious_to_attack(self, labeller):
        # Sanity check that wiring Evidence construction into process()
        # didn't disturb the existing promotion logic.
        result = DetectionResult(Verdict.SUSPICIOUS, -0.7, {"src_ip": "1.1.1.1"})
        sample = labeller.process(result, timestamp=1.0)
        assert sample.verdict == "ATTACK"


class TestProcessTimestampFallback:
    def test_missing_timestamp_still_stores_without_raising(self, labeller):
        # timestamp defaults to None -> falls back to time.time() inside
        # process() rather than raising or storing a garbage value.
        result = DetectionResult(Verdict.SUSPICIOUS, -0.7, {"src_ip": "1.1.1.1"})
        sample = labeller.process(result)  # no timestamp passed
        assert sample is not None

        row = _fetch_evidence_rows(labeller)[0]
        assert isinstance(row["timestamp"], float)
        assert row["timestamp"] > 0