"""
tests/test_labeller.py
=========================
Unit tests for pipeline/labeller.py. Uses a fake LLM analyser (no
real network calls) to test the full labelling/storage logic in
isolation.
"""

import pytest

from pipeline.labeller import Labeller
from detection.anomaly import DetectionResult, Verdict
from detection.llm_analyser import AnalysisResult, AnalysisConfidence


class FakeAnalyser:
    """
    A minimal stand-in for LLMAnalyser that returns a fixed result
    without making any real network calls — exactly the shape
    Labeller expects (should_analyse() and analyse() methods).
    """

    def __init__(self, fixed_result: AnalysisResult, should_analyse_value: bool = True):
        self.fixed_result = fixed_result
        self._should_analyse_value = should_analyse_value
        self.analyse_call_count = 0

    def should_analyse(self, score: float) -> bool:
        return self._should_analyse_value

    def analyse(self, features, anomaly_score, verdict):
        self.analyse_call_count += 1
        return self.fixed_result


ATTACK_FEATURES = {
    "src_ip": "10.0.0.99", "dst_ip": "192.168.1.50",
    "src_port": 40000, "dst_port": 22, "protocol": 6,
    "total_packets": 50, "packets_per_second": 2500.0,
    "syn_ratio": 1.0, "zero_payload_ratio": 1.0,
}


@pytest.fixture
def db_config(tmp_path):
    return {"storage": {"db_path": str(tmp_path / "test_labels.db")}}


class TestNonStorableVerdicts:
    """NORMAL and WARMING_UP flows are never labelled or stored — only SUSPICIOUS/ATTACK."""

    def test_normal_verdict_not_stored(self, db_config):
        labeller = Labeller(db_config, llm_analyser=None)
        result = DetectionResult(Verdict.NORMAL, 0.1, ATTACK_FEATURES)
        assert labeller.process(result) is None

    def test_warming_up_not_stored(self, db_config):
        labeller = Labeller(db_config, llm_analyser=None)
        result = DetectionResult(Verdict.WARMING_UP, None, ATTACK_FEATURES)
        assert labeller.process(result) is None


class TestLabellingWithoutLLM:

    def test_attack_with_no_llm_analyser_stores_unknown_auto(self, db_config):
        labeller = Labeller(db_config, llm_analyser=None)
        result = DetectionResult(Verdict.ATTACK, -0.15, ATTACK_FEATURES)
        stored = labeller.process(result)

        assert stored is not None
        assert stored.label == "unknown"
        assert stored.label_source == "auto"

    def test_should_analyse_false_skips_llm_for_suspicious(self, db_config):
        """
        should_analyse() only gates LLM calls for SUSPICIOUS verdicts.
        ATTACK verdicts (e.g. the flood-rate guard) always get sent
        to the LLM regardless of should_analyse() — see
        Labeller.process()'s docstring: "Anomaly score below
        llm.min_score_for_analysis, OR the detector already said
        ATTACK (flood-guard) -> ask the LLM." This test previously
        used Verdict.ATTACK, which meant it was actually exercising
        the "always analyse on ATTACK" branch and asserting the
        opposite of what really happens — it passed for the wrong
        reason until the OR-based gating was correctly implemented.
        Using SUSPICIOUS here is what actually exercises
        should_analyse() as a real gate.
        """
        good_analysis = AnalysisResult(
            available=True, attack_type="port_scan",
            confidence=AnalysisConfidence.HIGH, reasoning="test",
        )
        fake = FakeAnalyser(good_analysis, should_analyse_value=False)
        labeller = Labeller(db_config, llm_analyser=fake)

        result = DetectionResult(Verdict.SUSPICIOUS, -0.01, ATTACK_FEATURES)
        stored = labeller.process(result)

        assert fake.analyse_call_count == 0  # LLM correctly skipped for SUSPICIOUS + should_analyse=False
        assert stored.label == "unknown"
        assert stored.label_source == "auto"

    def test_attack_verdict_always_analysed_even_if_should_analyse_false(self, db_config):
        """
        Complementary case to the test above: an ATTACK verdict
        (e.g. flood-rate guard) must ALWAYS be sent to the LLM,
        regardless of what should_analyse() says — this is the OR
        branch in Labeller.process(). Flood-guard-triggered ATTACKs
        are rarer and deterministic-rule-based, so they're always
        worth a real LLM judgment rather than being silently
        auto-labelled "unknown".
        """
        good_analysis = AnalysisResult(
            available=True, attack_type="syn_flood",
            confidence=AnalysisConfidence.HIGH, reasoning="test",
        )
        fake = FakeAnalyser(good_analysis, should_analyse_value=False)
        labeller = Labeller(db_config, llm_analyser=fake)

        result = DetectionResult(Verdict.ATTACK, -0.01, ATTACK_FEATURES)
        stored = labeller.process(result)

        assert fake.analyse_call_count == 1  # LLM WAS called despite should_analyse=False
        assert stored.label == "syn_flood"
        assert stored.label_source == "llm"


class TestLabellingWithLLM:

    def test_successful_llm_analysis_stores_real_label(self, db_config):
        good_analysis = AnalysisResult(
            available=True, attack_type="port_scan",
            confidence=AnalysisConfidence.HIGH, reasoning="High SYN ratio with no replies.",
        )
        fake = FakeAnalyser(good_analysis)
        labeller = Labeller(db_config, llm_analyser=fake)

        result = DetectionResult(Verdict.ATTACK, -0.15, ATTACK_FEATURES)
        stored = labeller.process(result)

        assert fake.analyse_call_count == 1
        assert stored.label == "port_scan"
        assert stored.label_source == "llm"
        assert stored.confidence == "high"
        assert stored.reasoning == "High SYN ratio with no replies."

    def test_failed_llm_analysis_still_stores_a_sample(self, db_config):
        """
        Critical design property: an LLM failure (timeout, rate limit,
        network error) must NEVER silently drop a sample. It gets
        stored as label="unknown", source="llm_failed" — fully
        auditable, not lost.
        """
        failed_analysis = AnalysisResult(available=False, error="Request timed out")
        fake = FakeAnalyser(failed_analysis)
        labeller = Labeller(db_config, llm_analyser=fake)

        result = DetectionResult(Verdict.ATTACK, -0.15, ATTACK_FEATURES)
        stored = labeller.process(result)

        assert stored is not None
        assert stored.label == "unknown"
        assert stored.label_source == "llm_failed"
        assert stored.reasoning == "Request timed out"


class TestQueryHelpers:

    def test_count_by_label_aggregates_correctly(self, db_config):
        port_scan_analysis = AnalysisResult(
            available=True, attack_type="port_scan",
            confidence=AnalysisConfidence.HIGH, reasoning="test",
        )
        labeller = Labeller(db_config, llm_analyser=FakeAnalyser(port_scan_analysis))

        for _ in range(3):
            labeller.process(DetectionResult(Verdict.ATTACK, -0.15, ATTACK_FEATURES))

        counts = labeller.count_by_label()
        assert counts == {"port_scan": 3}

    def test_fetch_all_returns_correctly_deserialised_samples(self, db_config):
        analysis = AnalysisResult(
            available=True, attack_type="ddos",
            confidence=AnalysisConfidence.MEDIUM, reasoning="test reasoning",
        )
        labeller = Labeller(db_config, llm_analyser=FakeAnalyser(analysis))
        labeller.process(DetectionResult(Verdict.ATTACK, -0.2, ATTACK_FEATURES))

        samples = labeller.fetch_all()
        assert len(samples) == 1
        sample = samples[0]
        assert sample.label == "ddos"
        assert isinstance(sample.features, dict)
        assert sample.features["src_ip"] == "10.0.0.99"

    def test_fetch_all_filters_by_confidence(self, db_config):
        high_conf = AnalysisResult(available=True, attack_type="port_scan",
                                     confidence=AnalysisConfidence.HIGH, reasoning="test")
        low_conf = AnalysisResult(available=True, attack_type="port_scan",
                                    confidence=AnalysisConfidence.LOW, reasoning="test")

        labeller_high = Labeller(db_config, llm_analyser=FakeAnalyser(high_conf))
        labeller_high.process(DetectionResult(Verdict.ATTACK, -0.15, ATTACK_FEATURES))

        labeller_low = Labeller(db_config, llm_analyser=FakeAnalyser(low_conf))
        labeller_low.process(DetectionResult(Verdict.ATTACK, -0.15, ATTACK_FEATURES))

        # Both labellers point at the SAME db_config (same db_path),
        # so this verifies the database aggregates across multiple
        # Labeller instances correctly too.
        high_only = labeller_high.fetch_all(min_confidence="high")
        assert len(high_only) == 1
        assert high_only[0].confidence == "high"

    def test_schema_is_idempotent_across_multiple_instances(self, db_config):
        """Constructing multiple Labeller instances against the same
        db_path must not fail or duplicate the schema."""
        labeller1 = Labeller(db_config, llm_analyser=None)
        labeller2 = Labeller(db_config, llm_analyser=None)  # Should not raise

        labeller1.process(DetectionResult(Verdict.ATTACK, -0.15, ATTACK_FEATURES))
        counts = labeller2.count_by_label()
        assert sum(counts.values()) == 1