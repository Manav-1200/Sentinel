"""
tests/test_risk_engine.py

Coverage for detection/risk_engine.py's fusion math: per-detector
worst-verdict-only aggregation (no inflation from repeated polling),
trust-weighted severity, the corroboration bonus, and the score->tier
mapping.
"""

import pytest

from detection.risk_engine import assess, RiskTier
from detection.correlation_engine import CorrelationEngine
from detection.evidence import from_anomaly, from_ddos, from_port_scan, from_brute_force, from_llm
from detection.anomaly import DetectionResult, Verdict
from detection.ddos_tracker import DDoSCheckResult, DDoSVerdict
from detection.port_scan_tracker import PortScanCheckResult, PortScanVerdict
from detection.brute_force_tracker import BruteForceResult, BruteForceVerdict
from detection.llm_analyser import AnalysisResult, AnalysisConfidence


@pytest.fixture
def engine():
    return CorrelationEngine()


class TestSingleDetectorAlone:
    def test_weak_statistical_detector_alone_scores_low(self, engine):
        # anomaly is the lowest-trust detector - one SUSPICIOUS finding
        # alone must not read as alarming.
        incident = engine.add_evidence(
            from_anomaly(DetectionResult(Verdict.SUSPICIOUS, -0.3, {"src_ip": "1.1.1.1"}), timestamp=1.0)
        )
        result = assess(incident)
        assert result.tier == RiskTier.LOW
        assert result.contributing_detectors == ["anomaly"]

    def test_deterministic_detector_alone_scores_higher_than_anomaly_alone(self, engine):
        # port_scan is trusted at full weight (1.0) vs anomaly's 0.5 -
        # an ATTACK verdict from it alone should outscore anomaly alone.
        incident = engine.add_evidence(
            from_port_scan(PortScanCheckResult(PortScanVerdict.ATTACK, "9.9.9.9", 10.0, 25, 10), timestamp=1.0)
        )
        result = assess(incident)
        anomaly_incident = engine.add_evidence(
            from_anomaly(DetectionResult(Verdict.ATTACK, -0.9, {"src_ip": "8.8.8.8"}), timestamp=1.0)
        )
        anomaly_result = assess(anomaly_incident)
        assert result.score > anomaly_result.score


class TestCorroborationAcrossDetectors:
    def test_two_detectors_score_higher_than_either_alone(self, engine):
        incident = engine.add_evidence(
            from_anomaly(DetectionResult(Verdict.SUSPICIOUS, -0.3, {"src_ip": "1.1.1.1"}), timestamp=1.0)
        )
        solo_score = assess(incident).score

        incident = engine.add_evidence(
            from_brute_force(
                BruteForceResult(BruteForceVerdict.ATTACK, "1.1.1.1", "2.2.2.2", 22, 20, 60.0, 1),
                timestamp=2.0,
            )
        )
        corroborated = assess(incident)
        assert corroborated.score > solo_score
        assert set(corroborated.contributing_detectors) == {"anomaly", "brute_force"}

    def test_three_way_corroboration_including_llm_reaches_critical(self, engine):
        incident = engine.add_evidence(
            from_anomaly(DetectionResult(Verdict.SUSPICIOUS, -0.3, {"src_ip": "1.1.1.1"}), timestamp=1.0)
        )
        incident = engine.add_evidence(
            from_brute_force(
                BruteForceResult(BruteForceVerdict.ATTACK, "1.1.1.1", "2.2.2.2", 22, 20, 60.0, 1),
                timestamp=2.0,
            )
        )
        incident = engine.add_evidence(
            from_llm(
                AnalysisResult(available=True, attack_type="brute_force", confidence=AnalysisConfidence.HIGH),
                timestamp=3.0, src_ip="1.1.1.1",
            )
        )
        result = assess(incident)
        assert result.tier == RiskTier.CRITICAL


class TestNoInflationFromRepeatedPolling:
    def test_repeated_attack_verdicts_from_same_detector_do_not_stack(self, engine):
        # A tracker re-confirming ATTACK on every check() call must not
        # let the score keep climbing just because it was polled more.
        incident = None
        for t in range(1, 6):
            incident = engine.add_evidence(
                from_brute_force(
                    BruteForceResult(BruteForceVerdict.ATTACK, "5.5.5.5", "6.6.6.6", 22, 20, 60.0, 1),
                    timestamp=float(t),
                )
            )
        repeated_score = assess(incident).score

        fresh_engine = CorrelationEngine()
        single_incident = fresh_engine.add_evidence(
            from_brute_force(
                BruteForceResult(BruteForceVerdict.ATTACK, "9.9.9.9", "8.8.8.8", 22, 20, 60.0, 1),
                timestamp=1.0,
            )
        )
        single_score = assess(single_incident).score

        assert repeated_score == single_score

    def test_worst_verdict_per_detector_is_used_not_first_or_last(self, engine):
        # SUSPICIOUS then ATTACK from the same detector should score as
        # if only the ATTACK happened - not an average, not the first.
        incident = engine.add_evidence(
            from_port_scan(PortScanCheckResult(PortScanVerdict.SUSPICIOUS, "1.1.1.1", 10.0, 9, 4), timestamp=1.0)
        )
        incident = engine.add_evidence(
            from_port_scan(PortScanCheckResult(PortScanVerdict.ATTACK, "1.1.1.1", 10.0, 25, 10), timestamp=2.0)
        )
        mixed_score = assess(incident).score

        fresh_engine = CorrelationEngine()
        attack_only_incident = fresh_engine.add_evidence(
            from_port_scan(PortScanCheckResult(PortScanVerdict.ATTACK, "9.9.9.9", 10.0, 25, 10), timestamp=1.0)
        )
        attack_only_score = assess(attack_only_incident).score

        assert mixed_score == attack_only_score


class TestUnavailableContributesNothing:
    def test_unavailable_does_not_add_score_or_count_as_corroboration(self, engine):
        incident = engine.add_evidence(
            from_brute_force(
                BruteForceResult(BruteForceVerdict.ATTACK, "1.1.1.1", "2.2.2.2", 22, 20, 60.0, 1),
                timestamp=1.0,
            )
        )
        baseline_score = assess(incident).score

        incident = engine.add_evidence(
            from_llm(AnalysisResult(available=False, error="timeout"), timestamp=2.0, src_ip="1.1.1.1")
        )
        after_unavailable = assess(incident)

        assert after_unavailable.score == baseline_score
        assert "llm" not in after_unavailable.contributing_detectors


class TestAggregateDDoSIncident:
    def test_ddos_only_incident_scores_reasonably(self, engine):
        incident = engine.add_evidence(from_ddos(DDoSCheckResult(DDoSVerdict.ATTACK, 10.0, 600, 30), timestamp=1.0))
        result = assess(incident)
        assert result.score == 30  # 30 points * 1.0 weight, no corroboration bonus
        assert result.tier == RiskTier.MEDIUM


class TestTierBoundaries:
    @pytest.mark.parametrize("score, expected_tier", [
        (0, RiskTier.LOW),
        (24, RiskTier.LOW),
        (25, RiskTier.MEDIUM),
        (49, RiskTier.MEDIUM),
        (50, RiskTier.HIGH),
        (79, RiskTier.HIGH),
        (80, RiskTier.CRITICAL),
        (100, RiskTier.CRITICAL),
    ])
    def test_score_maps_to_expected_tier(self, score, expected_tier):
        from detection.risk_engine import _tier_for_score
        assert _tier_for_score(score) == expected_tier


class TestEmptyIncidentIsDefensive:
    def test_incident_with_no_evidence_scores_zero_low(self):
        from detection.correlation_engine import Incident, IncidentStatus
        from detection.evidence import EvidenceVerdict
        empty_incident = Incident(
            incident_id="test", key="1.1.1.1", status=IncidentStatus.OPEN,
            first_seen=1.0, last_seen=1.0, highest_verdict=EvidenceVerdict.SUSPICIOUS,
        )
        result = assess(empty_incident)
        assert result.score == 0
        assert result.tier == RiskTier.LOW