"""
tests/test_correlation_engine.py

Coverage for detection/correlation_engine.py: grouping by src_ip
(including the multi-detector merge that's the entire point of this
engine), the aggregate-DDoS special case, the never-auto-closes
contract, and the opening-verdict vs. attaching-verdict distinction.
"""

import pytest

from detection.correlation_engine import CorrelationEngine, IncidentStatus, _AGGREGATE_KEY
from detection.evidence import from_anomaly, from_ddos, from_port_scan, from_brute_force, from_llm
from detection.anomaly import DetectionResult, Verdict
from detection.ddos_tracker import DDoSCheckResult, DDoSVerdict
from detection.port_scan_tracker import PortScanCheckResult, PortScanVerdict
from detection.brute_force_tracker import BruteForceResult, BruteForceVerdict
from detection.llm_analyser import AnalysisResult, AnalysisConfidence


@pytest.fixture
def engine():
    return CorrelationEngine()


class TestGroupingBySourceIP:
    def test_two_detectors_same_source_merge_into_one_incident(self, engine):
        # This is the entire point of the engine - a multi-stage attack
        # from one source must read as one story, not two.
        scan = from_port_scan(
            PortScanCheckResult(PortScanVerdict.ATTACK, "10.0.0.66", 10.0, 25, 10),
            timestamp=100.0,
        )
        bf = from_brute_force(
            BruteForceResult(BruteForceVerdict.ATTACK, "10.0.0.66", "10.0.0.99", 22, 20, 60.0, 1),
            timestamp=150.0,
        )
        inc1 = engine.add_evidence(scan)
        inc2 = engine.add_evidence(bf)

        assert inc1.incident_id == inc2.incident_id
        assert inc2.detectors_involved == {"port_scan", "brute_force"}
        assert len(inc2.evidence) == 2

    def test_different_destinations_same_source_still_merge(self, engine):
        # Grouping is src_ip ONLY - a source hitting two different
        # destinations must still merge into one incident, since the
        # dst is not part of the grouping key (see module docstring).
        bf1 = from_brute_force(
            BruteForceResult(BruteForceVerdict.ATTACK, "1.1.1.1", "2.2.2.2", 22, 20, 60.0, 1),
            timestamp=100.0,
        )
        bf2 = from_brute_force(
            BruteForceResult(BruteForceVerdict.ATTACK, "1.1.1.1", "3.3.3.3", 3389, 20, 60.0, 1),
            timestamp=200.0,
        )
        inc1 = engine.add_evidence(bf1)
        inc2 = engine.add_evidence(bf2)
        assert inc1.incident_id == inc2.incident_id

    def test_different_sources_do_not_merge(self, engine):
        bf1 = from_brute_force(
            BruteForceResult(BruteForceVerdict.ATTACK, "1.1.1.1", "2.2.2.2", 22, 20, 60.0, 1),
            timestamp=100.0,
        )
        bf2 = from_brute_force(
            BruteForceResult(BruteForceVerdict.ATTACK, "9.9.9.9", "2.2.2.2", 22, 20, 60.0, 1),
            timestamp=100.0,
        )
        inc1 = engine.add_evidence(bf1)
        inc2 = engine.add_evidence(bf2)
        assert inc1.incident_id != inc2.incident_id


class TestAggregateDDoSBucket:
    def test_ddos_evidence_goes_to_dedicated_key(self, engine):
        ddos = from_ddos(DDoSCheckResult(DDoSVerdict.ATTACK, 10.0, 600, 30), timestamp=100.0)
        incident = engine.add_evidence(ddos)
        assert incident.key == _AGGREGATE_KEY

    def test_multiple_ddos_findings_accumulate_in_same_bucket(self, engine):
        ddos1 = from_ddos(DDoSCheckResult(DDoSVerdict.ATTACK, 10.0, 600, 30), timestamp=100.0)
        ddos2 = from_ddos(DDoSCheckResult(DDoSVerdict.ATTACK, 10.0, 700, 35), timestamp=200.0)
        engine.add_evidence(ddos1)
        inc2 = engine.add_evidence(ddos2)
        assert len(inc2.evidence) == 2


class TestIgnoredVerdicts:
    def test_normal_evidence_never_creates_an_incident(self, engine):
        normal = from_anomaly(DetectionResult(Verdict.NORMAL, 0.1, {"src_ip": "1.2.3.4"}), timestamp=1.0)
        assert engine.add_evidence(normal) is None
        assert engine.get_incident("1.2.3.4") is None

    def test_warming_up_evidence_never_creates_an_incident(self, engine):
        warming = from_anomaly(DetectionResult(Verdict.WARMING_UP, None, {"src_ip": "1.2.3.4"}), timestamp=1.0)
        assert engine.add_evidence(warming) is None

    def test_normal_evidence_does_not_disturb_an_existing_open_incident(self, engine):
        bf = from_brute_force(
            BruteForceResult(BruteForceVerdict.ATTACK, "1.1.1.1", "2.2.2.2", 22, 20, 60.0, 1),
            timestamp=100.0,
        )
        engine.add_evidence(bf)
        normal = from_anomaly(DetectionResult(Verdict.NORMAL, 0.1, {"src_ip": "1.1.1.1"}), timestamp=150.0)
        assert engine.add_evidence(normal) is None
        # existing incident must still be exactly as it was
        incident = engine.get_incident("1.1.1.1")
        assert len(incident.evidence) == 1


class TestUnavailableVerdictSpecialCase:
    def test_unavailable_cannot_open_a_new_incident(self, engine):
        failed = from_llm(
            AnalysisResult(available=False, error="timeout"),
            timestamp=1.0, src_ip="5.5.5.5",
        )
        assert engine.add_evidence(failed) is None

    def test_unavailable_can_attach_to_an_already_open_incident(self, engine):
        bf = from_brute_force(
            BruteForceResult(BruteForceVerdict.ATTACK, "5.5.5.5", "6.6.6.6", 22, 20, 60.0, 1),
            timestamp=100.0,
        )
        engine.add_evidence(bf)
        failed = from_llm(
            AnalysisResult(available=False, error="timeout"),
            timestamp=150.0, src_ip="5.5.5.5",
        )
        incident = engine.add_evidence(failed)
        assert incident is not None
        assert len(incident.evidence) == 2


class TestNeverAutoCloses:
    def test_incident_stays_open_regardless_of_time_gap(self, engine):
        bf = from_brute_force(
            BruteForceResult(BruteForceVerdict.ATTACK, "1.1.1.1", "2.2.2.2", 22, 20, 60.0, 1),
            timestamp=100.0,
        )
        engine.add_evidence(bf)
        # A huge time gap - engine has no time-based eviction at all.
        later = from_brute_force(
            BruteForceResult(BruteForceVerdict.ATTACK, "1.1.1.1", "2.2.2.2", 22, 20, 60.0, 2),
            timestamp=100_000_000.0,
        )
        incident = engine.add_evidence(later)
        assert incident.status == IncidentStatus.OPEN
        assert len(incident.evidence) == 2


class TestResolveAndReopen:
    def test_resolve_marks_incident_resolved(self, engine):
        bf = from_brute_force(
            BruteForceResult(BruteForceVerdict.ATTACK, "1.1.1.1", "2.2.2.2", 22, 20, 60.0, 1),
            timestamp=100.0,
        )
        engine.add_evidence(bf)
        resolved = engine.resolve("1.1.1.1")
        assert resolved.status == IncidentStatus.RESOLVED
        assert engine.open_incidents() == []

    def test_resolve_on_nonexistent_key_returns_none_not_raise(self, engine):
        assert engine.resolve("does.not.exist") is None

    def test_new_severe_evidence_after_resolve_opens_a_fresh_incident(self, engine):
        bf1 = from_brute_force(
            BruteForceResult(BruteForceVerdict.ATTACK, "1.1.1.1", "2.2.2.2", 22, 20, 60.0, 1),
            timestamp=100.0,
        )
        first = engine.add_evidence(bf1)
        engine.resolve("1.1.1.1")

        bf2 = from_brute_force(
            BruteForceResult(BruteForceVerdict.ATTACK, "1.1.1.1", "3.3.3.3", 3389, 20, 60.0, 1),
            timestamp=500.0,
        )
        second = engine.add_evidence(bf2)
        assert second.incident_id != first.incident_id
        assert second.status == IncidentStatus.OPEN

    def test_reopen_explicitly_reopens_a_resolved_incident(self, engine):
        bf = from_brute_force(
            BruteForceResult(BruteForceVerdict.ATTACK, "1.1.1.1", "2.2.2.2", 22, 20, 60.0, 1),
            timestamp=100.0,
        )
        engine.add_evidence(bf)
        engine.resolve("1.1.1.1")
        reopened = engine.reopen("1.1.1.1")
        assert reopened.status == IncidentStatus.OPEN

    def test_reopen_on_nonexistent_key_returns_none(self, engine):
        assert engine.reopen("does.not.exist") is None


class TestHighestVerdictTracking:
    def test_suspicious_then_attack_upgrades_highest_verdict(self, engine):
        scan = from_port_scan(
            PortScanCheckResult(PortScanVerdict.SUSPICIOUS, "1.1.1.1", 10.0, 9, 4),
            timestamp=100.0,
        )
        incident = engine.add_evidence(scan)
        assert incident.highest_verdict.value == "SUSPICIOUS"

        bf = from_brute_force(
            BruteForceResult(BruteForceVerdict.ATTACK, "1.1.1.1", "2.2.2.2", 22, 20, 60.0, 1),
            timestamp=150.0,
        )
        incident2 = engine.add_evidence(bf)
        assert incident2.highest_verdict.value == "ATTACK"

    def test_attack_then_suspicious_does_not_downgrade(self, engine):
        bf = from_brute_force(
            BruteForceResult(BruteForceVerdict.ATTACK, "1.1.1.1", "2.2.2.2", 22, 20, 60.0, 1),
            timestamp=100.0,
        )
        engine.add_evidence(bf)

        scan = from_port_scan(
            PortScanCheckResult(PortScanVerdict.SUSPICIOUS, "1.1.1.1", 10.0, 9, 4),
            timestamp=150.0,
        )
        incident = engine.add_evidence(scan)
        assert incident.highest_verdict.value == "ATTACK"


class TestFirstLastSeen:
    def test_first_and_last_seen_span_all_evidence(self, engine):
        bf1 = from_brute_force(
            BruteForceResult(BruteForceVerdict.ATTACK, "1.1.1.1", "2.2.2.2", 22, 20, 60.0, 1),
            timestamp=100.0,
        )
        bf2 = from_brute_force(
            BruteForceResult(BruteForceVerdict.ATTACK, "1.1.1.1", "3.3.3.3", 22, 20, 60.0, 2),
            timestamp=500.0,
        )
        engine.add_evidence(bf1)
        incident = engine.add_evidence(bf2)
        assert incident.first_seen == 100.0
        assert incident.last_seen == 500.0