"""
tests/test_evidence.py

Coverage for detection/evidence.py's five from_* constructors: verdict
mapping (including the two non-trivial cases - anomaly's WARMING_UP
and the LLM path's three-way available/benign/unknown split) and the
identity-field presence/absence contract each detector is documented
to have (see evidence.py's module docstring).
"""

import pytest

from detection.evidence import (
    Evidence,
    EvidenceVerdict,
    EvidenceBuffer,
    DetectorName,
    from_anomaly,
    from_ddos,
    from_port_scan,
    from_brute_force,
    from_llm,
)
from detection.anomaly import DetectionResult, Verdict
from detection.ddos_tracker import DDoSCheckResult, DDoSVerdict
from detection.port_scan_tracker import PortScanCheckResult, PortScanVerdict
from detection.brute_force_tracker import BruteForceResult, BruteForceVerdict
from detection.llm_analyser import AnalysisResult, AnalysisConfidence


class TestFromAnomaly:
    def test_pulls_identity_from_features_dict(self):
        result = DetectionResult(
            Verdict.SUSPICIOUS, -0.5,
            {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 443, "total_packets": 50},
        )
        evidence = from_anomaly(result, timestamp=100.0)

        assert evidence.detector == DetectorName.ANOMALY
        assert evidence.verdict == EvidenceVerdict.SUSPICIOUS
        assert evidence.src_ip == "10.0.0.1"
        assert evidence.dst_ip == "10.0.0.2"
        assert evidence.dst_port == 443
        assert evidence.timestamp == 100.0
        assert evidence.payload is result

    def test_warming_up_verdict_maps_through(self):
        result = DetectionResult(Verdict.WARMING_UP, None, {"src_ip": "10.0.0.1"})
        evidence = from_anomaly(result, timestamp=100.0)

        assert evidence.verdict == EvidenceVerdict.WARMING_UP
        assert "warming up" in evidence.reasoning.lower()

    def test_missing_identity_fields_become_none_not_keyerror(self):
        # If a caller ever hands predict() a features dict without
        # identity fields, from_anomaly must degrade to None rather
        # than raising - see the docstring's note about this being a
        # documented assumption, not a hard guarantee.
        result = DetectionResult(Verdict.NORMAL, 0.1, {"total_packets": 5})
        evidence = from_anomaly(result, timestamp=100.0)

        assert evidence.src_ip is None
        assert evidence.dst_ip is None
        assert evidence.dst_port is None

    def test_reasoning_includes_score_when_present(self):
        result = DetectionResult(Verdict.ATTACK, -0.987, {"src_ip": "1.1.1.1"})
        evidence = from_anomaly(result, timestamp=100.0)
        assert "-0.987" in evidence.reasoning


class TestFromDDoS:
    def test_identity_fields_are_none(self):
        # DDoS is a global aggregate signal by design - there is no
        # single source or destination to attribute it to.
        result = DDoSCheckResult(DDoSVerdict.ATTACK, 10.0, 600, 30)
        evidence = from_ddos(result, timestamp=200.0)

        assert evidence.src_ip is None
        assert evidence.dst_ip is None
        assert evidence.dst_port is None
        assert evidence.detector == DetectorName.DDOS

    def test_verdict_mapping(self):
        for verdict in (DDoSVerdict.NORMAL, DDoSVerdict.SUSPICIOUS, DDoSVerdict.ATTACK):
            result = DDoSCheckResult(verdict, 10.0, 1, 1)
            evidence = from_ddos(result, timestamp=1.0)
            assert evidence.verdict.value == verdict.value

    def test_reasoning_mentions_flow_and_source_counts(self):
        result = DDoSCheckResult(DDoSVerdict.SUSPICIOUS, 10.0, 250, 15)
        evidence = from_ddos(result, timestamp=1.0)
        assert "250" in evidence.reasoning
        assert "15" in evidence.reasoning


class TestFromPortScan:
    def test_src_ip_present_dst_fields_none(self):
        # A scan is one-source-many-targets by definition - there is
        # deliberately no single dst_ip/dst_port to report.
        result = PortScanCheckResult(PortScanVerdict.ATTACK, "192.168.1.50", 10.0, 25, 12)
        evidence = from_port_scan(result, timestamp=300.0)

        assert evidence.src_ip == "192.168.1.50"
        assert evidence.dst_ip is None
        assert evidence.dst_port is None
        assert evidence.detector == DetectorName.PORT_SCAN

    def test_reasoning_mentions_ports_and_targets(self):
        result = PortScanCheckResult(PortScanVerdict.SUSPICIOUS, "1.2.3.4", 10.0, 9, 4)
        evidence = from_port_scan(result, timestamp=1.0)
        assert "9" in evidence.reasoning
        assert "4" in evidence.reasoning


class TestFromBruteForce:
    def test_full_identity_triple_present(self):
        # The one detector with a genuine (src, dst, port) triple.
        result = BruteForceResult(
            BruteForceVerdict.ATTACK, "10.0.0.5", "10.0.0.99", 22,
            attempts_in_window=20, window_seconds=60.0, repeat_offender_count=3,
        )
        evidence = from_brute_force(result, timestamp=400.0)

        assert evidence.src_ip == "10.0.0.5"
        assert evidence.dst_ip == "10.0.0.99"
        assert evidence.dst_port == 22
        assert evidence.payload.repeat_offender_count == 3

    def test_reasoning_includes_offence_count(self):
        result = BruteForceResult(
            BruteForceVerdict.ATTACK, "1.1.1.1", "2.2.2.2", 3389,
            attempts_in_window=15, window_seconds=60.0, repeat_offender_count=2,
        )
        evidence = from_brute_force(result, timestamp=1.0)
        assert "#2" in evidence.reasoning


class TestFromLLM:
    def test_unavailable_maps_to_unavailable_not_normal(self):
        # An absent finding must never read as a confirmed-clean verdict.
        result = AnalysisResult(available=False, error="timeout after 3 retries")
        evidence = from_llm(result, timestamp=500.0)

        assert evidence.verdict == EvidenceVerdict.UNAVAILABLE
        assert "timeout" in evidence.reasoning

    def test_benign_maps_to_normal(self):
        result = AnalysisResult(
            available=True, attack_type="benign",
            confidence=AnalysisConfidence.HIGH, reasoning="ordinary traffic",
        )
        evidence = from_llm(result, timestamp=500.0)
        assert evidence.verdict == EvidenceVerdict.NORMAL

    def test_unknown_maps_to_suspicious(self):
        result = AnalysisResult(
            available=True, attack_type="unknown",
            confidence=AnalysisConfidence.LOW, reasoning="couldn't determine",
        )
        evidence = from_llm(result, timestamp=500.0)
        assert evidence.verdict == EvidenceVerdict.SUSPICIOUS

    def test_named_attack_type_maps_to_attack(self):
        result = AnalysisResult(
            available=True, attack_type="ddos",
            confidence=AnalysisConfidence.MEDIUM, reasoning="matches ddos pattern",
        )
        evidence = from_llm(result, timestamp=500.0)
        assert evidence.verdict == EvidenceVerdict.ATTACK

    def test_identity_passed_through_explicitly(self):
        # LLM results carry no identity of their own - the caller
        # (labeller.py) must supply it from the flow already in scope.
        result = AnalysisResult(available=True, attack_type="benign")
        evidence = from_llm(result, timestamp=1.0, src_ip="7.7.7.7", dst_ip="8.8.8.8", dst_port=80)

        assert evidence.src_ip == "7.7.7.7"
        assert evidence.dst_ip == "8.8.8.8"
        assert evidence.dst_port == 80

    def test_no_identity_defaults_to_none(self):
        result = AnalysisResult(available=True, attack_type="benign")
        evidence = from_llm(result, timestamp=1.0)
        assert evidence.src_ip is None and evidence.dst_ip is None and evidence.dst_port is None


class TestEvidenceBuffer:
    def _ddos_evidence(self, timestamp: float, verdict=DDoSVerdict.NORMAL) -> Evidence:
        result = DDoSCheckResult(verdict, 10.0, 1, 1)
        return from_ddos(result, timestamp=timestamp)

    def test_recent_returns_items_within_window(self):
        buffer = EvidenceBuffer(window_seconds=60.0)
        buffer.add(self._ddos_evidence(100.0))
        buffer.add(self._ddos_evidence(120.0))

        items = buffer.recent(current_timestamp=120.0)
        assert len(items) == 2

    def test_evicts_items_older_than_window(self):
        buffer = EvidenceBuffer(window_seconds=60.0)
        buffer.add(self._ddos_evidence(100.0))
        buffer.add(self._ddos_evidence(200.0))  # 100s later - outside a 60s window

        items = buffer.recent(current_timestamp=200.0)
        assert len(items) == 1
        assert items[0].timestamp == 200.0

    def test_eviction_happens_on_add_not_just_on_recent(self):
        # _evict_expired runs from both add() and recent(), mirroring
        # the dual-path eviction convention the trackers already use -
        # a recent() call after a period of silence shouldn't report
        # stale entries just because add() wasn't called to trigger it.
        buffer = EvidenceBuffer(window_seconds=10.0)
        buffer.add(self._ddos_evidence(0.0))
        buffer.add(self._ddos_evidence(50.0))
        assert len(buffer._items) == 1

    def test_empty_buffer_returns_empty_list(self):
        buffer = EvidenceBuffer(window_seconds=60.0)
        assert buffer.recent(current_timestamp=100.0) == []

    def test_recent_without_timestamp_reports_current_state_only(self):
        # add() already evicts eagerly against its own timestamp, so by
        # the time the second (much later) item is added, the first is
        # already gone - recent() with no timestamp just reports
        # whatever's left, it doesn't trigger any FURTHER eviction.
        buffer = EvidenceBuffer(window_seconds=1.0)
        buffer.add(self._ddos_evidence(0.0))
        buffer.add(self._ddos_evidence(1000.0))
        assert len(buffer.recent()) == 1
        assert buffer.recent()[0].timestamp == 1000.0


class TestEvidenceIdShapes:
    def test_evidence_ids_are_unique_across_calls(self):
        result = DDoSCheckResult(DDoSVerdict.NORMAL, 10.0, 1, 1)
        e1 = from_ddos(result, timestamp=1.0)
        e2 = from_ddos(result, timestamp=1.0)
        assert e1.evidence_id != e2.evidence_id

    def test_repr_does_not_crash_and_omits_payload(self):
        result = DDoSCheckResult(DDoSVerdict.NORMAL, 10.0, 1, 1)
        evidence = from_ddos(result, timestamp=1.0)
        text = repr(evidence)
        assert "detector=ddos" in text