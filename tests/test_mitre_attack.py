"""
tests/test_mitre_attack.py

Tests for detection/mitre_attack.py's per-evidence and per-incident
ATT&CK technique lookups.
"""

import pytest

from detection.evidence import (
    DetectorName,
    Evidence,
    EvidenceVerdict,
)
from detection.mitre_attack import (
    MitreTechnique,
    get_technique_for_evidence,
    get_techniques_for_incident,
)
from detection.correlation_engine import Incident, IncidentStatus


def _make_evidence(detector, verdict=EvidenceVerdict.ATTACK, payload=None, timestamp=1.0):
    return Evidence(
        evidence_id="test-id",
        detector=detector,
        timestamp=timestamp,
        verdict=verdict,
        reasoning="test",
        payload=payload,
    )


class FakeAnalysisResult:
    """Stand-in for llm_analyser.AnalysisResult, since only attack_type
    is read by mitre_attack.py."""
    def __init__(self, attack_type):
        self.attack_type = attack_type


class TestPerEvidenceTechniqueLookup:
    def test_anomaly_never_gets_a_technique(self):
        evidence = _make_evidence(DetectorName.ANOMALY)
        assert get_technique_for_evidence(evidence) is None

    def test_ddos_maps_to_fixed_technique(self):
        evidence = _make_evidence(DetectorName.DDOS)
        technique = get_technique_for_evidence(evidence)
        assert technique.technique_id == "T1498"

    def test_port_scan_maps_to_fixed_technique(self):
        evidence = _make_evidence(DetectorName.PORT_SCAN)
        technique = get_technique_for_evidence(evidence)
        assert technique.technique_id == "T1046"

    def test_brute_force_maps_to_fixed_technique(self):
        evidence = _make_evidence(DetectorName.BRUTE_FORCE)
        technique = get_technique_for_evidence(evidence)
        assert technique.technique_id == "T1110"

    def test_llm_known_attack_type_maps_correctly(self):
        evidence = _make_evidence(
            DetectorName.LLM, payload=FakeAnalysisResult("credential_stuffing")
        )
        technique = get_technique_for_evidence(evidence)
        assert technique.technique_id == "T1110.004"

    def test_llm_benign_maps_to_none(self):
        evidence = _make_evidence(
            DetectorName.LLM, verdict=EvidenceVerdict.NORMAL,
            payload=FakeAnalysisResult("benign"),
        )
        assert get_technique_for_evidence(evidence) is None

    def test_llm_unknown_attack_type_maps_to_none(self):
        evidence = _make_evidence(
            DetectorName.LLM, verdict=EvidenceVerdict.SUSPICIOUS,
            payload=FakeAnalysisResult("unknown"),
        )
        assert get_technique_for_evidence(evidence) is None

    def test_llm_unrecognised_attack_type_maps_to_none(self):
        """An attack_type this module doesn't yet know about should
        never guess a technique - it should fall through to None."""
        evidence = _make_evidence(
            DetectorName.LLM, payload=FakeAnalysisResult("some_future_attack_type")
        )
        assert get_technique_for_evidence(evidence) is None

    def test_llm_missing_payload_maps_to_none(self):
        evidence = _make_evidence(DetectorName.LLM, payload=None)
        assert get_technique_for_evidence(evidence) is None


class TestIncidentLevelLookup:
    def _make_incident(self, evidence_list):
        incident = Incident(
            incident_id="inc-1",
            key="1.2.3.4",
            status=IncidentStatus.OPEN,
            first_seen=1.0,
            last_seen=1.0,
        )
        incident.evidence.extend(evidence_list)
        return incident

    def test_single_detector_incident_returns_one_technique(self):
        incident = self._make_incident([_make_evidence(DetectorName.BRUTE_FORCE)])
        techniques = get_techniques_for_incident(incident)
        assert [t.technique_id for t in techniques] == ["T1110"]

    def test_multi_stage_incident_returns_deduplicated_union(self):
        """Port scan followed by brute force from the same source
        should surface BOTH techniques - the whole point of
        incident-level correlation."""
        incident = self._make_incident([
            _make_evidence(DetectorName.PORT_SCAN, timestamp=1.0),
            _make_evidence(DetectorName.BRUTE_FORCE, timestamp=2.0),
        ])
        techniques = get_techniques_for_incident(incident)
        ids = [t.technique_id for t in techniques]
        assert ids == ["T1046", "T1110"]

    def test_repeated_same_detector_evidence_is_deduplicated(self):
        incident = self._make_incident([
            _make_evidence(DetectorName.BRUTE_FORCE, timestamp=1.0),
            _make_evidence(DetectorName.BRUTE_FORCE, timestamp=2.0),
            _make_evidence(DetectorName.BRUTE_FORCE, timestamp=3.0),
        ])
        techniques = get_techniques_for_incident(incident)
        assert len(techniques) == 1

    def test_anomaly_evidence_contributes_nothing(self):
        incident = self._make_incident([
            _make_evidence(DetectorName.ANOMALY, timestamp=1.0),
            _make_evidence(DetectorName.BRUTE_FORCE, timestamp=2.0),
        ])
        techniques = get_techniques_for_incident(incident)
        assert len(techniques) == 1
        assert techniques[0].technique_id == "T1110"

    def test_empty_incident_returns_empty_list(self):
        incident = self._make_incident([])
        assert get_techniques_for_incident(incident) == []


class TestMitreTechniqueDataclass:
    def test_is_frozen_and_hashable(self):
        t = MitreTechnique(technique_id="T9999", name="Test", tactic="Test")
        # frozen dataclasses are hashable by default - useful if a
        # future caller wants to put these in a set
        hash(t)

    def test_repr_includes_id_and_name(self):
        t = MitreTechnique(technique_id="T1110", name="Brute Force", tactic="Credential Access")
        assert "T1110" in repr(t)
        assert "Brute Force" in repr(t)