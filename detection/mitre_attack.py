"""
detection/mitre_attack.py

MITRE ATT&CK technique tagging for Sentinel's Evidence objects and
Incidents. Maps each detector's finding onto a (best-effort) ATT&CK
technique, so incident reports and SIEM exports can carry standard,
cross-tool-recognisable technique IDs instead of only Sentinel's own
internal verdict vocabulary.

Why anomaly gets no technique tag:
-----------------------------------
anomaly.py's Isolation Forest verdict is a purely statistical
judgement - "this flow's feature vector is far from the learned
baseline." It doesn't know *what* is anomalous about the flow, only
that something is. Attaching a specific ATT&CK technique to that would
be inventing a claim the detector never made. Every other detector
(ddos, port_scan, brute_force, llm) is judging a specific, named
pattern and can be mapped honestly; anomaly is deliberately excluded
rather than mapped to a vague catch-all technique.

Why the three tracker detectors get a single fixed technique each:
--------------------------------------------------------------------
ddos, port_scan, and brute_force are each purpose-built to detect one
specific pattern - there's no ambiguity to resolve, so the mapping is
a static 1:1 lookup.

Why llm is different (mapped off attack_type, not DetectorName):
--------------------------------------------------------------------
The LLM path can name any of several attack types in a single field
(AnalysisResult.attack_type), so unlike the trackers, one DetectorName
does not correspond to one technique. Evidence.payload is inspected to
read that field. Unrecognised or non-attack attack_type values
(e.g. "benign", "unknown", or any future type this module doesn't yet
know about) intentionally map to None rather than guessing - a wrong
technique tag is worse than no tag.

Incident-level lookup:
-----------------------
get_techniques_for_incident() walks every piece of Evidence attached
to an Incident and returns the deduplicated union of techniques found,
since a multi-stage attack (e.g. a port scan followed by a brute-force
attempt from the same source) should surface every technique involved,
not just the most recent one.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from detection.evidence import DetectorName, Evidence

if TYPE_CHECKING:
    from detection.correlation_engine import Incident


@dataclass(frozen=True)
class MitreTechnique:
    """One ATT&CK technique reference. Kept intentionally minimal -
    just enough to be useful in a report or CEF export line - rather
    than mirroring MITRE's full technique schema."""
    technique_id: str
    name: str
    tactic: str

    def __repr__(self) -> str:
        return f"MitreTechnique({self.technique_id} {self.name!r})"


# ----------------------------------------------------------------------
# Static, fixed mappings for the three single-purpose trackers.
# ----------------------------------------------------------------------

_DDOS_TECHNIQUE = MitreTechnique(
    technique_id="T1498",
    name="Network Denial of Service",
    tactic="Impact",
)

_PORT_SCAN_TECHNIQUE = MitreTechnique(
    technique_id="T1046",
    name="Network Service Discovery",
    tactic="Discovery",
)

_BRUTE_FORCE_TECHNIQUE = MitreTechnique(
    technique_id="T1110",
    name="Brute Force",
    tactic="Credential Access",
)

_TRACKER_TECHNIQUES = {
    DetectorName.DDOS: _DDOS_TECHNIQUE,
    DetectorName.PORT_SCAN: _PORT_SCAN_TECHNIQUE,
    DetectorName.BRUTE_FORCE: _BRUTE_FORCE_TECHNIQUE,
}

# ----------------------------------------------------------------------
# LLM path: mapped off AnalysisResult.attack_type, not DetectorName.
# Values here are Sentinel's own attack_type vocabulary as produced by
# detection/llm_analyser.py's prompt/schema - extend this dict as that
# vocabulary grows. Deliberately does NOT include "benign" or
# "unknown" - those fall through to the default None below, same as
# any attack_type this module doesn't yet recognise.
# ----------------------------------------------------------------------

_LLM_ATTACK_TYPE_TECHNIQUES = {
    "port_scan": _PORT_SCAN_TECHNIQUE,
    "ddos": _DDOS_TECHNIQUE,
    "brute_force": _BRUTE_FORCE_TECHNIQUE,
    "credential_stuffing": MitreTechnique(
        technique_id="T1110.004",
        name="Credential Stuffing",
        tactic="Credential Access",
    ),
    "data_exfiltration": MitreTechnique(
        technique_id="T1041",
        name="Exfiltration Over C2 Channel",
        tactic="Exfiltration",
    ),
    "lateral_movement": MitreTechnique(
        technique_id="T1021",
        name="Remote Services",
        tactic="Lateral Movement",
    ),
    "command_and_control": MitreTechnique(
        technique_id="T1071",
        name="Application Layer Protocol",
        tactic="Command and Control",
    ),
    "reconnaissance": MitreTechnique(
        technique_id="T1595",
        name="Active Scanning",
        tactic="Reconnaissance",
    ),
}


def _technique_for_llm(evidence: Evidence) -> Optional[MitreTechnique]:
    """
    Reads attack_type off the LLM payload (AnalysisResult) and looks it
    up. Returns None for "benign", "unknown", a missing/unavailable
    payload, or any attack_type this module doesn't recognise - see
    module docstring.
    """
    payload = evidence.payload
    attack_type = getattr(payload, "attack_type", None)
    if attack_type is None:
        return None
    return _LLM_ATTACK_TYPE_TECHNIQUES.get(attack_type)


def get_technique_for_evidence(evidence: Evidence) -> Optional[MitreTechnique]:
    """
    Returns the single best-effort ATT&CK technique for one piece of
    Evidence, or None if this detector/finding doesn't map to one
    (always None for anomaly - see module docstring).
    """
    if evidence.detector == DetectorName.LLM:
        return _technique_for_llm(evidence)
    return _TRACKER_TECHNIQUES.get(evidence.detector)


def get_techniques_for_incident(incident: "Incident") -> list[MitreTechnique]:
    """
    Deduplicated union of every technique found across all Evidence
    attached to this incident, in first-seen order (matching
    Incident.evidence's own chronological-by-arrival ordering - see
    detection/timeline.py for why that ordering is preserved rather
    than re-sorted).
    """
    seen: dict[str, MitreTechnique] = {}
    for ev in incident.evidence:
        technique = get_technique_for_evidence(ev)
        if technique is not None and technique.technique_id not in seen:
            seen[technique.technique_id] = technique
    return list(seen.values())