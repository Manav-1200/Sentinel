"""
detection/correlation_engine.py

Incident Correlation Engine — groups Evidence from all five detectors
into per-attacker Incidents, so an operator (or the future dashboard)
sees "this source is doing X, Y, and Z" as one escalating story,
instead of five disconnected log lines from five different trackers.

Why group on src_ip alone, not (src_ip, dst_ip, dst_port):
--------------------------------------------------------------
The whole point of correlation is tying together multiple detector
signals from the SAME ATTACKER. If incidents were split further by
destination, a real multi-stage attack - a recon port scan against one
host, followed by a brute-force attempt against a different host, both
from the same source - would scatter across separate incidents instead
of surfacing as one escalating pattern. That's exactly the story an
operator watching Sentinel needs to see in one place.

dst_ip/dst_port aren't lost - they stay attached to each individual
Evidence inside the incident (see evidence.py), just not used to split
incidents apart.

The one structural exception: ddos evidence (detection/ddos_tracker.py)
has no src_ip at all - it's a genuine cross-source aggregate, there is
no single attacker to attribute it to. That can't merge into any
per-source incident, so it gets one dedicated, permanently-open bucket
(AGGREGATE_KEY) instead.

Why incidents never auto-close:
------------------------------------
Explicit product decision (2026-07): an incident auto-closing after a
quiet period risks an operator missing genuinely ongoing malicious
activity that just happens to have gone quiet for a while (e.g. a
patient attacker pausing between probing attempts). Incidents stay
OPEN indefinitely until a human explicitly calls resolve() - silence
is not evidence of resolution.

Why only SUSPICIOUS/ATTACK evidence creates or updates an incident:
------------------------------------------------------------------
NORMAL and WARMING_UP findings are the overwhelming majority of what
detectors produce during ordinary operation - folding every one of
them into the correlation engine would swamp real incidents in noise
and make "does this source have an open incident" a meaningless
question (nearly everyone would). UNAVAILABLE (LLM call failed) is
also excluded from CREATING a new incident - an absent finding isn't
evidence of anything - but if an incident is already open for that
source, an UNAVAILABLE result is still attached to it, since "we tried
to get a second opinion and couldn't" is relevant context for an
already-open incident, even though it shouldn't be enough to open one.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from detection.evidence import Evidence, EvidenceVerdict


# Dedicated key for aggregate, sourceless evidence (currently only
# ddos_tracker's findings) - see module docstring. Exposed without a
# leading underscore (unlike the other module-level constants below)
# because external callers (pipeline/labeller.py's logging call site)
# legitimately need to compute the same grouping key add_evidence()
# uses internally, and re-deriving/hardcoding "__aggregate__" at each
# call site would silently drift if this ever changed.
AGGREGATE_KEY = "__aggregate__"

# Verdicts that are allowed to CREATE a brand-new incident. Deliberately
# narrower than the set of verdicts allowed to be ATTACHED to an
# already-open incident (see add_evidence) - see module docstring's
# "why only SUSPICIOUS/ATTACK" section.
_INCIDENT_OPENING_VERDICTS = frozenset({EvidenceVerdict.SUSPICIOUS, EvidenceVerdict.ATTACK})

# Verdicts that are NEVER attached to an incident, open or not - these
# represent the absence of a finding, not a finding.
_IGNORED_VERDICTS = frozenset({EvidenceVerdict.NORMAL, EvidenceVerdict.WARMING_UP})

# Severity ranking used to compute an incident's highest_verdict as new
# Evidence arrives - higher index wins. UNAVAILABLE ranks below
# SUSPICIOUS deliberately: "we couldn't get a second opinion" should
# never look more severe than a confirmed SUSPICIOUS finding.
_SEVERITY_ORDER = [
    EvidenceVerdict.UNAVAILABLE,
    EvidenceVerdict.SUSPICIOUS,
    EvidenceVerdict.ATTACK,
]


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    RESOLVED = "RESOLVED"


@dataclass
class Incident:
    """
    One attacker's accumulated story, built from Evidence across
    however many of the five detectors have flagged them. `key` is the
    src_ip this incident is grouped on, or AGGREGATE_KEY for the one
    permanent aggregate-DDoS bucket.
    """
    incident_id: str
    key: str
    status: IncidentStatus
    first_seen: float
    last_seen: float
    evidence: list = field(default_factory=list)  # list[Evidence], oldest first
    detectors_involved: set = field(default_factory=set)  # set[str] of DetectorName values
    highest_verdict: EvidenceVerdict = EvidenceVerdict.SUSPICIOUS

    def __repr__(self) -> str:
        return (
            f"Incident(key={self.key}, status={self.status.value}, "
            f"highest_verdict={self.highest_verdict.value}, "
            f"detectors={sorted(self.detectors_involved)}, "
            f"evidence_count={len(self.evidence)})"
        )


class CorrelationEngine:
    """
    Groups incoming Evidence into per-source (or aggregate) Incidents.
    Thread-safe, mirroring the other trackers' locking convention,
    since main.py's live-capture path may call this from more than one
    thread (packet capture worker + LLM retry worker both eventually
    feed evidence in).
    """

    def __init__(self):
        self._incidents: dict[str, Incident] = {}
        self._lock = threading.Lock()

    def add_evidence(self, evidence: Evidence) -> Optional[Incident]:
        """
        Files one Evidence into its incident, creating a new incident
        only if none is currently open for this key AND this evidence's
        verdict is one that's allowed to open one (see module
        docstring). Returns the Incident it was filed into, or None if
        this evidence didn't warrant any incident action at all (e.g.
        a NORMAL/WARMING_UP finding with no existing open incident to
        attach to).
        """
        if evidence.verdict in _IGNORED_VERDICTS:
            return None

        key = evidence.src_ip if evidence.src_ip is not None else AGGREGATE_KEY

        with self._lock:
            incident = self._incidents.get(key)

            if incident is None or incident.status == IncidentStatus.RESOLVED:
                # No open incident to attach to - only open a new one if
                # this evidence is severe enough to justify starting one.
                if evidence.verdict not in _INCIDENT_OPENING_VERDICTS:
                    return None
                incident = Incident(
                    incident_id=str(uuid.uuid4()),
                    key=key,
                    status=IncidentStatus.OPEN,
                    first_seen=evidence.timestamp,
                    last_seen=evidence.timestamp,
                    highest_verdict=evidence.verdict,
                )
                self._incidents[key] = incident

            incident.evidence.append(evidence)
            incident.detectors_involved.add(evidence.detector.value)
            incident.last_seen = max(incident.last_seen, evidence.timestamp)

            if _SEVERITY_ORDER.index(evidence.verdict) > _SEVERITY_ORDER.index(incident.highest_verdict):
                incident.highest_verdict = evidence.verdict

            return incident

    def get_incident(self, key: str) -> Optional[Incident]:
        with self._lock:
            return self._incidents.get(key)

    def open_incidents(self) -> list:
        """Returns all currently-OPEN incidents. Order is not guaranteed."""
        with self._lock:
            return [i for i in self._incidents.values() if i.status == IncidentStatus.OPEN]

    def all_incidents(self) -> list:
        """Returns every incident regardless of status - open or resolved."""
        with self._lock:
            return list(self._incidents.values())

    def resolve(self, key: str) -> Optional[Incident]:
        """
        Marks the incident for this key as RESOLVED. Safe to call on an
        already-resolved or nonexistent key - returns None rather than
        raising, since a human reviewing incidents may resolve() one
        that's already been closed by a prior action without needing to
        check first.
        """
        with self._lock:
            incident = self._incidents.get(key)
            if incident is None:
                return None
            incident.status = IncidentStatus.RESOLVED
            return incident

    def reopen(self, key: str) -> Optional[Incident]:
        """
        Reopens a previously-resolved incident - e.g. if new Evidence
        for a source arrives after a human marked it resolved, but
        BEFORE add_evidence() would have started a fresh one on its
        own (add_evidence already does this automatically for
        SUSPICIOUS/ATTACK evidence - this method exists for a human
        explicitly reopening a resolved incident without waiting for
        new evidence to trigger it).
        """
        with self._lock:
            incident = self._incidents.get(key)
            if incident is None:
                return None
            incident.status = IncidentStatus.OPEN
            return incident