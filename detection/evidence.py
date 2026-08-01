"""
detection/evidence.py

Universal Evidence Object — normalises the five heterogeneous detector
outputs (anomaly.DetectionResult, ddos_tracker.DDoSCheckResult,
port_scan_tracker.PortScanCheckResult, brute_force_tracker.BruteForceResult,
llm_analyser.AnalysisResult) into one common shape, so downstream
consumers (the future Incident Correlation Engine, the Unified Risk
Engine, per-incident timelines) have one thing to reason about instead
of five different dataclasses with different fields and different
verdict vocabularies.

Why a common-core-plus-typed-payload design, not one flat schema:
--------------------------------------------------------------------
The five detector outputs are not just cosmetically different - they
disagree on which identity fields even exist:
  - anomaly: no dst_ip/dst_port at the top level (buried in `features`),
    no window (judges one flow in isolation).
  - ddos: no identity at all - it's a global aggregate, not tied to
    any one source or destination.
  - port_scan: has src_ip only. A scan is one-source-many-targets, so
    there is deliberately no single dst_ip/dst_port to report.
  - brute_force: has the full (src_ip, dst_ip, dst_port) triple.
  - llm: doesn't carry identity at all - the caller (labeller.py)
    already has the flow in scope and must pass identity through
    explicitly (see from_llm).

Forcing these into one flat schema would mean inventing values for
fields that structurally don't exist (e.g. a fake dst_ip for a DDoS
verdict). Instead, dst_ip/dst_port are Optional on the common core -
their absence for ddos/port_scan/anomaly-without-features is real
information, not a gap to paper over. The future correlation engine
must key on src_ip alone for those detectors, and can use the full
(src_ip, dst_ip, dst_port) triple for brute_force.

No detector output carries its own timestamp - all five call sites
must supply `timestamp` explicitly (the flow's own timestamp,
flow.last_seen - NOT time.time(), matching the pcap-replay-safe
convention every other Sentinel tracker already follows).
"""

from __future__ import annotations

import dataclasses
import threading
import uuid
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Union

from detection.anomaly import DetectionResult
from detection.ddos_tracker import DDoSCheckResult
from detection.port_scan_tracker import PortScanCheckResult
from detection.brute_force_tracker import BruteForceResult
from detection.llm_analyser import AnalysisResult


class EvidenceVerdict(str, Enum):
    """
    Unified vocabulary, collapsing the four separate-but-identical
    NORMAL/SUSPICIOUS/ATTACK enums (anomaly.Verdict, DDoSVerdict,
    PortScanVerdict, BruteForceVerdict) into one, plus:
      - WARMING_UP: only ever produced by anomaly (still collecting
        its warm-up baseline).
      - UNAVAILABLE: only ever produced by the LLM path, when the call
        failed for any reason. Deliberately NOT folded into NORMAL -
        "the LLM never got back to us" is an absence of a finding, not
        a confirmed clean bill of health, and the correlation engine
        should be able to tell the two apart.
    """
    WARMING_UP = "WARMING_UP"
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    ATTACK = "ATTACK"
    UNAVAILABLE = "UNAVAILABLE"


class DetectorName(str, Enum):
    ANOMALY = "anomaly"
    DDOS = "ddos"
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    LLM = "llm"


# Union of every detector-specific result type that can be carried as
# an Evidence's payload. Kept as the ORIGINAL dataclass, not flattened
# into loose fields, so nothing is lost and callers who need a
# specific field (e.g. repeat_offender_count for the response layer's
# escalation logic) still get it fully typed rather than digging
# through a dict.
EvidencePayload = Union[
    DetectionResult,
    DDoSCheckResult,
    PortScanCheckResult,
    BruteForceResult,
    AnalysisResult,
]


@dataclass
class Evidence:
    """
    One detector's finding, normalised to a common shape.

    src_ip/dst_ip/dst_port are Optional - see module docstring for
    exactly which detectors leave which fields as None, and why that's
    real structural information rather than a gap.
    """
    evidence_id: str
    detector: DetectorName
    timestamp: float  # caller-supplied - flow.last_seen, never time.time()
    verdict: EvidenceVerdict
    reasoning: str

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None

    payload: EvidencePayload = field(default=None, repr=False)

    def __repr__(self) -> str:
        return (
            f"Evidence(detector={self.detector.value}, "
            f"verdict={self.verdict.value}, "
            f"src_ip={self.src_ip}, dst_ip={self.dst_ip}, dst_port={self.dst_port})"
        )

    def to_dict(self) -> dict:
        """
        JSON-serialisable representation, for the DB storage path
        (see pipeline/labeller.py's store_evidence). Recurses through
        `payload` - which is one of five different dataclasses, each
        with their own Enum-valued fields (Verdict, DDoSVerdict,
        PortScanVerdict, BruteForceVerdict, AnalysisConfidence) - so a
        plain dataclasses.asdict() isn't enough on its own; Enums
        inside it still need converting to their .value.
        """
        return {
            "evidence_id": self.evidence_id,
            "detector": self.detector.value,
            "timestamp": self.timestamp,
            "verdict": self.verdict.value,
            "reasoning": self.reasoning,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "payload": _serialise(self.payload),
        }


def _serialise(obj):
    """
    Recursively converts a dataclass (possibly containing nested
    dataclasses, Enums, or plain values) into a JSON-serialisable
    structure. Used only for Evidence.payload, which is always one of
    the five detector result dataclasses - none of them are deeply
    nested beyond one level today, but this stays recursive so a
    future detector adding a nested dataclass field doesn't silently
    break serialisation.
    """
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: _serialise(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, dict):
        return {k: _serialise(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_serialise(v) for v in obj]
    return obj


class EvidenceBuffer:
    """
    Bounded, thread-safe, in-memory holding area for recent Evidence,
    for the future Incident Correlation Engine to read directly rather
    than re-querying the DB for every check. Mirrors the sliding-window
    pattern the trackers already use (bounded deque, evict-old-first),
    just time-bounded instead of count-bounded — correlation needs
    "everything from roughly the last N seconds", not "the last N
    items", since flow rates vary wildly session to session.

    This is deliberately NOT the system of record — see the module
    docstring's storage note. Evidence is also persisted via whatever
    DB path pipeline/labeller.py already uses; this buffer is a fast,
    volatile, correlation-only view that resets every restart.
    """

    def __init__(self, window_seconds: float = 300.0):
        self.window_seconds = window_seconds
        self._items: deque[Evidence] = deque()
        self._lock = threading.Lock()

    def add(self, evidence: Evidence) -> None:
        with self._lock:
            self._items.append(evidence)
            self._evict_expired(evidence.timestamp)

    def recent(self, current_timestamp: Optional[float] = None) -> list[Evidence]:
        """Returns all buffered Evidence still within the window, oldest first."""
        with self._lock:
            if current_timestamp is not None:
                self._evict_expired(current_timestamp)
            return list(self._items)

    def _evict_expired(self, now: float) -> None:
        """MUST be called while holding self._lock."""
        cutoff = now - self.window_seconds
        while self._items and self._items[0].timestamp < cutoff:
            self._items.popleft()


def _verdict_from(detector_verdict) -> EvidenceVerdict:
    """
    Translates any of the four identical-vocabulary detector enums
    (anomaly.Verdict, DDoSVerdict, PortScanVerdict, BruteForceVerdict)
    into EvidenceVerdict. Safe because all four already use the exact
    string values "NORMAL"/"SUSPICIOUS"/"ATTACK"/"WARMING_UP" - this
    function exists so call sites don't each need to know that detail,
    and so a future detector enum drifting from that convention fails
    loudly (ValueError) rather than silently mismatching.
    """
    return EvidenceVerdict(detector_verdict.value)


# ----------------------------------------------------------------------
# Per-detector constructors
# ----------------------------------------------------------------------

def from_anomaly(result: DetectionResult, timestamp: float) -> Evidence:
    """
    Builds Evidence from an AnomalyDetector.predict() result.

    src_ip/dst_ip/dst_port are pulled from result.features, which
    works ONLY because main.py's per-flow loop currently passes the
    full feature dict (identity fields included) into predict() -
    anomaly.py's own IDENTITY_FIELDS set excludes them from the
    numeric vector handed to the model, but never deletes them from
    the dict itself. If a future refactor strips identity fields
    before calling predict() (e.g. to save memory), this will start
    silently returning None for all three - worth a quick check here
    rather than assuming it'll always hold.
    """
    features = result.features
    src_ip = features.get("src_ip")
    dst_ip = features.get("dst_ip")
    dst_port = features.get("dst_port")

    score_str = f"{result.score:.3f}" if result.score is not None else "N/A"
    reasoning = (
        "Still warming up - no baseline yet."
        if result.verdict.value == "WARMING_UP"
        else f"Isolation Forest score {score_str} against learned baseline."
    )

    return Evidence(
        evidence_id=str(uuid.uuid4()),
        detector=DetectorName.ANOMALY,
        timestamp=timestamp,
        verdict=_verdict_from(result.verdict),
        reasoning=reasoning,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        payload=result,
    )


def from_ddos(result: DDoSCheckResult, timestamp: float) -> Evidence:
    """
    Builds Evidence from a GlobalRateTracker.check() result.

    src_ip/dst_ip/dst_port are left as None - DDoS is, by design, an
    aggregate cross-source signal with no single source or
    destination to attribute it to. See module docstring.
    """
    return Evidence(
        evidence_id=str(uuid.uuid4()),
        detector=DetectorName.DDOS,
        timestamp=timestamp,
        verdict=_verdict_from(result.verdict),
        reasoning=(
            f"{result.total_flows_in_window} flows from "
            f"{result.distinct_sources_in_window} distinct sources "
            f"in a {result.window_seconds}s window."
        ),
        payload=result,
    )


def from_port_scan(result: PortScanCheckResult, timestamp: float) -> Evidence:
    """
    Builds Evidence from a PortScanTracker.check() result.

    dst_ip/dst_port are left as None - a scan is one-source-many-
    targets by definition, so there is no single destination to
    report. src_ip is the one identity field that genuinely exists
    here. See module docstring.
    """
    return Evidence(
        evidence_id=str(uuid.uuid4()),
        detector=DetectorName.PORT_SCAN,
        timestamp=timestamp,
        verdict=_verdict_from(result.verdict),
        reasoning=(
            f"{result.distinct_ports_in_window} distinct ports touched "
            f"across {result.distinct_targets_in_window} targets "
            f"in a {result.window_seconds}s window."
        ),
        src_ip=result.src_ip,
        payload=result,
    )


def from_brute_force(result: BruteForceResult, timestamp: float) -> Evidence:
    """
    Builds Evidence from a BruteForceTracker.check() result. This is
    the one detector with a full (src_ip, dst_ip, dst_port) triple
    available, since brute-force is inherently a specific-source-to-
    specific-service pattern.
    """
    return Evidence(
        evidence_id=str(uuid.uuid4()),
        detector=DetectorName.BRUTE_FORCE,
        timestamp=timestamp,
        verdict=_verdict_from(result.verdict),
        reasoning=(
            f"{result.attempts_in_window} attempts in "
            f"{result.window_seconds}s window "
            f"(offence #{result.repeat_offender_count})."
        ),
        src_ip=result.src_ip,
        dst_ip=result.dst_ip,
        dst_port=result.dst_port,
        payload=result,
    )


def from_llm(
    result: AnalysisResult,
    timestamp: float,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    dst_port: Optional[int] = None,
) -> Evidence:
    """
    Builds Evidence from an LLMAnalyser.analyse() result.

    Unlike the four trackers, AnalysisResult carries no identity
    fields and isn't a fresh detection at all - it's a confirmation
    (or non-confirmation) of a pattern the caller already suspects in
    a specific flow. The caller (pipeline/labeller.py) already has
    that flow's src_ip/dst_ip/dst_port in scope, so it must pass them
    through explicitly here rather than this function trying to infer
    them from nothing.

    Verdict mapping:
      - result.available is False (call failed/timed out/malformed
        response) -> UNAVAILABLE. Deliberately not NORMAL - an absent
        finding must never be read as a confirmed-clean verdict.
      - result.attack_type == "benign" -> NORMAL (the LLM looked at a
        flow that scored SUSPICIOUS elsewhere and concluded it's
        actually fine).
      - Any other known attack type -> ATTACK (the LLM is the
        confirmation step; if it names a specific attack type instead
        of "benign" or "unknown", that's Sentinel's highest-confidence
        signal, matching how pipeline/labeller.py already treats it
        for training-label purposes).
      - "unknown" -> SUSPICIOUS (the LLM engaged but couldn't
        determine a specific type - worth a second look, not a
        confirmed attack).
    """
    if not result.available:
        return Evidence(
            evidence_id=str(uuid.uuid4()),
            detector=DetectorName.LLM,
            timestamp=timestamp,
            verdict=EvidenceVerdict.UNAVAILABLE,
            reasoning=f"LLM analysis unavailable: {result.error}",
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            payload=result,
        )

    if result.attack_type == "benign":
        verdict = EvidenceVerdict.NORMAL
    elif result.attack_type == "unknown":
        verdict = EvidenceVerdict.SUSPICIOUS
    else:
        verdict = EvidenceVerdict.ATTACK

    reasoning = result.reasoning or f"LLM classified this flow as {result.attack_type}."

    return Evidence(
        evidence_id=str(uuid.uuid4()),
        detector=DetectorName.LLM,
        timestamp=timestamp,
        verdict=verdict,
        reasoning=reasoning,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        payload=result,
    )