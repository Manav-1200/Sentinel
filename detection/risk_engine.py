"""
detection/risk_engine.py

Unified Risk Engine — fuses an Incident's accumulated Evidence (from
however many of the five detectors flagged it) into one risk score
(0-100, for the future dashboard) and one risk tier (LOW/MEDIUM/HIGH/
CRITICAL, for the TUI), instead of an operator having to mentally
combine five different verdicts themselves.

Why "disagreement" barely exists as a case to solve, and why that
constrains this design:
--------------------------------------------------------------------
correlation_engine.py already filters NORMAL/WARMING_UP evidence
before it can ever attach to an incident (see its module docstring).
That means a "benign" LLM verdict for a flow never actually reaches an
incident's evidence list to argue AGAINST an anomaly detector's
ATTACK finding on the same source - it's discarded upstream, not
weighed against it here. This is a real, worth-naming limitation: this
engine cannot currently down-weight an incident based on
counter-evidence it never sees. Fixing that would mean changing what
the correlation engine attaches, not this engine's fusion math - noted
here rather than silently assumed away.

What genuine disagreement DOES look like, given that constraint, is
SEVERITY disagreement between detectors that all flagged something:
anomaly (a statistical Isolation Forest score, acknowledged elsewhere
in Sentinel as the weakest, most false-positive-prone signal - it's
the whole reason the LLM confirmation step exists) saying SUSPICIOUS,
while brute_force or port_scan (deterministic, rule-based threshold
crossings - by design not run through LLM confirmation because
there's nothing uncertain to confirm) says ATTACK on the same source.

Fusion approach:
------------------
1. Group the incident's evidence by detector, and take each detector's
   own WORST verdict only - not a sum across every repeated check.
   Without this, a brute_force tracker re-confirming an ongoing ATTACK
   on every single check() call would let ONE noisy detector inflate
   the score arbitrarily just by firing more often, which would make
   the score reflect polling frequency instead of genuine severity.
2. Weight each detector's contribution by DETECTOR_TRUST_WEIGHT -
   deterministic trackers (ddos/port_scan/brute_force) are trusted at
   face value (weight 1.0); anomaly is trusted less (weight 0.5) since
   it's a statistical guess, not a rule-based threshold; llm is
   trusted MOST (weight 1.2) when it names a real attack type,
   mirroring the exact same "LLM confirmation is Sentinel's
   highest-confidence signal" reasoning pipeline/labeller.py already
   uses for its own SUSPICIOUS-to-ATTACK promotion logic - this engine
   is consistent with a precedent that already exists in the
   codebase, not inventing a new one.
3. Add a corroboration bonus scaled by how many DISTINCT detectors
   contributed - independent detectors agreeing on the same source is
   exactly the signal an attacker can't easily fake by tuning against
   any one detector, and is the entire reason correlation exists in
   the first place. One detector alone gets no bonus; each additional
   distinct detector adds further confidence.
4. Sum, cap at 100, map to a tier.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from detection.correlation_engine import Incident
from detection.evidence import EvidenceVerdict


class RiskTier(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# How much each detector's finding is trusted, before severity is even
# considered. See module docstring point 2 for the reasoning behind
# each individual weight.
DETECTOR_TRUST_WEIGHT = {
    "ddos": 1.0,
    "port_scan": 1.0,
    "brute_force": 1.0,
    "anomaly": 0.5,
    "llm": 1.2,
}

# Points contributed by a detector's worst verdict, before its trust
# weight is applied. UNAVAILABLE contributes 0 - an absent finding
# adds no risk, it just means one fewer detector corroborated.
VERDICT_POINTS = {
    EvidenceVerdict.SUSPICIOUS: 15,
    EvidenceVerdict.ATTACK: 30,
    EvidenceVerdict.UNAVAILABLE: 0,
}

# Bonus added per ADDITIONAL distinct detector beyond the first that
# contributed non-zero points - see module docstring point 3. Two
# corroborating detectors is already a meaningfully stronger signal
# than one; a third makes it stronger still.
CORROBORATION_BONUS_PER_EXTRA_DETECTOR = 10

# Score thresholds mapping to each tier - upper bound inclusive.
_TIER_THRESHOLDS = [
    (24, RiskTier.LOW),
    (49, RiskTier.MEDIUM),
    (79, RiskTier.HIGH),
    (100, RiskTier.CRITICAL),
]


@dataclass
class RiskAssessment:
    """
    The fused output for one Incident - a numeric score for the future
    dashboard, and a coarser tier for the TUI/CLI, plus enough detail
    (contributing_detectors, explanation) that an operator can see WHY
    the score landed where it did, not just the number itself.
    """
    score: int
    tier: RiskTier
    contributing_detectors: list = field(default_factory=list)  # detector names that scored > 0
    explanation: str = ""


def _tier_for_score(score: int) -> RiskTier:
    for upper_bound, tier in _TIER_THRESHOLDS:
        if score <= upper_bound:
            return tier
    return RiskTier.CRITICAL  # unreachable given the table ends at 100, but safe


def assess(incident: Incident) -> RiskAssessment:
    """
    Fuses an Incident's evidence into one RiskAssessment. Safe to call
    on an incident with no evidence at all (returns score=0, LOW) -
    shouldn't happen in practice since correlation_engine never creates
    an incident without at least one qualifying Evidence, but this
    stays defensive rather than assuming that invariant always holds.
    """
    worst_verdict_per_detector: dict[str, EvidenceVerdict] = {}
    for evidence in incident.evidence:
        detector = evidence.detector.value
        current_worst = worst_verdict_per_detector.get(detector)
        if current_worst is None or (
            VERDICT_POINTS[evidence.verdict] > VERDICT_POINTS[current_worst]
        ):
            worst_verdict_per_detector[detector] = evidence.verdict

    contributing_detectors = []
    raw_total = 0.0
    for detector, verdict in worst_verdict_per_detector.items():
        points = VERDICT_POINTS[verdict]
        if points <= 0:
            continue  # UNAVAILABLE - contributes nothing, doesn't count toward corroboration
        weight = DETECTOR_TRUST_WEIGHT.get(detector, 1.0)
        raw_total += points * weight
        contributing_detectors.append(detector)

    if contributing_detectors:
        corroboration_bonus = (
            (len(contributing_detectors) - 1) * CORROBORATION_BONUS_PER_EXTRA_DETECTOR
        )
        raw_total += corroboration_bonus

    score = int(min(100, round(raw_total)))
    tier = _tier_for_score(score)

    if not contributing_detectors:
        explanation = "No corroborating evidence contributed to this score."
    else:
        explanation = (
            f"{len(contributing_detectors)} detector(s) corroborating "
            f"({', '.join(sorted(contributing_detectors))})."
        )

    return RiskAssessment(
        score=score,
        tier=tier,
        contributing_detectors=sorted(contributing_detectors),
        explanation=explanation,
    )