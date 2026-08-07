"""
api/app.py

Read-only-plus-actions REST API over Sentinel's incidents - the layer
the future dashboard will actually talk to, instead of reaching into
SQLite or the in-memory CorrelationEngine directly. Built now,
deliberately BEFORE the dashboard, so the dashboard is a client of a
real API from day one rather than something built against direct DB
access that then has to be redone once an API exists anyway.

Why FastAPI:
------------
Auto-generates interactive API docs (Swagger UI at /docs) directly
from the type hints and Pydantic models below - genuinely useful here
specifically because there's no API experience to lean on yet: the
docs UI becomes a working test client with zero extra code.

Why the CorrelationEngine is a constructor argument, not a global:
--------------------------------------------------------------------
create_app(correlation_engine) takes the engine as a parameter rather
than importing/constructing one internally, for two reasons:
  1. Testability - tests can build a CorrelationEngine, populate it
     with known Evidence, and test the API against that exact state,
     with no need to spin up a real capture pipeline.
  2. Correctness - there must be exactly ONE CorrelationEngine per
     running Sentinel process (the same one main.py's per-flow loop
     and pipeline/labeller.py's store_evidence() already share - see
     detection/correlation_engine.py and pipeline/labeller.py). If
     this module constructed its own engine internally, the API would
     silently see a DIFFERENT, always-empty engine instead of the
     live one main.py is actually populating.

IMPORTANT - deployment assumption not yet wired into main.py:
--------------------------------------------------------------------
For the API to reflect real-time incidents, it must run IN THE SAME
PROCESS as the capture loop, sharing the actual live CorrelationEngine
object (e.g. started in a background thread from run_live_capture/
run_pcap) - NOT as a separate process reading a stale snapshot. That
wiring (starting uvicorn alongside the capture loop) is intentionally
NOT done in this file - this module only builds the API itself,
testable in isolation. Wiring main.py to actually launch it is a
follow-up integration step, same pattern as evidence.py/
correlation_engine.py/risk_engine.py were each built and tested
standalone before being wired in.
"""

from __future__ import annotations

from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from api.auth import require_auth_dependency
from detection.correlation_engine import CorrelationEngine, IncidentStatus
from detection.risk_engine import assess as assess_risk, RiskTier
from detection.timeline import build_timeline


class EvidenceOut(BaseModel):
    evidence_id: str
    detector: str
    timestamp: float
    verdict: str
    reasoning: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None


class RiskOut(BaseModel):
    score: int
    tier: str
    contributing_detectors: list[str]
    explanation: str


class IncidentSummaryOut(BaseModel):
    """Shape returned by the list endpoint - deliberately lighter than
    IncidentDetailOut (no full evidence list) since a dashboard's
    incident list view needs an at-a-glance summary, not everything."""
    incident_id: str
    key: str
    status: str
    first_seen: float
    last_seen: float
    highest_verdict: str
    detectors_involved: list[str]
    evidence_count: int
    risk: RiskOut


class IncidentDetailOut(IncidentSummaryOut):
    """Everything in the summary, plus the full evidence timeline -
    what a dashboard's single-incident detail view actually needs."""
    evidence: list[EvidenceOut]


class ActionResult(BaseModel):
    incident_id: str
    key: str
    status: str


class SummaryOut(BaseModel):
    """Shape for GET /summary - a dashboard's top-level headline
    numbers in one call, instead of fetching and locally aggregating
    every incident just to show three counts. See PHASES.md Phase
    4.1' - built specifically so detection/tui_dashboard.py's top
    panel doesn't need incident-list-shaped data at all."""
    open_incident_count: int
    risk_tier_breakdown: dict[str, int]
    blocked_ip_count: int


def _to_summary(incident, risk) -> IncidentSummaryOut:
    return IncidentSummaryOut(
        incident_id=incident.incident_id,
        key=incident.key,
        status=incident.status.value,
        first_seen=incident.first_seen,
        last_seen=incident.last_seen,
        highest_verdict=incident.highest_verdict.value,
        detectors_involved=sorted(incident.detectors_involved),
        evidence_count=len(incident.evidence),
        risk=RiskOut(
            score=risk.score, tier=risk.tier.value,
            contributing_detectors=risk.contributing_detectors,
            explanation=risk.explanation,
        ),
    )


def create_app(
    correlation_engine: CorrelationEngine,
    require_auth: bool = True,
    blocker: object = None,
) -> FastAPI:
    """
    Builds the FastAPI app wired to a specific CorrelationEngine
    instance. See module docstring for why the engine is injected
    rather than constructed here.

    require_auth: gates every route except /health behind the
    X-API-Key check in api/auth.py. Defaults to True - a deployment
    has to deliberately opt OUT of auth, not opt in. Set False only
    for tests/local dev that construct their own CorrelationEngine
    and don't want to fuss with SENTINEL_API_KEY - main.py's real
    wiring should never pass False. See config.yaml's `api:` section
    - this should mirror `api.require_auth` from config, not be
    hardcoded at the call site.

    blocker: optional response.blocker.IPBlocker instance, used only
    by GET /summary for blocked_ip_count. Typed as `object` rather
    than importing IPBlocker directly - response/blocker.py pulls in
    nftables/iptables subprocess plumbing that has no business being
    an import-time dependency of the API module, which needs to stay
    importable (e.g. for tests, or a future read-only API-only
    deployment) even somewhere blocker.py's system calls wouldn't
    work. Left None, /summary reports blocked_ip_count as 0 rather
    than failing - see that route's docstring.
    """
    app = FastAPI(
        title="Sentinel Incidents API",
        description="Read-only incident/evidence access, plus resolve/reopen actions.",
        version="0.1.0",
    )

    # Applied per-route below rather than as a single app-wide
    # dependency, specifically so /health can stay exempt (see
    # api/auth.py's module docstring for why).
    auth_deps = [require_auth_dependency] if require_auth else []

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/summary", response_model=SummaryOut, dependencies=auth_deps)
    def summary():
        """
        Headline numbers for a dashboard's top-level view - see
        SummaryOut's docstring for why this exists as its own route
        instead of making every client fetch /incidents and aggregate
        it locally.

        risk_tier_breakdown only counts OPEN incidents (a resolved
        incident's risk tier isn't part of "what's the state of things
        right now"), keyed by RiskTier's string values so every tier
        is always present in the response (0 for tiers with no open
        incidents) rather than a client having to handle a
        possibly-missing key.

        blocked_ip_count is 0 if this app was built without a blocker
        (blocker=None) - see create_app's docstring. Not an error
        condition: a pcap-replay run or a test harness legitimately
        has no live blocker to report on.
        """
        open_incidents = correlation_engine.open_incidents()

        tier_breakdown = {tier.value: 0 for tier in RiskTier}
        for incident in open_incidents:
            tier_breakdown[assess_risk(incident).tier.value] += 1

        blocked_ip_count = len(blocker.currently_blocked()) if blocker is not None else 0

        return SummaryOut(
            open_incident_count=len(open_incidents),
            risk_tier_breakdown=tier_breakdown,
            blocked_ip_count=blocked_ip_count,
        )

    @app.get("/incidents", response_model=list[IncidentSummaryOut], dependencies=auth_deps)
    def list_incidents(include_resolved: bool = False):
        """
        Lists incidents. By default only OPEN incidents (the common
        case - "what's actively going on right now") - pass
        ?include_resolved=true for the full history.
        """
        incidents = correlation_engine.all_incidents() if include_resolved else correlation_engine.open_incidents()
        return [_to_summary(i, assess_risk(i)) for i in incidents]

    @app.get("/incidents/{key}", response_model=IncidentDetailOut, dependencies=auth_deps)
    def get_incident(key: str):
        """
        Full detail for one incident - `key` is the src_ip an incident
        is grouped on, or the literal string "__aggregate__" for the
        one permanent DDoS bucket (see correlation_engine.py's
        AGGREGATE_KEY).
        """
        incident = correlation_engine.get_incident(key)
        if incident is None:
            raise HTTPException(status_code=404, detail=f"No incident found for key '{key}'")

        risk = assess_risk(incident)
        summary = _to_summary(incident, risk)
        timeline = build_timeline(incident)
        return IncidentDetailOut(
            **summary.model_dump(),
            evidence=[
                EvidenceOut(
                    evidence_id=e.evidence.evidence_id,
                    detector=e.detector,
                    timestamp=e.timestamp,
                    verdict=e.verdict,
                    reasoning=e.reasoning,
                    src_ip=e.src_ip,
                    dst_ip=e.dst_ip,
                    dst_port=e.dst_port,
                )
                for e in timeline
            ],
        )

    @app.post("/incidents/{key}/resolve", response_model=ActionResult, dependencies=auth_deps)
    def resolve_incident(key: str):
        incident = correlation_engine.resolve(key)
        if incident is None:
            raise HTTPException(status_code=404, detail=f"No incident found for key '{key}'")
        return ActionResult(incident_id=incident.incident_id, key=incident.key, status=incident.status.value)

    @app.post("/incidents/{key}/reopen", response_model=ActionResult, dependencies=auth_deps)
    def reopen_incident(key: str):
        incident = correlation_engine.reopen(key)
        if incident is None:
            raise HTTPException(status_code=404, detail=f"No incident found for key '{key}'")
        return ActionResult(incident_id=incident.incident_id, key=incident.key, status=incident.status.value)

    return app