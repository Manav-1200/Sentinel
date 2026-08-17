"""
api/app.py

REST API over Sentinel's incidents - what the dashboard talks to
instead of reaching into SQLite/CorrelationEngine directly. Built
before the dashboard so the dashboard is a real API client from day
one.

FastAPI: auto-generates Swagger docs at /docs, useful as a free test
client while there's no other API tooling yet.

create_app(correlation_engine) takes the engine as a constructor arg
rather than a global, so (1) tests can build an isolated engine and
populate known Evidence, and (2) there must be exactly one
CorrelationEngine per process - main.py's capture loop and
labeller.py already share one; constructing a second here would
silently show an always-empty engine.

NOTE: for the API to reflect real-time incidents it must run in the
same process as the capture loop (e.g. uvicorn on a background thread
from main.py), sharing the live engine - this module only builds the
API itself; wiring it into main.py is separate.
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
    """Lighter than IncidentDetailOut (no evidence list) - a list view
    needs an at-a-glance summary, not everything."""
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
    """Summary plus the full evidence timeline, for the detail view."""
    evidence: list[EvidenceOut]


class ActionResult(BaseModel):
    incident_id: str
    key: str
    status: str


class SummaryOut(BaseModel):
    """GET /summary's headline numbers in one call, instead of a
    client fetching every incident to locally aggregate three counts."""
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
    require_auth: gates every route but /health behind the X-API-Key
    check (api/auth.py). Defaults True - only tests/local dev without
    SENTINEL_API_KEY should pass False; main.py's real wiring never should.
    Should mirror config.yaml's api.require_auth, not be hardcoded.

    blocker: optional IPBlocker, used only by /summary for
    blocked_ip_count. Typed `object` (not imported directly) so this
    module stays importable without pulling in nftables/iptables
    subprocess plumbing. None -> blocked_ip_count reports 0, which is
    expected for pcap-replay/test runs with no live blocker.
    """
    app = FastAPI(
        title="Sentinel Incidents API",
        description="Read-only incident/evidence access, plus resolve/reopen actions.",
        version="0.1.0",
    )

    # Applied per-route (not app-wide) so /health can stay exempt.
    auth_deps = [require_auth_dependency] if require_auth else []

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/summary", response_model=SummaryOut, dependencies=auth_deps)
    def summary():
        """risk_tier_breakdown only counts OPEN incidents, keyed by
        every RiskTier value (0 for tiers with none) so clients never
        need to handle a missing key."""
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
        """Only OPEN by default - pass ?include_resolved=true for full history."""
        incidents = correlation_engine.all_incidents() if include_resolved else correlation_engine.open_incidents()
        return [_to_summary(i, assess_risk(i)) for i in incidents]

    @app.get("/incidents/{key}", response_model=IncidentDetailOut, dependencies=auth_deps)
    def get_incident(key: str):
        """`key` is the src_ip an incident is grouped on, or
        "__aggregate__" for the DDoS bucket (see correlation_engine.py)."""
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