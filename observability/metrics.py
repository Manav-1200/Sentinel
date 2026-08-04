"""
observability/metrics.py

Prometheus metrics — exposes Sentinel's operational and detection
counters/gauges/histograms over a standard /metrics endpoint, so a
real deployment can be scraped by Prometheus and graphed in Grafana
(or alerted on directly) instead of an operator having to tail
observability/structured_logger.py's JSON-lines output by hand to
know Sentinel is healthy.

Why this is a separate module from structured_logger.py, even though
both are "record what Sentinel just did":
--------------------------------------------------------------------
structured_logger.py answers "what happened, in order, with full
detail" (a durable, greppable event log - one line per event,
unbounded cardinality, meant for forensics). Prometheus metrics answer
a structurally different question: "what's the CURRENT rate/state of
things" (bounded-cardinality counters and gauges, meant for
dashboards/alerting, not for reconstructing individual events after
the fact - a Counter has no memory of any specific evidence_id).
Trying to serve both needs from one mechanism means compromising one
of them; keeping them separate lets each be exactly the right shape
for its own consumer (log shipper vs. Prometheus scraper).

Why labels are kept low-cardinality:
--------------------------------------------------------------------
Prometheus label values create a new time series per unique
combination - labelling by something unbounded (e.g. src_ip, evidence_id)
would make the metrics endpoint grow without bound and get slow/expensive
to scrape, defeating the purpose. Every label used below (detector,
verdict, risk tier, block action) comes from a small, fixed enum -
never a raw IP or free-text field. Anything that needs per-IP or
per-incident granularity belongs in structured_logger.py/the DB, not
here.

Mounting, not a separate server:
--------------------------------------------------------------------
mount_metrics(app) adds a /metrics route directly onto the SAME
FastAPI app api/app.py already builds (via prometheus_client's ASGI
app), rather than starting a second HTTP server on its own port. This
mirrors the reasoning that led api/app.py to take its CorrelationEngine
as a constructor argument rather than owning global state: one process,
one already-running server, one thing for an operator to point a
Prometheus scrape config at (SENTINEL_HOST:PORT/metrics) instead of
two ports to remember and firewall separately. Wiring main.py to
actually call mount_metrics() on the same app instance it hands to
uvicorn is a follow-up integration step - this module is built and
tested standalone first, matching how evidence.py/correlation_engine.py/
risk_engine.py/api/app.py were each introduced.

A metrics recording call must NEVER crash or slow the detection
pipeline - every record_* function below is a fire-and-forget
prometheus_client call (their Counter.inc()/Gauge.set()/
Histogram.observe() are all in-process, in-memory, and effectively
never raise under normal use, unlike a network-bound export like
CEFSyslogExporter) - but record_* functions still don't propagate
exceptions, for the same defensive reasoning cef_export.py and
structured_logger.py already apply to their own call sites.
"""

from __future__ import annotations

import threading
from typing import Optional

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    make_asgi_app,
)

from detection.correlation_engine import Incident
from detection.evidence import Evidence
from detection.risk_engine import RiskAssessment


class SentinelMetrics:
    """
    Holds every Prometheus collector Sentinel exposes, bound to one
    CollectorRegistry. Kept as an instance (not bare module-level
    globals) so tests can construct a fresh, isolated
    SentinelMetrics(registry=CollectorRegistry()) per test - the same
    reasoning observability/structured_logger.py's reset_for_tests()
    exists for, just solved with an explicit instance instead of a
    reset function, since prometheus_client's own Collector objects
    don't support being cleanly re-registered onto the default global
    registry more than once.
    """

    def __init__(self, registry: Optional[CollectorRegistry] = None):
        self.registry = registry if registry is not None else CollectorRegistry()

        # -- Evidence / detection activity --------------------------
        self.evidence_total = Counter(
            "sentinel_evidence_total",
            "Total Evidence objects filed, by detector and verdict.",
            ["detector", "verdict"],
            registry=self.registry,
        )

        self.flows_processed_total = Counter(
            "sentinel_flows_processed_total",
            "Total flows processed by the per-flow detection loop.",
            registry=self.registry,
        )

        self.packets_dropped_total = Counter(
            "sentinel_packets_dropped_total",
            "Total packets dropped by the capture layer (buffer overload).",
            registry=self.registry,
        )

        # -- Incidents / risk -----------------------------------------
        self.incidents_opened_total = Counter(
            "sentinel_incidents_opened_total",
            "Total incidents opened by the correlation engine.",
            registry=self.registry,
        )

        self.incidents_updated_total = Counter(
            "sentinel_incidents_updated_total",
            "Total times an existing incident received new evidence.",
            registry=self.registry,
        )

        self.incidents_open_current = Gauge(
            "sentinel_incidents_open_current",
            "Number of currently OPEN incidents.",
            registry=self.registry,
        )

        self.risk_score = Histogram(
            "sentinel_incident_risk_score",
            "Fused risk scores (0-100) as incidents are assessed.",
            buckets=[0, 10, 25, 40, 50, 65, 80, 90, 100],
            registry=self.registry,
        )

        self.risk_tier_assessments_total = Counter(
            "sentinel_risk_tier_assessments_total",
            "Total risk assessments performed, by resulting tier.",
            ["tier"],
            registry=self.registry,
        )

        # -- Response / blocking ---------------------------------------
        self.block_actions_total = Counter(
            "sentinel_block_actions_total",
            "Total block/unblock actions taken, by action and backend.",
            ["action", "backend"],
            registry=self.registry,
        )

        self.blocked_ips_current = Gauge(
            "sentinel_blocked_ips_current",
            "Number of source IPs currently blocked.",
            registry=self.registry,
        )

        # -- LLM analyser -----------------------------------------------
        self.llm_calls_total = Counter(
            "sentinel_llm_calls_total",
            "Total LLM analysis calls, by outcome.",
            ["outcome"],  # success | failed | retried
            registry=self.registry,
        )

        # -- SIEM / export health ----------------------------------------
        self.cef_export_total = Counter(
            "sentinel_cef_export_total",
            "Total CEF events exported, by granularity and outcome.",
            ["granularity", "outcome"],  # evidence|incident, sent|failed
            registry=self.registry,
        )

        self._lock = threading.Lock()


_singleton_lock = threading.Lock()
_singleton: Optional[SentinelMetrics] = None


def get_metrics(registry: Optional[CollectorRegistry] = None) -> SentinelMetrics:
    """
    Returns the shared SentinelMetrics singleton, constructing it on
    first call - mirrors structured_logger.get_structured_logger()'s
    idempotent singleton pattern, so main.py/labeller.py/response
    call sites can all call this freely without worrying about
    duplicate collector registration (which prometheus_client raises
    on if the same metric name is registered twice against the same
    registry).

    `registry` is only respected on the FIRST call in a process -
    later calls ignore it and return the already-built singleton, same
    caveat get_structured_logger() has for its config argument. Tests
    that need an isolated registry should construct SentinelMetrics(...)
    directly rather than going through this singleton accessor.
    """
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = SentinelMetrics(registry=registry)
        return _singleton


def reset_for_tests() -> None:
    """Test-only: clears the singleton, mirroring
    structured_logger.reset_for_tests()."""
    global _singleton
    with _singleton_lock:
        _singleton = None


def mount_metrics(app, metrics: Optional[SentinelMetrics] = None) -> None:
    """
    Mounts a /metrics ASGI app onto an existing FastAPI app (the same
    instance api/app.py's create_app() returns), for Prometheus to
    scrape. See module docstring for why this mounts onto the existing
    app rather than starting a second server.
    """
    if metrics is None:
        metrics = get_metrics()
    app.mount("/metrics", make_asgi_app(registry=metrics.registry))


# ----------------------------------------------------------------------
# record_* helpers - fire-and-forget, never raise. Mirrors the
# call-site shape of observability/structured_logger.py's log_*
# functions and observability/cef_export.py's _safe_send(), so a
# caller wiring all three observability outputs into one call site
# (e.g. Labeller.store_evidence()) can call them identically.
# ----------------------------------------------------------------------

def record_evidence(metrics: SentinelMetrics, evidence: Evidence) -> None:
    try:
        metrics.evidence_total.labels(
            detector=evidence.detector.value, verdict=evidence.verdict.value
        ).inc()
    except Exception:
        pass


def record_flow_processed(metrics: SentinelMetrics) -> None:
    try:
        metrics.flows_processed_total.inc()
    except Exception:
        pass


def record_packets_dropped(metrics: SentinelMetrics, count: int = 1) -> None:
    try:
        metrics.packets_dropped_total.inc(count)
    except Exception:
        pass


def record_incident_event(metrics: SentinelMetrics, incident: Incident, is_new: bool) -> None:
    """Mirrors structured_logger.log_incident_event()'s is_new
    convention - see that function's docstring for how callers
    determine is_new."""
    try:
        if is_new:
            metrics.incidents_opened_total.inc()
        else:
            metrics.incidents_updated_total.inc()
    except Exception:
        pass


def set_incidents_open_current(metrics: SentinelMetrics, count: int) -> None:
    """
    Gauges must be explicitly SET, not incremented, since incidents
    can also resolve (decreasing the count) - unlike the Counters
    above, which only ever go up. Callers should pass
    len(correlation_engine.open_incidents()) periodically (e.g. the
    same cadence as the CLI's existing summary line), not on every
    single evidence event, to avoid the lock contention a Gauge.set()
    on every flow would add for a number that only needs to be
    approximately current.
    """
    try:
        metrics.incidents_open_current.set(count)
    except Exception:
        pass


def record_risk_assessment(metrics: SentinelMetrics, risk: RiskAssessment) -> None:
    try:
        metrics.risk_score.observe(risk.score)
        metrics.risk_tier_assessments_total.labels(tier=risk.tier.value).inc()
    except Exception:
        pass


def record_block_action(metrics: SentinelMetrics, action: str, backend: str) -> None:
    """`action` should be "block" or "unblock"; `backend` should be
    "nftables" or "iptables" - matching response/blocker.py's own
    backend-selection vocabulary."""
    try:
        metrics.block_actions_total.labels(action=action, backend=backend).inc()
    except Exception:
        pass


def set_blocked_ips_current(metrics: SentinelMetrics, count: int) -> None:
    try:
        metrics.blocked_ips_current.set(count)
    except Exception:
        pass


def record_llm_call(metrics: SentinelMetrics, outcome: str) -> None:
    """`outcome` should be one of "success", "failed", "retried" -
    matching detection/llm_analyser.py's own AnalysisConfidence/retry
    vocabulary."""
    try:
        metrics.llm_calls_total.labels(outcome=outcome).inc()
    except Exception:
        pass


def record_cef_export(metrics: SentinelMetrics, granularity: str, outcome: str) -> None:
    """`granularity` should be "evidence" or "incident"; `outcome`
    should be "sent" or "failed" - matching
    observability/cef_export.py's two export functions and its
    _safe_send()'s try/except boundary."""
    try:
        metrics.cef_export_total.labels(granularity=granularity, outcome=outcome).inc()
    except Exception:
        pass