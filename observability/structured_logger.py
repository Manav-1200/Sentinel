"""
observability/structured_logger.py

Structured, machine-readable event logging - one JSON object per line,
written alongside (not instead of) the existing Rich-console CLI
output. This is the foundation the next few items depend on: SIEM
export needs real structured events to translate into CEF/syslog, and
the eventual REST API/dashboard both want a durable, greppable record
of what Sentinel has actually done, independent of whatever's
currently on an operator's terminal.

Why JSON-lines, not a custom text format:
--------------------------------------------------------------------
One JSON object per line is trivially parseable by any log shipper
(Filebeat, Fluentd, a simple `jq` pipeline) without Sentinel needing
to know anything about the consumer - this is the same reasoning that
makes CEF/syslog a sane SIEM export target later: emit a widely-
understood format, don't invent a bespoke one that only Sentinel's own
tooling can read.

Why this lives in its own `observability` package, not inside
detection/ or pipeline/:
--------------------------------------------------------------------
Structured logging is a cross-cutting concern - the same event logger
gets called from detection/correlation_engine.py (incident lifecycle),
pipeline/labeller.py (evidence creation), and eventually response/
(block/unblock actions). Putting it inside any one of those packages
would make the others import "sideways" across package boundaries for
no good reason; a small top-level `observability` package avoids that.

What gets logged (v1 scope):
--------------------------------------------------------------------
  - evidence_created: every Evidence object, the moment
    Labeller.store_evidence() persists it - mirrors exactly what's
    already going into the `evidence` DB table, just also emitted as a
    log line for anything that wants to tail Sentinel's activity
    without querying SQLite.
  - incident_opened / incident_updated: fired from the same
    store_evidence() call site, based on whether the Evidence just
    filed started a brand-new Incident or attached to an existing one.

Incident resolve/reopen logging isn't wired yet - there's no caller of
CorrelationEngine.resolve()/reopen() yet (that's a future CLI/response-
layer action), so there's nothing real to hook into today. Worth
revisiting once that exists, rather than logging a made-up call site
now.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import threading
import time
from typing import Optional

from detection.evidence import Evidence
from detection.correlation_engine import Incident


class _JSONLinesFormatter(logging.Formatter):
    """
    Renders each log record as one JSON object per line. Only the
    structured `event` dict (passed via `extra={"event": {...}}` at
    the call site) is emitted - the standard logging boilerplate
    (logger name, level name as a Python concept, etc.) is intentionally
    NOT included, since every event already carries its own explicit
    `event_type` and `timestamp` fields that mean something to a log
    consumer, unlike Python's internal logging metadata.
    """

    def format(self, record: logging.LogRecord) -> str:
        event = getattr(record, "event", None)
        if event is None:
            # A record without a structured event was logged through
            # this logger by mistake (e.g. a stray logger.info(str)
            # call) - fail loudly in the log itself rather than
            # silently dropping or crashing the whole logging pipeline.
            event = {
                "event_type": "malformed_log_record",
                "timestamp": time.time(),
                "message": record.getMessage(),
            }
        return json.dumps(event, default=str)


_lock = threading.Lock()
_logger: Optional[logging.Logger] = None


def get_structured_logger(config: dict) -> logging.Logger:
    """
    Returns the shared structured-event logger, configuring it on
    first call. Idempotent - safe to call from multiple places
    (main.py, labeller.py, correlation_engine.py) without creating
    duplicate handlers, mirroring the singleton pattern already used
    for other cross-cutting config-driven setup in Sentinel.

    Config keys (all under a `logging:` section, all with fallback
    defaults so this works even before config.yaml is updated):
      structured_log_path (str): where to write JSON-lines events.
        Default: "logs/sentinel_events.jsonl"
      max_bytes (int): rotate after this many bytes. Default: 10 MB.
      backup_count (int): how many rotated files to keep. Default: 5.
        (This is a stopgap, not the full retention-policy item still
        on the roadmap - it bounds disk usage for THIS log file
        specifically, it doesn't address the SQLite DB's unbounded
        growth, which is a separate, larger piece of work.)
    """
    global _logger
    with _lock:
        if _logger is not None:
            return _logger

        log_config = config.get("logging", {})
        log_path = log_config.get("structured_log_path", "logs/sentinel_events.jsonl")
        max_bytes = int(log_config.get("max_bytes", 10 * 1024 * 1024))
        backup_count = int(log_config.get("backup_count", 5))

        log_dir = os.path.dirname(log_path)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

        logger = logging.getLogger("sentinel.events")
        logger.setLevel(logging.INFO)
        logger.propagate = False  # never bubble into the root logger / console output

        handler = logging.handlers.RotatingFileHandler(
            log_path, maxBytes=max_bytes, backupCount=backup_count
        )
        handler.setFormatter(_JSONLinesFormatter())
        logger.addHandler(handler)

        _logger = logger
        return _logger


def _emit(logger: logging.Logger, event_type: str, **fields) -> None:
    event = {"event_type": event_type, "timestamp": time.time(), **fields}
    logger.info("", extra={"event": event})


def log_evidence_created(logger: logging.Logger, evidence: Evidence) -> None:
    """Logs one evidence_created event. Called from Labeller.store_evidence()."""
    _emit(
        logger,
        "evidence_created",
        evidence_id=evidence.evidence_id,
        detector=evidence.detector.value,
        verdict=evidence.verdict.value,
        src_ip=evidence.src_ip,
        dst_ip=evidence.dst_ip,
        dst_port=evidence.dst_port,
        reasoning=evidence.reasoning,
        evidence_timestamp=evidence.timestamp,
    )


def log_incident_event(logger: logging.Logger, incident: Incident, is_new: bool) -> None:
    """
    Logs either incident_opened (is_new=True) or incident_updated
    (is_new=False). Called from Labeller.store_evidence() right after
    CorrelationEngine.add_evidence() returns - see that call site for
    how `is_new` is determined (a heuristic, not a first-class return
    value from the engine - see structured_logger.py's module
    docstring for why that's an acceptable tradeoff for a logging-only
    concern).
    """
    _emit(
        logger,
        "incident_opened" if is_new else "incident_updated",
        incident_id=incident.incident_id,
        key=incident.key,
        status=incident.status.value,
        highest_verdict=incident.highest_verdict.value,
        detectors_involved=sorted(incident.detectors_involved),
        evidence_count=len(incident.evidence),
    )


def log_incident_resolved(logger: logging.Logger, incident: Incident) -> None:
    """Not yet called anywhere - see module docstring's scope note. Provided now so
    the future CLI/response-layer resolve() action has a ready-made call site."""
    _emit(
        logger,
        "incident_resolved",
        incident_id=incident.incident_id,
        key=incident.key,
        highest_verdict=incident.highest_verdict.value,
        evidence_count=len(incident.evidence),
    )


def reset_for_tests() -> None:
    """
    Test-only: clears the singleton so each test gets a fresh logger
    pointed at its own tmp_path log file, instead of every test in a
    run sharing whatever the FIRST test configured.
    """
    global _logger
    with _lock:
        if _logger is not None:
            for handler in list(_logger.handlers):
                _logger.removeHandler(handler)
                handler.close()
        _logger = None