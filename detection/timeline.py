"""
detection/timeline.py

Per-incident detection timeline — a thin presentation layer over
Incident.evidence, which is already chronological (Evidence is appended
in arrival order by CorrelationEngine.add_evidence, never reordered or
sorted after the fact). There's no new tracking logic here; this
module exists so the CLI display (and later, the dashboard) has one
shared, tested rendering path instead of each caller re-implementing
"walk incident.evidence and format each entry" slightly differently.

Two output shapes are provided:
  - TimelineEntry / build_timeline(): a structured list, for the future
    dashboard to render however it wants (e.g. a vertical stepper UI).
  - render_timeline_text(): a plain-text rendering, for the CLI/TUI,
    which already prints scrolling per-flow output and needs something
    it can just print() directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from detection.correlation_engine import Incident
from detection.evidence import Evidence


@dataclass
class TimelineEntry:
    """
    One line of an incident's story - deliberately just a thin,
    display-oriented wrapper around the underlying Evidence, not a new
    data model. `evidence` is kept attached (not flattened away) so a
    consumer that needs more detail than the summary line can still
    get at the original Evidence.payload.
    """
    timestamp: float
    detector: str
    verdict: str
    reasoning: str
    src_ip: str | None
    dst_ip: str | None
    dst_port: int | None
    evidence: Evidence


def build_timeline(incident: Incident) -> list[TimelineEntry]:
    """
    Returns the incident's evidence as a list of TimelineEntry, oldest
    first. Incident.evidence is already in arrival order (see module
    docstring) - this does NOT re-sort by timestamp, since detector
    check() calls and flow.last_seen values are not perfectly
    synchronised across trackers, and arrival order (the order Sentinel
    actually observed and acted on each finding) is more meaningful for
    an operator reading a timeline than a timestamp-sorted
    reconstruction would be.
    """
    return [
        TimelineEntry(
            timestamp=e.timestamp,
            detector=e.detector.value,
            verdict=e.verdict.value,
            reasoning=e.reasoning,
            src_ip=e.src_ip,
            dst_ip=e.dst_ip,
            dst_port=e.dst_port,
            evidence=e,
        )
        for e in incident.evidence
    ]


def _format_timestamp(ts: float) -> str:
    """
    Renders a flow timestamp as human-readable UTC. Flow timestamps
    are epoch seconds (flow.last_seen) whether from live capture or
    pcap replay - see evidence.py's module docstring on why every
    Evidence is timestamped this way rather than with time.time().
    """
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def render_timeline_text(incident: Incident) -> str:
    """
    Plain-text, human-readable rendering of an incident's timeline -
    for the CLI/TUI to print() directly. One line per TimelineEntry,
    oldest first, in the form:

        [2026-07-24 14:03:11 UTC] port_scan  ATTACK     10.0.0.66 -> ? (25 ports across 10 targets in 10.0s window.)

    dst_ip/dst_port render as "?" when the underlying detector has no
    single destination to report (ddos, port_scan) - see evidence.py's
    module docstring for exactly which detectors leave those fields
    None and why that's real information, not a gap.
    """
    if not incident.evidence:
        return f"Incident {incident.key}: no evidence recorded."

    lines = [
        f"Incident {incident.incident_id} ({incident.key}) — "
        f"status={incident.status.value}, highest_verdict={incident.highest_verdict.value}"
    ]
    for entry in build_timeline(incident):
        dst = f"{entry.dst_ip or '?'}:{entry.dst_port if entry.dst_port is not None else '?'}"
        src = entry.src_ip or "?"
        lines.append(
            f"  [{_format_timestamp(entry.timestamp)}] "
            f"{entry.detector:<12} {entry.verdict:<10} "
            f"{src} -> {dst}  ({entry.reasoning})"
        )
    return "\n".join(lines)