"""
reporting/incident_report.py

Incident report export — turns Incidents (plus their already-computed
RiskAssessment and MITRE technique tags) into two output formats a
human or a compliance process can actually use:

  - CSV: one row per incident (summary) or one row per Evidence
    (forensic detail) - for spreadsheets, ticketing system imports,
    or feeding into yet another tool that isn't a SIEM.
  - Markdown text report: a readable "case file" for one incident, or
    a one-page summary across many - for handoff to a person (an
    auditor, a manager, a teammate) rather than another system.

Why Markdown instead of a real PDF:
--------------------------------------------------------------------
Generating an actual PDF (via e.g. reportlab or a headless browser)
is real infrastructure weight - a new heavy dependency, layout code,
font handling - for a benefit Markdown already delivers: it's human-
readable as-is, renders cleanly in GitHub/GitLab/most wikis, converts
to PDF trivially with existing tools (pandoc, or Sentinel's own docx
skill if a Word doc is ever specifically needed) if someone actually
needs a PDF for a specific handoff, and is trivially diffable/
version-controllable, unlike a binary PDF. If a real bundled PDF
becomes a hard requirement later, generating one FROM this Markdown
is a much smaller step than building PDF generation from scratch here
first.

Both CSV and Markdown functions take already-computed RiskAssessment/
MitreTechnique inputs rather than recomputing them internally - this
mirrors risk_engine.py's own "on-demand, caller controls when" design
note, and keeps this module a pure rendering layer with no detection
logic of its own.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone

from detection.correlation_engine import Incident, AGGREGATE_KEY
from detection.risk_engine import RiskAssessment, assess
from detection.mitre_attack import get_techniques_for_incident as techniques_for_incident
from detection.timeline import render_timeline_text


def _format_timestamp(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ----------------------------------------------------------------------
# CSV export
# ----------------------------------------------------------------------

_INCIDENT_CSV_COLUMNS = [
    "incident_id", "source", "status", "risk_score", "risk_tier",
    "highest_verdict", "detectors_involved", "mitre_techniques",
    "evidence_count", "first_seen", "last_seen",
]

_EVIDENCE_CSV_COLUMNS = [
    "incident_id", "evidence_id", "detector", "verdict", "timestamp",
    "src_ip", "dst_ip", "dst_port", "reasoning",
]


def incidents_to_csv(incidents: list[Incident]) -> str:
    """
    One row per incident - the fused, summary view. `source` reads
    "aggregate (DDoS)" for the one sourceless bucket rather than the
    raw AGGREGATE_KEY sentinel string, since a human reading this CSV
    in a spreadsheet shouldn't need to know that internal detail.
    """
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_INCIDENT_CSV_COLUMNS)
    writer.writeheader()

    for incident in incidents:
        risk = assess(incident)
        techniques = techniques_for_incident(incident)
        source = "aggregate (DDoS)" if incident.key == AGGREGATE_KEY else incident.key

        writer.writerow({
            "incident_id": incident.incident_id,
            "source": source,
            "status": incident.status.value,
            "risk_score": risk.score,
            "risk_tier": risk.tier.value,
            "highest_verdict": incident.highest_verdict.value,
            "detectors_involved": ",".join(sorted(incident.detectors_involved)),
            "mitre_techniques": ",".join(t.technique_id for t in techniques),
            "evidence_count": len(incident.evidence),
            "first_seen": _format_timestamp(incident.first_seen),
            "last_seen": _format_timestamp(incident.last_seen),
        })

    return buffer.getvalue()


def evidence_to_csv(incidents: list[Incident]) -> str:
    """
    One row per individual Evidence, across all given incidents - the
    forensic-detail view, for when a summary row per incident isn't
    enough and someone needs to see every raw finding that went into
    an incident's risk score.
    """
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_EVIDENCE_CSV_COLUMNS)
    writer.writeheader()

    for incident in incidents:
        for evidence in incident.evidence:
            writer.writerow({
                "incident_id": incident.incident_id,
                "evidence_id": evidence.evidence_id,
                "detector": evidence.detector.value,
                "verdict": evidence.verdict.value,
                "timestamp": _format_timestamp(evidence.timestamp),
                "src_ip": evidence.src_ip,
                "dst_ip": evidence.dst_ip,
                "dst_port": evidence.dst_port,
                "reasoning": evidence.reasoning,
            })

    return buffer.getvalue()


# ----------------------------------------------------------------------
# Markdown text report
# ----------------------------------------------------------------------

def render_incident_report(incident: Incident, risk: RiskAssessment | None = None) -> str:
    """
    A single-incident "case file" in Markdown: summary header, MITRE
    techniques involved, the fused risk assessment, and the full
    chronological timeline (reusing detection/timeline.py's renderer
    rather than re-implementing it).

    `risk` can be passed in if already computed elsewhere (e.g. the
    same assessment already shown on a dashboard) to avoid a second
    recomputation - defaults to computing it fresh if omitted.
    """
    if risk is None:
        risk = assess(incident)

    techniques = techniques_for_incident(incident)
    source = "Aggregate (cross-source DDoS)" if incident.key == AGGREGATE_KEY else incident.key

    lines = [
        f"# Incident report — {incident.incident_id}",
        "",
        f"- **Source:** {source}",
        f"- **Status:** {incident.status.value}",
        f"- **Risk:** {risk.score}/100 ({risk.tier.value})",
        f"- **Highest verdict recorded:** {incident.highest_verdict.value}",
        f"- **Detectors involved:** {', '.join(sorted(incident.detectors_involved)) or 'none'}",
        f"- **First seen:** {_format_timestamp(incident.first_seen)}",
        f"- **Last seen:** {_format_timestamp(incident.last_seen)}",
        "",
        "## MITRE ATT&CK techniques",
        "",
    ]

    if techniques:
        for t in techniques:
            lines.append(f"- **{t.technique_id}** — {t.name} ({t.tactic})")
    else:
        lines.append("- No technique could be confidently attributed (see risk explanation below).")

    lines += [
        "",
        f"## Risk explanation",
        "",
        risk.explanation,
        "",
        "## Timeline",
        "",
        "```",
        render_timeline_text(incident),
        "```",
    ]

    return "\n".join(lines)


def render_fleet_summary(incidents: list[Incident]) -> str:
    """
    A one-page Markdown overview across MANY incidents - a Markdown
    table, one row per incident, sorted by risk score descending so
    the most severe incidents are immediately visible at the top
    rather than in arrival order.
    """
    if not incidents:
        return "# Incident summary\n\nNo incidents recorded."

    scored = [(incident, assess(incident)) for incident in incidents]
    scored.sort(key=lambda pair: pair[1].score, reverse=True)

    open_count = sum(1 for i in incidents if i.status.value == "OPEN")

    lines = [
        "# Incident summary",
        "",
        f"**{len(incidents)} total incidents, {open_count} currently open.**",
        "",
        "| Source | Status | Risk | Detectors | Last seen |",
        "|---|---|---|---|---|",
    ]

    for incident, risk in scored:
        source = "Aggregate (DDoS)" if incident.key == AGGREGATE_KEY else incident.key
        detectors = ", ".join(sorted(incident.detectors_involved))
        lines.append(
            f"| {source} | {incident.status.value} | {risk.score} ({risk.tier.value}) | "
            f"{detectors} | {_format_timestamp(incident.last_seen)} |"
        )

    return "\n".join(lines)