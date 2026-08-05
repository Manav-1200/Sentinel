"""
observability/cef_export.py

SIEM export — renders Evidence and Incident/RiskAssessment findings as
CEF (Common Event Format) strings, and optionally ships them to a
syslog endpoint, so Sentinel's findings show up natively inside a
real SOC's existing SIEM (Splunic, QRadar, ArcSight, Microsoft
Sentinel, etc.) instead of requiring that team to build a Sentinel-
specific integration first.

Why CEF specifically, not a bespoke JSON schema:
--------------------------------------------------------------------
CEF is a widely-adopted, vendor-neutral log format that virtually
every mainstream SIEM already parses out of the box. Emitting it means
"integrate Sentinel with our SIEM" becomes "point a syslog listener at
Sentinel" rather than "write and maintain a custom parser for
Sentinel's JSON" - the same reasoning that justified JSON-Lines for
observability/structured_logger.py, one level up the integration
stack: structured_logger.py is for Sentinel's own/generic tooling
(jq, Filebeat), CEF is specifically for SIEM ingestion, which expects
this exact format.

CEF format (per the spec):
--------------------------------------------------------------------
    CEF:Version|Device Vendor|Device Product|Device Version|
        Signature ID|Name|Severity|Extension

The header fields (everything before the Extension) use `|` as a
delimiter, so any literal `|` or `\\` inside a header field value MUST
be escaped. The Extension is a sequence of key=value pairs
space-separated, where `=` and `\\` inside a VALUE must be escaped
(keys never need escaping - they're from a fixed CEF dictionary, e.g.
src, dst, dpt, msg, cn1, cs1). Getting this wrong silently corrupts
every downstream field in the same message, so escaping is handled
centrally here (_escape_header/_escape_extension) rather than
per-call-site.

Two export granularities are provided:
  - evidence_to_cef(): one CEF event per individual detector finding -
    mirrors structured_logger.py's evidence_created granularity, for
    a SIEM that wants every raw signal.
  - incident_to_cef(): one CEF event per Incident, carrying the FUSED
    risk score/tier from risk_engine.py - for a SIEM that only cares
    about "what does Sentinel currently think is a real incident",
    without needing to reconstruct that fusion itself from five raw
    detector events.
Most real deployments will want incident-level export as the primary
feed (less noise, already fused) with evidence-level available for
deeper forensics - hence both exist rather than picking one.
"""

from __future__ import annotations

import logging
import logging.handlers
import socket
import time
from typing import Optional

from typing import Optional

from detection.evidence import Evidence, EvidenceVerdict
from detection.correlation_engine import Incident
from detection.risk_engine import RiskAssessment, RiskTier
from detection.mitre_attack import MitreTechnique


CEF_VENDOR = "Sentinel"
CEF_PRODUCT = "NIDRS"
CEF_VERSION = "1.0"

# CEF severity is an integer 0-10. Evidence-level export maps directly
# off EvidenceVerdict; incident-level export maps off the fused
# RiskTier instead (see incident_to_cef), since that's already a
# considered judgement rather than one raw detector's verdict.
_EVIDENCE_VERDICT_SEVERITY = {
    EvidenceVerdict.UNAVAILABLE: 0,
    EvidenceVerdict.NORMAL: 0,
    EvidenceVerdict.WARMING_UP: 0,
    EvidenceVerdict.SUSPICIOUS: 5,
    EvidenceVerdict.ATTACK: 9,
}

_RISK_TIER_SEVERITY = {
    RiskTier.LOW: 2,
    RiskTier.MEDIUM: 5,
    RiskTier.HIGH: 8,
    RiskTier.CRITICAL: 10,
}


def _escape_header(value: str) -> str:
    """Escapes `\\` and `|` for a CEF HEADER field (per the CEF spec,
    header fields are pipe-delimited, so both characters are unsafe
    inside a value if left unescaped)."""
    return value.replace("\\", "\\\\").replace("|", "\\|")


def _escape_extension(value: str) -> str:
    """Escapes `\\` and `=` for a CEF EXTENSION value (extension
    fields are key=value pairs, so a literal `=` or `\\` inside a
    VALUE must be escaped or it corrupts the key/value parsing for
    every field after it in the same message)."""
    return str(value).replace("\\", "\\\\").replace("=", "\\=")


def _cef_header(signature_id: str, name: str, severity: int) -> str:
    return (
        f"CEF:0|{_escape_header(CEF_VENDOR)}|{_escape_header(CEF_PRODUCT)}|"
        f"{_escape_header(CEF_VERSION)}|{_escape_header(signature_id)}|"
        f"{_escape_header(name)}|{severity}"
    )


def _cef_extension(fields: dict) -> str:
    """Renders a dict of CEF extension key/value pairs, skipping any
    key whose value is None - CEF has no concept of a null field, an
    absent key is the correct representation (e.g. dst/dpt are
    legitimately absent for ddos/port_scan evidence - see
    evidence.py's module docstring on why those fields are None)."""
    parts = [f"{key}={_escape_extension(value)}" for key, value in fields.items() if value is not None]
    return " ".join(parts)


def evidence_to_cef(evidence: Evidence) -> str:
    """
    Renders one Evidence as a single CEF event line. signature_id is
    "{detector}.{verdict}" (e.g. "brute_force.ATTACK") - stable and
    specific enough for a SIEM rule to filter on a particular
    detector+verdict combination without parsing the free-text name.
    """
    signature_id = f"{evidence.detector.value}.{evidence.verdict.value}"
    name = f"Sentinel {evidence.detector.value} finding: {evidence.verdict.value}"
    severity = _EVIDENCE_VERDICT_SEVERITY.get(evidence.verdict, 0)

    extension = _cef_extension({
        "rt": int(evidence.timestamp * 1000),  # CEF rt is epoch milliseconds
        "src": evidence.src_ip,
        "dst": evidence.dst_ip,
        "dpt": evidence.dst_port,
        "msg": evidence.reasoning,
        "externalId": evidence.evidence_id,
        "cs1Label": "detector",
        "cs1": evidence.detector.value,
    })
    return f"{_cef_header(signature_id, name, severity)}|{extension}"


def incident_to_cef(
    incident: Incident,
    risk: RiskAssessment,
    techniques: Optional[list[MitreTechnique]] = None,
) -> str:
    """
    Renders one Incident (plus its already-computed RiskAssessment) as
    a single CEF event line - the fused, corroborated view, not a raw
    per-detector finding. `risk` is passed in rather than computed
    here so the caller controls exactly when risk_engine.assess() runs
    (see risk_engine.py's own note on on-demand vs. cached scoring).

    `techniques` is likewise passed in rather than computed here, for
    the same reason - the caller (Labeller.store_evidence()) already
    has to call detection.mitre_attack.get_techniques_for_incident()
    for its own purposes, so this function shouldn't recompute it a
    second time. Optional and defaults to None/empty - a SIEM listener
    that doesn't care about ATT&CK mapping still gets a valid CEF line
    either way, just without cs3.
    """
    signature_id = f"incident.{incident.status.value}"
    name = f"Sentinel incident ({risk.tier.value}): {incident.key}"
    severity = _RISK_TIER_SEVERITY.get(risk.tier, 0)

    technique_ids = ",".join(t.technique_id for t in (techniques or []))

    extension = _cef_extension({
        "rt": int(incident.last_seen * 1000),
        "src": incident.key if incident.key != "__aggregate__" else None,
        "msg": risk.explanation,
        "externalId": incident.incident_id,
        "cn1Label": "riskScore",
        "cn1": risk.score,
        "cs1Label": "detectorsInvolved",
        "cs1": ",".join(sorted(incident.detectors_involved)),
        "cs2Label": "incidentStatus",
        "cs2": incident.status.value,
        "cs3Label": "mitreTechniques",
        "cs3": technique_ids or None,
    })
    return f"{_cef_header(signature_id, name, severity)}|{extension}"


class CEFSyslogExporter:
    """
    Ships CEF-formatted events to a syslog endpoint (the standard
    transport CEF is designed for - most SIEM CEF listeners expect a
    syslog stream, not a raw file). Uses Python's stdlib
    SysLogHandler, defaulting to UDP (the common choice for high-
    volume event streams where an occasional dropped message is an
    acceptable trade-off for never blocking the capture pipeline on a
    slow/unavailable SIEM).

    Like observability/structured_logger.py, export failures here must
    NEVER interrupt Sentinel's actual detection pipeline - see
    _safe_send().
    """

    def __init__(self, host: str = "localhost", port: int = 514,
                 socktype: int = socket.SOCK_DGRAM):
        self._logger = logging.getLogger(f"sentinel.cef.{id(self)}")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False

        handler = logging.handlers.SysLogHandler(address=(host, port), socktype=socktype)
        handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(handler)

    def send_evidence(self, evidence: Evidence) -> None:
        self._safe_send(evidence_to_cef(evidence))

    def send_incident(
        self,
        incident: Incident,
        risk: RiskAssessment,
        techniques: Optional[list[MitreTechnique]] = None,
    ) -> None:
        self._safe_send(incident_to_cef(incident, risk, techniques=techniques))

    def _safe_send(self, cef_line: str) -> None:
        """A SIEM being unreachable is a real, expected operational
        condition (network hiccup, SIEM maintenance window) - it must
        never propagate up into main.py's per-flow loop."""
        try:
            self._logger.info(cef_line)
        except Exception:
            pass