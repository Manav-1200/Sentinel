"""
tests/test_cef_export.py

Coverage for observability/cef_export.py: correct CEF header structure,
correct escaping rules per the CEF spec (header: `|` and `\\` escaped;
extension: only `=` and `\\` escaped, `|` left alone), severity mapping
for both evidence- and incident-level export, None-field omission, and
the never-crash-the-pipeline guarantee on a failed syslog send.
"""

import pytest

from observability.cef_export import (
    evidence_to_cef, incident_to_cef, CEFSyslogExporter,
    _escape_header, _escape_extension,
)
from detection.correlation_engine import CorrelationEngine
from detection.evidence import from_brute_force, from_port_scan, from_ddos
from detection.brute_force_tracker import BruteForceResult, BruteForceVerdict
from detection.port_scan_tracker import PortScanCheckResult, PortScanVerdict
from detection.ddos_tracker import DDoSCheckResult, DDoSVerdict
from detection.risk_engine import assess


class TestEscaping:
    def test_header_escapes_pipe_and_backslash(self):
        assert _escape_header("a|b") == "a\\|b"
        assert _escape_header("a\\b") == "a\\\\b"

    def test_extension_escapes_equals_and_backslash_but_not_pipe(self):
        # Per CEF spec: extension values only need = and \ escaped -
        # | is fine unescaped in extension (unlike header fields).
        assert _escape_extension("a=b") == "a\\=b"
        assert _escape_extension("a\\b") == "a\\\\b"
        assert _escape_extension("a|b") == "a|b"


class TestEvidenceToCEF:
    def test_basic_structure(self):
        evidence = from_brute_force(
            BruteForceResult(BruteForceVerdict.ATTACK, "1.2.3.4", "5.6.7.8", 22, 20, 60.0, 1),
            timestamp=1721000000.0,
        )
        line = evidence_to_cef(evidence)
        assert line.startswith("CEF:0|Sentinel|NIDRS|1.0|brute_force.ATTACK|")
        assert "src=1.2.3.4" in line
        assert "dst=5.6.7.8" in line
        assert "dpt=22" in line
        assert "rt=1721000000000" in line  # epoch millis, not seconds

    def test_attack_severity_higher_than_suspicious(self):
        attack = from_brute_force(
            BruteForceResult(BruteForceVerdict.ATTACK, "1.1.1.1", "2.2.2.2", 22, 20, 60.0, 1), timestamp=1.0
        )
        suspicious = from_port_scan(
            PortScanCheckResult(PortScanVerdict.SUSPICIOUS, "1.1.1.1", 10.0, 9, 4), timestamp=1.0
        )
        attack_severity = int(evidence_to_cef(attack).split("|")[6])
        suspicious_severity = int(evidence_to_cef(suspicious).split("|")[6])
        assert attack_severity > suspicious_severity

    def test_missing_destination_fields_are_omitted_not_blank(self):
        # port_scan structurally has no dst_ip/dst_port - CEF has no
        # null concept, the key must be absent entirely, not "dst=".
        evidence = from_port_scan(
            PortScanCheckResult(PortScanVerdict.ATTACK, "9.9.9.9", 10.0, 25, 10), timestamp=1.0
        )
        line = evidence_to_cef(evidence)
        assert "dst=" not in line
        assert "dpt=" not in line
        assert "src=9.9.9.9" in line

    def test_reasoning_with_special_characters_is_escaped(self):
        evidence = from_brute_force(
            BruteForceResult(BruteForceVerdict.ATTACK, "1.1.1.1", "2.2.2.2", 22, 20, 60.0, 1), timestamp=1.0
        )
        evidence.reasoning = "contains=equals and \\backslash"
        line = evidence_to_cef(evidence)
        assert "contains\\=equals and \\\\backslash" in line


class TestIncidentToCEF:
    def test_basic_structure(self):
        engine = CorrelationEngine()
        incident = engine.add_evidence(
            from_brute_force(
                BruteForceResult(BruteForceVerdict.ATTACK, "1.2.3.4", "5.6.7.8", 22, 20, 60.0, 1),
                timestamp=1721000000.0,
            )
        )
        risk = assess(incident)
        line = incident_to_cef(incident, risk)

        assert line.startswith("CEF:0|Sentinel|NIDRS|1.0|incident.OPEN|")
        assert "src=1.2.3.4" in line
        assert f"cn1={risk.score}" in line
        assert "cs2=OPEN" in line

    def test_aggregate_ddos_incident_omits_src(self):
        engine = CorrelationEngine()
        incident = engine.add_evidence(
            from_ddos(DDoSCheckResult(DDoSVerdict.ATTACK, 10.0, 600, 30), timestamp=1.0)
        )
        risk = assess(incident)
        line = incident_to_cef(incident, risk)
        assert "src=" not in line

    def test_severity_scales_with_risk_tier(self):
        from detection.risk_engine import RiskAssessment, RiskTier
        engine = CorrelationEngine()
        incident = engine.add_evidence(
            from_brute_force(
                BruteForceResult(BruteForceVerdict.ATTACK, "1.1.1.1", "2.2.2.2", 22, 20, 60.0, 1), timestamp=1.0
            )
        )
        low_risk = RiskAssessment(score=10, tier=RiskTier.LOW, contributing_detectors=[], explanation="")
        critical_risk = RiskAssessment(score=95, tier=RiskTier.CRITICAL, contributing_detectors=[], explanation="")

        low_severity = int(incident_to_cef(incident, low_risk).split("|")[6])
        critical_severity = int(incident_to_cef(incident, critical_risk).split("|")[6])
        assert critical_severity > low_severity


class TestCEFSyslogExporterNeverCrashes:
    def test_send_failure_is_swallowed_not_raised(self):
        exporter = CEFSyslogExporter(host="127.0.0.1", port=1)  # unlikely-bound port
        exporter._logger.info = lambda *a, **kw: (_ for _ in ()).throw(OSError("connection refused"))

        evidence = from_brute_force(
            BruteForceResult(BruteForceVerdict.ATTACK, "1.1.1.1", "2.2.2.2", 22, 20, 60.0, 1), timestamp=1.0
        )
        exporter.send_evidence(evidence)  # must not raise