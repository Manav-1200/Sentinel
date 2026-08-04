"""
tests/test_incident_report.py

Coverage for reporting/incident_report.py: CSV structure/quoting
correctness, aggregate-key friendly display, Markdown report content,
and fleet-summary sort-by-risk ordering.
"""

import csv
import io
import pytest

from reporting.incident_report import (
    incidents_to_csv, evidence_to_csv, render_incident_report, render_fleet_summary,
)
from detection.correlation_engine import CorrelationEngine, AGGREGATE_KEY
from detection.evidence import from_port_scan, from_brute_force, from_ddos
from detection.port_scan_tracker import PortScanCheckResult, PortScanVerdict
from detection.brute_force_tracker import BruteForceResult, BruteForceVerdict
from detection.ddos_tracker import DDoSCheckResult, DDoSVerdict


@pytest.fixture
def engine():
    return CorrelationEngine()


@pytest.fixture
def multi_incident_scenario(engine):
    # One multi-detector incident (higher risk) + one aggregate DDoS
    # incident (lower risk, no src_ip) - covers the interesting cases.
    inc1 = engine.add_evidence(
        from_port_scan(PortScanCheckResult(PortScanVerdict.ATTACK, "10.0.0.66", 10.0, 25, 10), timestamp=100.0)
    )
    inc1 = engine.add_evidence(
        from_brute_force(
            BruteForceResult(BruteForceVerdict.ATTACK, "10.0.0.66", "10.0.0.99", 22, 20, 60.0, 1),
            timestamp=200.0,
        )
    )
    inc2 = engine.add_evidence(from_ddos(DDoSCheckResult(DDoSVerdict.ATTACK, 10.0, 600, 30), timestamp=300.0))
    return engine.all_incidents()


class TestIncidentsToCSV:
    def test_produces_valid_parseable_csv_with_expected_columns(self, multi_incident_scenario):
        text = incidents_to_csv(multi_incident_scenario)
        rows = list(csv.DictReader(io.StringIO(text)))

        assert len(rows) == 2
        assert set(rows[0].keys()) == {
            "incident_id", "source", "status", "risk_score", "risk_tier",
            "highest_verdict", "detectors_involved", "mitre_techniques",
            "evidence_count", "first_seen", "last_seen",
        }

    def test_comma_containing_field_is_properly_quoted(self, multi_incident_scenario):
        text = incidents_to_csv(multi_incident_scenario)
        rows = list(csv.DictReader(io.StringIO(text)))
        multi_detector_row = next(r for r in rows if r["source"] == "10.0.0.66")
        # csv.DictReader already de-quotes - the real assertion is that
        # BOTH detector names survive as one comma-joined field, not
        # split across unintended extra columns.
        assert multi_detector_row["detectors_involved"] == "brute_force,port_scan"

    def test_aggregate_key_displays_as_friendly_label_not_raw_sentinel(self, multi_incident_scenario):
        text = incidents_to_csv(multi_incident_scenario)
        assert AGGREGATE_KEY not in text
        assert "aggregate (DDoS)" in text

    def test_mitre_techniques_included(self, multi_incident_scenario):
        text = incidents_to_csv(multi_incident_scenario)
        rows = list(csv.DictReader(io.StringIO(text)))
        multi_detector_row = next(r for r in rows if r["source"] == "10.0.0.66")
        assert "T1046" in multi_detector_row["mitre_techniques"]
        assert "T1110" in multi_detector_row["mitre_techniques"]

    def test_empty_incident_list_still_produces_header_only(self):
        text = incidents_to_csv([])
        rows = list(csv.DictReader(io.StringIO(text)))
        assert rows == []


class TestEvidenceToCSV:
    def test_one_row_per_evidence_across_all_incidents(self, multi_incident_scenario):
        text = evidence_to_csv(multi_incident_scenario)
        rows = list(csv.DictReader(io.StringIO(text)))
        # 2 evidence in incident 1 + 1 evidence in incident 2 = 3 rows
        assert len(rows) == 3

    def test_missing_destination_fields_render_as_empty_not_none_string(self, multi_incident_scenario):
        text = evidence_to_csv(multi_incident_scenario)
        rows = list(csv.DictReader(io.StringIO(text)))
        port_scan_row = next(r for r in rows if r["detector"] == "port_scan")
        assert port_scan_row["dst_ip"] == ""
        assert port_scan_row["dst_port"] == ""

    def test_incident_id_links_evidence_back_to_its_incident(self, multi_incident_scenario):
        incidents_csv = incidents_to_csv(multi_incident_scenario)
        evidence_csv = evidence_to_csv(multi_incident_scenario)

        incident_ids = {r["incident_id"] for r in csv.DictReader(io.StringIO(incidents_csv))}
        evidence_incident_ids = {r["incident_id"] for r in csv.DictReader(io.StringIO(evidence_csv))}
        assert evidence_incident_ids.issubset(incident_ids)


class TestRenderIncidentReport:
    def test_includes_all_expected_sections(self, multi_incident_scenario):
        incident = next(i for i in multi_incident_scenario if i.key == "10.0.0.66")
        report = render_incident_report(incident)

        assert "# Incident report" in report
        assert "## MITRE ATT&CK techniques" in report
        assert "## Risk explanation" in report
        assert "## Timeline" in report
        assert "T1046" in report and "T1110" in report

    def test_accepts_precomputed_risk_assessment(self, multi_incident_scenario):
        from detection.risk_engine import RiskAssessment, RiskTier
        incident = next(i for i in multi_incident_scenario if i.key == "10.0.0.66")
        custom_risk = RiskAssessment(score=99, tier=RiskTier.CRITICAL, contributing_detectors=[], explanation="custom")
        report = render_incident_report(incident, risk=custom_risk)
        assert "99/100 (CRITICAL)" in report
        assert "custom" in report

    def test_aggregate_incident_shows_friendly_source_label(self, multi_incident_scenario):
        ddos_incident = next(i for i in multi_incident_scenario if i.key == AGGREGATE_KEY)
        report = render_incident_report(ddos_incident)
        assert "Aggregate (cross-source DDoS)" in report

    def test_incident_with_no_techniques_says_so_explicitly(self):
        from detection.correlation_engine import CorrelationEngine
        from detection.evidence import from_anomaly
        from detection.anomaly import DetectionResult, Verdict
        engine = CorrelationEngine()
        incident = engine.add_evidence(
            from_anomaly(DetectionResult(Verdict.ATTACK, -0.9, {"src_ip": "1.1.1.1"}), timestamp=1.0)
        )
        report = render_incident_report(incident)
        assert "No technique could be confidently attributed" in report


class TestRenderFleetSummary:
    def test_sorted_by_risk_descending(self, multi_incident_scenario):
        summary = render_fleet_summary(multi_incident_scenario)
        # The multi-detector incident (higher risk) must appear before
        # the single-detector DDoS incident (lower risk) in the table.
        high_risk_pos = summary.index("10.0.0.66")
        low_risk_pos = summary.index("Aggregate (DDoS)")
        assert high_risk_pos < low_risk_pos

    def test_open_count_reflected_in_summary_line(self, multi_incident_scenario):
        summary = render_fleet_summary(multi_incident_scenario)
        assert "2 total incidents, 2 currently open" in summary

    def test_empty_incident_list_handled_gracefully(self):
        summary = render_fleet_summary([])
        assert "No incidents recorded" in summary