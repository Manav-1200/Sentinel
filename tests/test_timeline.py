"""
tests/test_timeline.py

Coverage for detection/timeline.py: chronological ordering preserved
(not re-sorted), correct "?" fallback for detectors with no single
destination, and the empty-incident edge case.
"""

import pytest

from detection.correlation_engine import CorrelationEngine
from detection.timeline import build_timeline, render_timeline_text
from detection.evidence import from_port_scan, from_ddos, from_brute_force
from detection.port_scan_tracker import PortScanCheckResult, PortScanVerdict
from detection.ddos_tracker import DDoSCheckResult, DDoSVerdict
from detection.brute_force_tracker import BruteForceResult, BruteForceVerdict


@pytest.fixture
def engine():
    return CorrelationEngine()


class TestBuildTimeline:
    def test_entries_preserve_arrival_order_not_re_sorted(self, engine):
        # Deliberately add evidence with a LATER timestamp first, to
        # confirm build_timeline preserves ARRIVAL order rather than
        # re-sorting by timestamp - see module docstring.
        later = from_brute_force(
            BruteForceResult(BruteForceVerdict.ATTACK, "1.1.1.1", "2.2.2.2", 22, 20, 60.0, 1),
            timestamp=500.0,
        )
        earlier = from_port_scan(
            PortScanCheckResult(PortScanVerdict.ATTACK, "1.1.1.1", 10.0, 25, 10),
            timestamp=100.0,
        )
        incident = engine.add_evidence(later)
        incident = engine.add_evidence(earlier)

        entries = build_timeline(incident)
        assert entries[0].detector == "brute_force"  # arrived first, despite later timestamp
        assert entries[1].detector == "port_scan"

    def test_entry_fields_match_source_evidence(self, engine):
        evidence = from_brute_force(
            BruteForceResult(BruteForceVerdict.ATTACK, "1.1.1.1", "2.2.2.2", 22, 20, 60.0, 1),
            timestamp=100.0,
        )
        incident = engine.add_evidence(evidence)
        entry = build_timeline(incident)[0]

        assert entry.timestamp == 100.0
        assert entry.detector == "brute_force"
        assert entry.verdict == "ATTACK"
        assert entry.src_ip == "1.1.1.1"
        assert entry.dst_ip == "2.2.2.2"
        assert entry.dst_port == 22
        assert entry.evidence is evidence


class TestRenderTimelineText:
    def test_renders_one_line_per_evidence_plus_header(self, engine):
        engine.add_evidence(
            from_port_scan(PortScanCheckResult(PortScanVerdict.ATTACK, "1.1.1.1", 10.0, 25, 10), timestamp=100.0)
        )
        incident = engine.add_evidence(
            from_brute_force(
                BruteForceResult(BruteForceVerdict.ATTACK, "1.1.1.1", "2.2.2.2", 22, 20, 60.0, 1),
                timestamp=200.0,
            )
        )
        text = render_timeline_text(incident)
        lines = text.splitlines()

        assert len(lines) == 3  # 1 header + 2 evidence lines
        assert "1.1.1.1" in lines[0]
        assert "port_scan" in lines[1]
        assert "brute_force" in lines[2]

    def test_missing_destination_renders_as_question_marks(self, engine):
        # port_scan/ddos structurally have no single destination - the
        # rendering must show that plainly rather than blank/None.
        incident = engine.add_evidence(
            from_port_scan(PortScanCheckResult(PortScanVerdict.ATTACK, "1.1.1.1", 10.0, 25, 10), timestamp=100.0)
        )
        text = render_timeline_text(incident)
        assert "?:?" in text

    def test_ddos_aggregate_incident_renders_without_src_or_dst(self, engine):
        incident = engine.add_evidence(
            from_ddos(DDoSCheckResult(DDoSVerdict.ATTACK, 10.0, 600, 30), timestamp=100.0)
        )
        text = render_timeline_text(incident)
        assert "? -> ?:?" in text

    def test_empty_incident_does_not_crash(self):
        from detection.correlation_engine import Incident, IncidentStatus
        from detection.evidence import EvidenceVerdict
        empty_incident = Incident(
            incident_id="test", key="1.1.1.1", status=IncidentStatus.OPEN,
            first_seen=1.0, last_seen=1.0, highest_verdict=EvidenceVerdict.SUSPICIOUS,
        )
        text = render_timeline_text(empty_incident)
        assert "no evidence recorded" in text