"""
tests/test_metrics.py

Tests for observability/metrics.py. Each test builds its own isolated
SentinelMetrics(registry=CollectorRegistry()) rather than going
through the get_metrics() singleton, exactly per that function's own
docstring guidance - this avoids duplicate-registration errors and
cross-test pollution across the test run.
"""

import time

import pytest
from prometheus_client import CollectorRegistry
from fastapi import FastAPI
from fastapi.testclient import TestClient

from detection.evidence import DetectorName, Evidence, EvidenceVerdict
from detection.correlation_engine import Incident, IncidentStatus
from detection.risk_engine import RiskAssessment, RiskTier

from observability import metrics as m


def _fresh_metrics():
    return m.SentinelMetrics(registry=CollectorRegistry())


def _make_evidence(detector=DetectorName.BRUTE_FORCE, verdict=EvidenceVerdict.ATTACK):
    return Evidence(
        evidence_id="e1",
        detector=detector,
        timestamp=time.time(),
        verdict=verdict,
        reasoning="test",
    )


def _make_incident():
    return Incident(
        incident_id="i1",
        key="1.2.3.4",
        status=IncidentStatus.OPEN,
        first_seen=1.0,
        last_seen=2.0,
    )


class TestEvidenceRecording:
    def test_record_evidence_increments_labelled_counter(self):
        metrics = _fresh_metrics()
        m.record_evidence(metrics, _make_evidence())
        value = metrics.evidence_total.labels(detector="brute_force", verdict="ATTACK")._value.get()
        assert value == 1

    def test_record_evidence_never_raises_on_bad_input(self):
        metrics = _fresh_metrics()
        # Passing something without .detector/.verdict must not propagate -
        # metrics recording must never crash the detection pipeline.
        m.record_evidence(metrics, object())  # should silently no-op


class TestIncidentMetrics:
    def test_new_incident_increments_opened_not_updated(self):
        metrics = _fresh_metrics()
        m.record_incident_event(metrics, _make_incident(), is_new=True)
        assert metrics.incidents_opened_total._value.get() == 1
        assert metrics.incidents_updated_total._value.get() == 0

    def test_existing_incident_increments_updated_not_opened(self):
        metrics = _fresh_metrics()
        m.record_incident_event(metrics, _make_incident(), is_new=False)
        assert metrics.incidents_updated_total._value.get() == 1
        assert metrics.incidents_opened_total._value.get() == 0

    def test_open_incidents_gauge_can_go_down(self):
        metrics = _fresh_metrics()
        m.set_incidents_open_current(metrics, 5)
        assert metrics.incidents_open_current._value.get() == 5
        m.set_incidents_open_current(metrics, 2)
        assert metrics.incidents_open_current._value.get() == 2


class TestRiskMetrics:
    def test_risk_assessment_observes_score_and_tier(self):
        metrics = _fresh_metrics()
        risk = RiskAssessment(score=85, tier=RiskTier.CRITICAL, contributing_detectors=["brute_force"])
        m.record_risk_assessment(metrics, risk)
        assert metrics.risk_tier_assessments_total.labels(tier="CRITICAL")._value.get() == 1


class TestBlockMetrics:
    def test_block_action_labelled_by_action_and_backend(self):
        metrics = _fresh_metrics()
        m.record_block_action(metrics, action="block", backend="nftables")
        value = metrics.block_actions_total.labels(action="block", backend="nftables")._value.get()
        assert value == 1

    def test_blocked_ips_gauge_reflects_latest_set(self):
        metrics = _fresh_metrics()
        m.set_blocked_ips_current(metrics, 3)
        assert metrics.blocked_ips_current._value.get() == 3


class TestLLMAndCEFMetrics:
    def test_llm_call_outcome_labelled(self):
        metrics = _fresh_metrics()
        m.record_llm_call(metrics, outcome="retried")
        assert metrics.llm_calls_total.labels(outcome="retried")._value.get() == 1

    def test_cef_export_outcome_labelled(self):
        metrics = _fresh_metrics()
        m.record_cef_export(metrics, granularity="incident", outcome="sent")
        value = metrics.cef_export_total.labels(granularity="incident", outcome="sent")._value.get()
        assert value == 1


class TestSingleton:
    def test_get_metrics_returns_same_instance(self):
        m.reset_for_tests()
        first = m.get_metrics()
        second = m.get_metrics()
        assert first is second
        m.reset_for_tests()

    def test_reset_for_tests_allows_fresh_instance(self):
        m.reset_for_tests()
        first = m.get_metrics()
        m.reset_for_tests()
        second = m.get_metrics()
        assert first is not second
        m.reset_for_tests()


class TestMountMetrics:
    def test_metrics_endpoint_is_scrapeable(self):
        metrics = _fresh_metrics()
        m.record_evidence(metrics, _make_evidence())

        app = FastAPI()
        m.mount_metrics(app, metrics=metrics)
        client = TestClient(app)

        response = client.get("/metrics")
        assert response.status_code == 200
        assert "sentinel_evidence_total" in response.text
        assert 'detector="brute_force"' in response.text

    def test_mount_metrics_defaults_to_singleton_when_none_passed(self):
        m.reset_for_tests()
        app = FastAPI()
        m.mount_metrics(app)  # should not raise, uses get_metrics() internally
        client = TestClient(app)
        response = client.get("/metrics")
        assert response.status_code == 200
        m.reset_for_tests()