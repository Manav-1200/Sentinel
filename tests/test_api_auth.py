"""
tests/test_api_auth.py

Coverage for api/auth.py and its wiring into api/app.py's create_app()
- closes the item tracked in PHASES.md Phase 6 ("API authentication -
design decided, not implemented") and confirms the fix for the real
import bug found alongside it (main.py importing `api.app` when the
file was actually `api/api.py`, with no `api/__init__.py` - this
module existing and importing cleanly is itself a regression test
for that).

Uses FastAPI's TestClient rather than starting a real uvicorn server -
these are the same routes main.py wires up, just exercised in-process.
"""

import os

import pytest
from fastapi.testclient import TestClient

from api.app import create_app
from detection.correlation_engine import CorrelationEngine

_TEST_KEY = "test-key-do-not-use-in-real-deployment"


@pytest.fixture
def engine():
    return CorrelationEngine()


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Every test starts with SENTINEL_API_KEY unset, so tests control
    it explicitly rather than inheriting whatever's in the real shell
    environment this suite happens to run in."""
    monkeypatch.delenv("SENTINEL_API_KEY", raising=False)


class TestAuthRequired:

    def test_health_never_requires_a_key(self, engine):
        app = create_app(engine, require_auth=True)
        client = TestClient(app)

        response = client.get("/health")

        assert response.status_code == 200

    def test_incidents_route_rejects_missing_key_when_configured(self, engine, monkeypatch):
        monkeypatch.setenv("SENTINEL_API_KEY", _TEST_KEY)
        app = create_app(engine, require_auth=True)
        client = TestClient(app)

        response = client.get("/incidents")

        assert response.status_code == 401

    def test_incidents_route_rejects_wrong_key(self, engine, monkeypatch):
        monkeypatch.setenv("SENTINEL_API_KEY", _TEST_KEY)
        app = create_app(engine, require_auth=True)
        client = TestClient(app)

        response = client.get("/incidents", headers={"X-API-Key": "wrong-key"})

        assert response.status_code == 401

    def test_incidents_route_accepts_correct_key(self, engine, monkeypatch):
        monkeypatch.setenv("SENTINEL_API_KEY", _TEST_KEY)
        app = create_app(engine, require_auth=True)
        client = TestClient(app)

        response = client.get("/incidents", headers={"X-API-Key": _TEST_KEY})

        assert response.status_code == 200

    def test_missing_server_side_key_is_a_500_not_a_401(self, engine):
        """
        SENTINEL_API_KEY unset entirely is a deployment misconfiguration,
        not an ordinary auth failure - see api/auth.py's module
        docstring for why these are deliberately different status codes
        (fail loud on misconfiguration, rather than silently running
        the API wide open or looking like a normal wrong-key 401).
        """
        app = create_app(engine, require_auth=True)
        client = TestClient(app)

        response = client.get("/incidents", headers={"X-API-Key": "anything"})

        assert response.status_code == 500

    def test_action_routes_are_also_protected(self, engine, monkeypatch):
        monkeypatch.setenv("SENTINEL_API_KEY", _TEST_KEY)
        app = create_app(engine, require_auth=True)
        client = TestClient(app)

        response = client.post("/incidents/1.2.3.4/resolve")

        assert response.status_code == 401


class TestAuthDisabled:

    def test_require_auth_false_allows_unauthenticated_access(self, engine):
        """
        require_auth=False is the escape hatch for tests/local dev
        (see create_app's docstring) - confirms the flag actually
        bypasses the dependency rather than just changing the error
        message.
        """
        app = create_app(engine, require_auth=False)
        client = TestClient(app)

        response = client.get("/incidents")

        assert response.status_code == 200

    def test_require_auth_false_ignores_env_key_entirely(self, engine, monkeypatch):
        monkeypatch.setenv("SENTINEL_API_KEY", _TEST_KEY)
        app = create_app(engine, require_auth=False)
        client = TestClient(app)

        response = client.get("/incidents")  # no header at all

        assert response.status_code == 200


class TestDefaultBehaviour:

    def test_create_app_defaults_to_requiring_auth(self, engine, monkeypatch):
        """
        require_auth defaults to True - a deployment has to
        deliberately opt OUT, matching create_app's own docstring
        ("a deployment has to deliberately opt OUT of auth").
        """
        monkeypatch.setenv("SENTINEL_API_KEY", _TEST_KEY)
        app = create_app(engine)  # no require_auth argument at all
        client = TestClient(app)

        response = client.get("/incidents")

        assert response.status_code == 401


def _seed_open_incident(engine, src_ip="10.0.0.5"):
    """Builds one real Evidence object (via the real from_port_scan
    factory, not a hand-rolled dict) and files it into the engine, so
    the success-path tests below exercise the actual
    _to_summary()/build_timeline()/model_dump() machinery in app.py
    against a real Incident, rather than just confirming they don't
    crash on missing data (the only thing the 404-only tests above
    covered)."""
    from detection.evidence import from_port_scan
    from detection.port_scan_tracker import PortScanCheckResult, PortScanVerdict

    result = PortScanCheckResult(
        verdict=PortScanVerdict.ATTACK,
        src_ip=src_ip,
        window_seconds=10.0,
        distinct_ports_in_window=25,
        distinct_targets_in_window=1,
        scan_start_timestamp=1000.0,
        scan_end_timestamp=1005.0,
        duration_seconds=5.0,
        ports_per_second=5.0,
        confidence_pct=100.0,
    )
    engine.add_evidence(from_port_scan(result, timestamp=1005.0))
    return src_ip


class TestSuccessPaths:
    """Previously only the 404 branches of get/resolve/reopen had any
    coverage - these exercise the actual 200 paths against a real
    Incident built from a real Evidence object."""

    def test_get_incident_returns_full_detail(self, engine, monkeypatch):
        monkeypatch.setenv("SENTINEL_API_KEY", _TEST_KEY)
        src_ip = _seed_open_incident(engine)
        app = create_app(engine, require_auth=True)
        client = TestClient(app)

        response = client.get(f"/incidents/{src_ip}", headers={"X-API-Key": _TEST_KEY})

        assert response.status_code == 200
        body = response.json()
        assert body["key"] == src_ip
        assert body["status"] == "OPEN"
        assert body["evidence_count"] == 1
        assert len(body["evidence"]) == 1
        assert body["evidence"][0]["detector"] == "port_scan"
        assert body["risk"]["score"] > 0

    def test_resolve_flips_status_and_drops_out_of_default_list(self, engine, monkeypatch):
        monkeypatch.setenv("SENTINEL_API_KEY", _TEST_KEY)
        src_ip = _seed_open_incident(engine)
        app = create_app(engine, require_auth=True)
        client = TestClient(app)
        headers = {"X-API-Key": _TEST_KEY}

        response = client.post(f"/incidents/{src_ip}/resolve", headers=headers)

        assert response.status_code == 200
        assert response.json()["status"] == "RESOLVED"

        open_list = client.get("/incidents", headers=headers).json()
        assert all(i["key"] != src_ip for i in open_list)

        full_list = client.get("/incidents?include_resolved=true", headers=headers).json()
        assert any(i["key"] == src_ip for i in full_list)

    def test_reopen_flips_status_back_to_open(self, engine, monkeypatch):
        monkeypatch.setenv("SENTINEL_API_KEY", _TEST_KEY)
        src_ip = _seed_open_incident(engine)
        app = create_app(engine, require_auth=True)
        client = TestClient(app)
        headers = {"X-API-Key": _TEST_KEY}

        client.post(f"/incidents/{src_ip}/resolve", headers=headers)
        response = client.post(f"/incidents/{src_ip}/reopen", headers=headers)

        assert response.status_code == 200
        assert response.json()["status"] == "OPEN"
        open_list = client.get("/incidents", headers=headers).json()
        assert any(i["key"] == src_ip for i in open_list)