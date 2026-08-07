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