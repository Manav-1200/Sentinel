"""
tests/test_tui_dashboard.py

Coverage for detection/tui_dashboard.py (Phase 4.2') - the Textual TUI
that consumes /summary and /incidents. Every test here runs the real
SentinelAPIClient / SentinelDashboardApp against a real api/app.py
FastAPI application - via httpx.ASGITransport, not a mocked client and
not a real background server thread. This means these tests exercise
the actual HTTP request/response cycle (headers, status codes, JSON
shapes) that production traffic goes through, while staying fast and
never touching a real socket or risking port collisions in CI.

No pytest-asyncio dependency needed: each async scenario is wrapped in
a plain `asyncio.run()` call inside an ordinary `def test_...():`
function, since Textual's App.run_test() itself is what needs the
event loop, not pytest's test collection machinery.
"""

import asyncio
import time

import httpx
import pytest

from api.app import create_app
from detection.correlation_engine import CorrelationEngine
from detection.evidence import from_port_scan
from detection.port_scan_tracker import PortScanCheckResult, PortScanVerdict
from detection.tui_dashboard import (
    IncidentDetailScreen,
    SentinelAPIClient,
    SentinelAPIError,
    SentinelDashboardApp,
)

_TEST_KEY = "test-key-do-not-use-in-real-deployment"


@pytest.fixture(autouse=True)
def _set_server_side_api_key(monkeypatch):
    """api/auth.py reads SENTINEL_API_KEY from the real environment at
    request time - every test in this module needs it set to exactly
    _TEST_KEY so the "correct key" path actually succeeds, regardless
    of whatever the shell running pytest happens to have exported.
    Tests that specifically want the missing-key (500) case override
    this with monkeypatch.delenv inside the test itself."""
    monkeypatch.setenv("SENTINEL_API_KEY", _TEST_KEY)


def _seed_open_incident(engine: CorrelationEngine, src_ip: str = "10.0.0.5") -> str:
    result = PortScanCheckResult(
        verdict=PortScanVerdict.ATTACK, src_ip=src_ip, window_seconds=10.0,
        distinct_ports_in_window=25, distinct_targets_in_window=1,
        scan_start_timestamp=time.time() - 5, scan_end_timestamp=time.time(),
        duration_seconds=5.0, ports_per_second=5.0, confidence_pct=100.0,
    )
    engine.add_evidence(from_port_scan(result, timestamp=time.time()))
    return src_ip


def _transport_for(engine: CorrelationEngine, require_auth: bool = True, blocker=None):
    app = create_app(engine, require_auth=require_auth, blocker=blocker)
    return httpx.ASGITransport(app=app)


class TestSentinelAPIClient:
    """The HTTP client layer in isolation, before involving Textual at all."""

    def test_get_summary_against_real_app(self):
        engine = CorrelationEngine()
        transport = _transport_for(engine)

        async def run():
            client = SentinelAPIClient("http://testserver", _TEST_KEY, transport=transport)
            summary = await client.get_summary()
            await client.close()
            return summary

        summary = asyncio.run(run())
        assert summary["open_incident_count"] == 0
        assert set(summary["risk_tier_breakdown"].keys()) == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def test_wrong_key_raises_sentinel_api_error(self):
        engine = CorrelationEngine()
        transport = _transport_for(engine)

        async def run():
            client = SentinelAPIClient("http://testserver", "wrong-key", transport=transport)
            try:
                await client.get_summary()
                return None
            except SentinelAPIError as exc:
                return str(exc)
            finally:
                await client.close()

        error_message = asyncio.run(run())
        assert error_message is not None
        assert "401" in error_message

    def test_missing_server_key_raises_sentinel_api_error(self, monkeypatch):
        """require_auth=True but SENTINEL_API_KEY isn't set on the
        server side - api/auth.py returns 500, the client should turn
        that into a readable SentinelAPIError, not an unhandled
        httpx.HTTPStatusError."""
        monkeypatch.delenv("SENTINEL_API_KEY", raising=False)
        engine = CorrelationEngine()
        app = create_app(engine, require_auth=True)  # no key configured anywhere
        transport = httpx.ASGITransport(app=app)

        async def run():
            client = SentinelAPIClient("http://testserver", None, transport=transport)
            try:
                await client.get_summary()
                return None
            except SentinelAPIError as exc:
                return str(exc)
            finally:
                await client.close()

        error_message = asyncio.run(run())
        assert error_message is not None
        assert "500" in error_message

    def test_get_incidents_and_get_incident_round_trip(self):
        engine = CorrelationEngine()
        src_ip = _seed_open_incident(engine)
        transport = _transport_for(engine)

        async def run():
            client = SentinelAPIClient("http://testserver", _TEST_KEY, transport=transport)
            incidents = await client.get_incidents()
            detail = await client.get_incident(src_ip)
            await client.close()
            return incidents, detail

        incidents, detail = asyncio.run(run())
        assert len(incidents) == 1
        assert incidents[0]["key"] == src_ip
        assert detail["key"] == src_ip
        assert len(detail["evidence"]) == 1

    def test_get_incident_404_raises_sentinel_api_error(self):
        engine = CorrelationEngine()
        transport = _transport_for(engine)

        async def run():
            client = SentinelAPIClient("http://testserver", _TEST_KEY, transport=transport)
            try:
                await client.get_incident("no-such-src-ip")
                return None
            except SentinelAPIError as exc:
                return str(exc)
            finally:
                await client.close()

        error_message = asyncio.run(run())
        assert error_message is not None
        assert "404" in error_message


class TestSentinelDashboardApp:
    """The actual Textual app, driven headlessly via App.run_test()."""

    def test_connects_and_populates_summary_and_table(self):
        engine = CorrelationEngine()
        src_ip = _seed_open_incident(engine)
        transport = _transport_for(engine)

        async def run():
            app = SentinelDashboardApp("http://testserver", _TEST_KEY, 60.0, transport=transport)
            async with app.run_test() as pilot:
                await pilot.pause(0.3)
                summary_widget = app.query_one("#summary")
                table = app.query_one("#incidents-table")
                return (
                    summary_widget.connection_error,
                    summary_widget.summary_data,
                    table.row_count,
                    app._incident_keys_by_row,
                )

        connection_error, summary_data, row_count, keys = asyncio.run(run())
        assert connection_error is None
        assert summary_data["open_incident_count"] == 1
        assert row_count == 1
        assert keys == [src_ip]

    def test_wrong_key_surfaces_as_connection_error_not_crash(self):
        """A dashboard pointed at the wrong key shouldn't crash - it
        should show the error in the summary panel and keep polling."""
        engine = CorrelationEngine()
        transport = _transport_for(engine)

        async def run():
            app = SentinelDashboardApp("http://testserver", "wrong-key", 60.0, transport=transport)
            async with app.run_test() as pilot:
                await pilot.pause(0.3)
                summary_widget = app.query_one("#summary")
                return summary_widget.connection_error

        connection_error = asyncio.run(run())
        assert connection_error is not None
        assert "401" in connection_error

    def test_enter_opens_detail_screen_and_escape_closes_it(self):
        engine = CorrelationEngine()
        _seed_open_incident(engine)
        transport = _transport_for(engine)

        async def run():
            app = SentinelDashboardApp("http://testserver", _TEST_KEY, 60.0, transport=transport)
            async with app.run_test() as pilot:
                await pilot.pause(0.3)
                await pilot.press("enter")
                await pilot.pause(0.3)
                opened_screen_type = type(app.screen).__name__

                await pilot.press("escape")
                await pilot.pause(0.2)
                closed_screen_type = type(app.screen).__name__
                return opened_screen_type, closed_screen_type

        opened, closed = asyncio.run(run())
        assert opened == "IncidentDetailScreen"
        assert closed != "IncidentDetailScreen"

    def test_detail_screen_renders_real_evidence(self):
        engine = CorrelationEngine()
        src_ip = _seed_open_incident(engine)
        transport = _transport_for(engine)

        async def run():
            app = SentinelDashboardApp("http://testserver", _TEST_KEY, 60.0, transport=transport)
            async with app.run_test() as pilot:
                await pilot.pause(0.3)
                await pilot.press("enter")
                await pilot.pause(0.3)
                screen = app.screen
                assert isinstance(screen, IncidentDetailScreen)
                body = screen.query_one("#detail-body")
                return body.content.plain

        rendered_text = asyncio.run(run())
        assert "10.0.0.5" in rendered_text
        assert "port_scan" in rendered_text
        assert "ATTACK" in rendered_text

    def test_toggle_resolved_flips_reactive_state(self):
        engine = CorrelationEngine()
        transport = _transport_for(engine)

        async def run():
            app = SentinelDashboardApp("http://testserver", _TEST_KEY, 60.0, transport=transport)
            async with app.run_test() as pilot:
                await pilot.pause(0.3)
                before = app.show_resolved
                await pilot.press("r")
                await pilot.pause(0.3)
                after = app.show_resolved
                return before, after

        before, after = asyncio.run(run())
        assert before is False
        assert after is True

    def test_resolved_incident_excluded_by_default_included_after_toggle(self):
        engine = CorrelationEngine()
        src_ip = _seed_open_incident(engine)
        engine.resolve(src_ip)
        transport = _transport_for(engine)

        async def run():
            app = SentinelDashboardApp("http://testserver", _TEST_KEY, 60.0, transport=transport)
            async with app.run_test() as pilot:
                await pilot.pause(0.3)
                table = app.query_one("#incidents-table")
                count_before = table.row_count

                await pilot.press("r")
                await pilot.pause(0.3)
                count_after = table.row_count
                return count_before, count_after

        count_before, count_after = asyncio.run(run())
        assert count_before == 0
        assert count_after == 1