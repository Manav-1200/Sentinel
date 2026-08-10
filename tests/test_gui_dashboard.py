"""
tests/test_gui_dashboard.py

Coverage for detection/gui_dashboard.py (Phase 4.2') - the PySide6
native desktop app. Unlike tests/test_tui_dashboard.py (which uses
httpx.ASGITransport since it's built on an ASYNC client), this module's
SyncSentinelAPIClient uses a synchronous httpx.Client - and
httpx.Client cannot use ASGITransport, which is async-only (confirmed
directly: it raises AttributeError, no handle_request method). So
these tests instead run a REAL uvicorn server on a real localhost
socket, in a background Python thread scoped to each test via a
pytest fixture - not shell-backgrounded, not a separate process, so
there's nothing to leak between tests or across a CI run.

QT_QPA_PLATFORM=offscreen is set at import time (before any PySide6
widget import) so this suite runs headlessly - no real display needed,
matches how this module was manually verified during development.

Requires a real port bind per test (127.0.0.1, OS-assigned via port 0)
to avoid collisions if tests ever run in parallel.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import socket
import threading
import time

import pytest
import uvicorn
from PySide6.QtWidgets import QApplication

from api.app import create_app
from detection.correlation_engine import CorrelationEngine
from detection.evidence import from_port_scan
from detection.gui_dashboard import SentinelMainWindow, SyncSentinelAPIClient, _ACTION_PAST_TENSE
from detection.port_scan_tracker import PortScanCheckResult, PortScanVerdict
from detection.tui_dashboard import SentinelAPIError

_TEST_KEY = "test-key-do-not-use-in-real-deployment"


def _free_port() -> int:
    """OS-assigned free port - avoids hardcoding 8787 (which might be
    genuinely in use by a real Sentinel instance on the same machine
    this test suite runs on) and avoids collisions between tests."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _LiveServer:
    """Runs a real api/app.py FastAPI app on a real localhost socket,
    in a background thread, for the duration of one test. Not a
    fixture-of-a-fixture abstraction - deliberately simple, since the
    only thing that needs to vary per test is the seeded
    CorrelationEngine content."""

    def __init__(self, engine: CorrelationEngine, require_auth: bool = True):
        self.port = _free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        app = create_app(engine, require_auth=require_auth)
        config = uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="error")
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    def start(self) -> None:
        self._thread.start()
        # Poll for readiness rather than a fixed sleep - uvicorn.Server
        # exposes .started once its socket is actually bound and
        # accepting connections.
        deadline = time.time() + 5.0
        while time.time() < deadline:
            if getattr(self._server, "started", False):
                return
            time.sleep(0.02)
        raise RuntimeError("Test API server did not start in time")

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=3.0)


@pytest.fixture
def live_server(monkeypatch):
    monkeypatch.setenv("SENTINEL_API_KEY", _TEST_KEY)
    engine = CorrelationEngine()
    server = _LiveServer(engine)
    server.start()
    yield server, engine
    server.stop()


@pytest.fixture
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


def _seed_open_incident(engine: CorrelationEngine, src_ip: str = "10.0.0.5") -> str:
    result = PortScanCheckResult(
        verdict=PortScanVerdict.ATTACK, src_ip=src_ip, window_seconds=10.0,
        distinct_ports_in_window=25, distinct_targets_in_window=1,
        scan_start_timestamp=time.time() - 5, scan_end_timestamp=time.time(),
        duration_seconds=5.0, ports_per_second=5.0, confidence_pct=100.0,
    )
    engine.add_evidence(from_port_scan(result, timestamp=time.time()))
    return src_ip


def _pump(app: QApplication, seconds: float) -> None:
    end = time.time() + seconds
    while time.time() < end:
        app.processEvents()
        time.sleep(0.02)


def _wait_for(app: QApplication, condition, timeout_s: float = 5.0) -> bool:
    end = time.time() + timeout_s
    while time.time() < end:
        app.processEvents()
        if condition():
            return True
        time.sleep(0.02)
    return False


class TestSyncSentinelAPIClient:
    """The HTTP client layer in isolation, before involving Qt at all."""

    def test_get_summary_against_real_server(self, live_server):
        server, engine = live_server
        client = SyncSentinelAPIClient(server.base_url, _TEST_KEY)
        summary = client.get_summary()
        client.close()
        assert summary["open_incident_count"] == 0
        assert set(summary["risk_tier_breakdown"].keys()) == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def test_wrong_key_raises_sentinel_api_error(self, live_server):
        server, engine = live_server
        client = SyncSentinelAPIClient(server.base_url, "wrong-key")
        with pytest.raises(SentinelAPIError, match="401"):
            client.get_summary()
        client.close()

    def test_resolve_and_reopen_round_trip(self, live_server):
        server, engine = live_server
        src_ip = _seed_open_incident(engine)
        client = SyncSentinelAPIClient(server.base_url, _TEST_KEY)

        resolved = client.resolve_incident(src_ip)
        assert resolved["status"] == "RESOLVED"

        reopened = client.reopen_incident(src_ip)
        assert reopened["status"] == "OPEN"
        client.close()

    def test_get_incident_404_raises_sentinel_api_error(self, live_server):
        server, engine = live_server
        client = SyncSentinelAPIClient(server.base_url, _TEST_KEY)
        with pytest.raises(SentinelAPIError, match="404"):
            client.get_incident("no-such-src-ip")
        client.close()


class TestActionPastTenseMapping:
    """Regression test for a real bug found during manual end-to-end
    testing: action.capitalize() + 'd' produces 'Reopend' (not
    'Reopened') for the reopen action - the reopen call itself
    succeeded against a real server, only the status-bar text was
    wrong. An explicit mapping has no such trap."""

    def test_resolve_maps_correctly(self):
        assert _ACTION_PAST_TENSE["resolve"] == "Resolved"

    def test_reopen_maps_correctly(self):
        assert _ACTION_PAST_TENSE["reopen"] == "Reopened"


class TestSentinelMainWindow:
    """The actual Qt window, driven headlessly (QT_QPA_PLATFORM=offscreen,
    set at module import time above)."""

    def test_connects_and_populates_table(self, qapp, live_server):
        server, engine = live_server
        src_ip = _seed_open_incident(engine)

        window = SentinelMainWindow(server.base_url, _TEST_KEY, 0.3)
        window.show()
        try:
            assert _wait_for(qapp, lambda: window.table.rowCount() == 1)
            assert window.table.item(0, 0).text() == src_ip
            assert window.table.item(0, 1).text() == "OPEN"
            assert "Open incidents: 1" in window.summary_label.text()
        finally:
            window.close()
            _pump(qapp, 0.2)

    def test_wrong_key_surfaces_as_error_not_crash(self, qapp, live_server):
        server, engine = live_server
        window = SentinelMainWindow(server.base_url, "wrong-key", 0.3)
        window.show()
        try:
            assert _wait_for(qapp, lambda: "401" in window.summary_label.text())
        finally:
            window.close()
            _pump(qapp, 0.2)

    def test_resolve_button_updates_table(self, qapp, live_server):
        server, engine = live_server
        src_ip = _seed_open_incident(engine)

        window = SentinelMainWindow(server.base_url, _TEST_KEY, 0.3)
        window.show()
        try:
            assert _wait_for(qapp, lambda: window.table.rowCount() == 1)
            window.table.selectRow(0)
            window._on_resolve_clicked()

            assert _wait_for(qapp, lambda: window.table.rowCount() == 0, timeout_s=6)

            window.show_resolved_button.setChecked(True)
            assert _wait_for(qapp, lambda: window.table.rowCount() == 1, timeout_s=6)
            assert window.table.item(0, 1).text() == "RESOLVED"
        finally:
            window.close()
            _pump(qapp, 0.2)

    def test_reopen_button_updates_table_and_status_bar(self, qapp, live_server):
        server, engine = live_server
        src_ip = _seed_open_incident(engine)
        engine.resolve(src_ip)

        window = SentinelMainWindow(server.base_url, _TEST_KEY, 0.3)
        window.show()
        try:
            window.show_resolved_button.setChecked(True)
            assert _wait_for(qapp, lambda: window.table.rowCount() == 1)
            assert window.table.item(0, 1).text() == "RESOLVED"

            window.table.selectRow(0)
            window._on_reopen_clicked()

            assert _wait_for(
                qapp, lambda: window.statusBar().currentMessage() == f"Reopened {src_ip}", timeout_s=6
            )
        finally:
            window.close()
            _pump(qapp, 0.2)

    def test_double_click_opens_detail_dialog_with_real_evidence(self, live_server):
        """Doesn't drive this through the live window's signal wiring
        at all - _on_detail_ready (wired in _start_worker_thread) opens
        a REAL modal QDialog.exec(), which has nothing to dismiss it in
        a headless test and hangs indefinitely (confirmed empirically -
        this is the same class of problem as a QMessageBox hang found
        earlier in manual testing). The actual thing worth testing here
        is IncidentDetailDialog._render()'s text output against real
        evidence data, which doesn't need the dialog to ever be shown."""
        server, engine = live_server
        _seed_open_incident(engine)

        client = SyncSentinelAPIClient(server.base_url, _TEST_KEY)
        incident = client.get_incident("10.0.0.5")
        client.close()

        from detection.gui_dashboard import IncidentDetailDialog
        rendered = IncidentDetailDialog._render(incident)
        assert "10.0.0.5" in rendered
        assert "port_scan" in rendered
        assert "ATTACK" in rendered