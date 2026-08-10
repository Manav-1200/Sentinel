"""
detection/gui_dashboard.py

The Phase 4.2' native desktop app - PySide6 (see PHASES.md's Phase 4
section for the Tauri-vs-PySide6 decision: PySide6 chosen to stay
single-language with the rest of Sentinel). Like detection/tui_dashboard.py,
this is a REAL HTTP CLIENT of the Incidents API (api/app.py) - a
genuinely separate process, run alongside live capture the same way
the TUI is:

    Terminal 1: sudo python main.py               # live capture, starts the API
    Terminal 2: python main.py --gui               # this module, connects to it

See tui_dashboard.py's module docstring for the full reasoning on why
this is a separate process rather than in-process with capture - it
applies identically here.

Why a SYNC httpx.Client in a QThread, not the async client tui_dashboard.py uses:
--------------------------------------------------------------------
Textual is built on asyncio, so an async httpx client is the natural
fit there. Qt has its OWN event loop (QApplication.exec()), not
asyncio - mixing the two would mean either a second dependency
(qasync) or running two event loops somehow side by side. The
idiomatic Qt way to do blocking I/O without freezing the UI is a
worker QObject moved to a QThread, driven by a QTimer that also lives
on that thread - so this module uses a plain synchronous httpx.Client
instead, polled from a background QThread, with results delivered back
to the main/GUI thread via Qt signals (which Qt automatically queues
correctly across the thread boundary).

Why resolve/reopen are included here but NOT in the TUI:
--------------------------------------------------------------------
The TUI stayed deliberately read-only for v1 (see tui_dashboard.py's
docstring - "actions can be added once the read side has proven
itself"). By the time this module was built, the read side (summary,
incident list, incident detail) had already been proven working
end-to-end via the TUI - so this pass adds Resolve/Reopen buttons,
which a GUI makes a natural, low-risk addition for (a button with a
confirmation-free single click, vs. a TUI keybinding that risks a
stray keypress on a real incident).
"""

from __future__ import annotations

import os
import sys
from datetime import datetime
from typing import Optional

import httpx
from PySide6.QtCore import QObject, QThread, Qt, QTimer, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from detection.tui_dashboard import SentinelAPIError  # shared error type - same meaning, either client

_API_KEY_ENV_VAR = "SENTINEL_API_KEY"

_RISK_TIER_COLOR = {
    "LOW": QColor("#2e7d32"),
    "MEDIUM": QColor("#f9a825"),
    "HIGH": QColor("#e65100"),
    "CRITICAL": QColor("#c62828"),
}

_STATUS_COLOR = {
    "OPEN": QColor("#c62828"),
    "RESOLVED": QColor("#546e7a"),
}

# action.capitalize() + "d" looks tempting but is wrong for "reopen"
# ("reopend" instead of "reopened") - confirmed by a real headless
# test where the reopen action succeeded on the server (state genuinely
# flipped back to OPEN) but the status-bar assertion failed because the
# generated text didn't match any correct English past tense. An
# explicit mapping has no such trap.
_ACTION_PAST_TENSE = {"resolve": "Resolved", "reopen": "Reopened"}


def _format_ts(unix_timestamp: float) -> str:
    return datetime.fromtimestamp(unix_timestamp).strftime("%H:%M:%S")


class SyncSentinelAPIClient:
    """
    Synchronous counterpart to tui_dashboard.py's SentinelAPIClient -
    same endpoints, same SentinelAPIError contract, just a blocking
    httpx.Client instead of an async one, because this one is always
    called from a background QThread rather than an asyncio loop.
    Also exposes resolve/reopen, which the TUI's client deliberately
    doesn't (see module docstring).
    """

    def __init__(self, base_url: str, api_key: Optional[str], timeout_seconds: float = 5.0):
        headers = {"X-API-Key": api_key} if api_key else {}
        self._client = httpx.Client(base_url=base_url, headers=headers, timeout=timeout_seconds)

    def close(self) -> None:
        self._client.close()

    def get_summary(self) -> dict:
        return self._get("/summary")

    def get_incidents(self, include_resolved: bool = False) -> list[dict]:
        return self._get("/incidents", params={"include_resolved": include_resolved})

    def get_incident(self, key: str) -> dict:
        return self._get(f"/incidents/{key}")

    def resolve_incident(self, key: str) -> dict:
        return self._post(f"/incidents/{key}/resolve")

    def reopen_incident(self, key: str) -> dict:
        return self._post(f"/incidents/{key}/reopen")

    def _get(self, path: str, params: Optional[dict] = None) -> dict:
        return self._handle(path, lambda: self._client.get(path, params=params))

    def _post(self, path: str) -> dict:
        return self._handle(path, lambda: self._client.post(path))

    def _handle(self, path: str, call):
        try:
            response = call()
        except httpx.ConnectError as exc:
            raise SentinelAPIError(
                "Can't reach the Incidents API - is live capture running (sudo python main.py)?"
            ) from exc
        except httpx.TimeoutException as exc:
            raise SentinelAPIError("API request timed out.") from exc

        if response.status_code == 401:
            raise SentinelAPIError(
                "401 Unauthorized - SENTINEL_API_KEY is missing or doesn't match the running API's key."
            )
        if response.status_code == 500:
            raise SentinelAPIError("500 from API - likely SENTINEL_API_KEY isn't set on the API side.")
        if response.status_code == 404:
            raise SentinelAPIError(f"404 - no such resource ({path}).")
        response.raise_for_status()
        return response.json()


class ApiWorker(QObject):
    """
    Lives on a background QThread (see SentinelMainWindow._start_worker_thread).
    Every method here does blocking network I/O - never call these
    directly from the GUI thread; always go through the request_*
    signals below instead, so Qt queues the call onto this worker's
    own thread.
    """

    summary_ready = Signal(dict)
    incidents_ready = Signal(list)
    incident_detail_ready = Signal(dict)
    action_succeeded = Signal(str, dict)   # action name ("resolve"/"reopen"), result dict
    error = Signal(str)

    def __init__(self, client: SyncSentinelAPIClient, refresh_interval_ms: int):
        super().__init__()
        self._client = client
        self.show_resolved = False
        self._refresh_interval_ms = refresh_interval_ms
        # Parented to self (not created externally and moved separately)
        # so that moving the WORKER to a new thread via moveToThread()
        # automatically carries this timer's thread affinity along with
        # it - a QTimer created and moved independently of its intended
        # owner, or started via a bare lambda (neither of which gives
        # Qt a bound-QObject-method connection to resolve thread
        # affinity from), is exactly what produced "Timers cannot be
        # started from another thread" during testing.
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.poll)

    def start_polling(self) -> None:
        """Slot - connect thread.started directly to this bound method
        (no lambda in between) so Qt can resolve this call to run with
        this worker's own (post-moveToThread) thread affinity."""
        self._timer.start(self._refresh_interval_ms)
        self.poll()  # first poll immediately, don't wait a full interval

    def stop_polling(self) -> None:
        """Slot - must be called via a queued connection from the GUI
        thread (see SentinelMainWindow.closeEvent), never directly.
        A QTimer can only be stopped from the thread it lives in -
        calling self._timer.stop() directly from the GUI thread during
        shutdown produced 'Timers cannot be stopped from another
        thread' during testing; routing the stop through a slot on
        this worker (whose thread affinity IS the worker thread) is
        what makes it safe."""
        self._timer.stop()

    def poll(self) -> None:
        try:
            summary = self._client.get_summary()
            incidents = self._client.get_incidents(include_resolved=self.show_resolved)
        except SentinelAPIError as exc:
            self.error.emit(str(exc))
            return
        self.summary_ready.emit(summary)
        self.incidents_ready.emit(incidents)

    def fetch_detail(self, key: str) -> None:
        try:
            detail = self._client.get_incident(key)
        except SentinelAPIError as exc:
            self.error.emit(str(exc))
            return
        self.incident_detail_ready.emit(detail)

    def resolve(self, key: str) -> None:
        try:
            result = self._client.resolve_incident(key)
        except SentinelAPIError as exc:
            self.error.emit(str(exc))
            return
        self.action_succeeded.emit("resolve", result)

    def reopen(self, key: str) -> None:
        try:
            result = self._client.reopen_incident(key)
        except SentinelAPIError as exc:
            self.error.emit(str(exc))
            return
        self.action_succeeded.emit("reopen", result)


class IncidentDetailDialog(QDialog):
    """Modal detail view - GET /incidents/{key} rendered as plain text,
    including the full evidence timeline. Kept intentionally simple
    (a QTextEdit, not a custom-painted widget) since the content here
    is read-and-scan, not something that benefits from rich layout."""

    def __init__(self, incident: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Incident: {incident['key']}")
        self.resize(600, 500)

        layout = QVBoxLayout(self)
        text = QTextEdit(self)
        text.setReadOnly(True)
        text.setPlainText(self._render(incident))
        layout.addWidget(text)

        close_button = QPushButton("Close", self)
        close_button.clicked.connect(self.accept)
        layout.addWidget(close_button)

    @staticmethod
    def _render(incident: dict) -> str:
        risk = incident["risk"]
        lines = [
            f"Incident: {incident['key']}",
            f"Status: {incident['status']}",
            f"Highest verdict: {incident['highest_verdict']}",
            f"Risk: {risk['score']} ({risk['tier']})",
            risk["explanation"],
            "",
            f"Detectors involved: {', '.join(incident['detectors_involved'])}",
            f"First seen: {_format_ts(incident['first_seen'])}",
            f"Last seen:  {_format_ts(incident['last_seen'])}",
            "",
            f"Evidence ({len(incident['evidence'])}):",
        ]
        for ev in incident["evidence"]:
            lines.append(
                f"  [{_format_ts(ev['timestamp'])}] {ev['detector']:<12} "
                f"{ev['verdict']:<10} {ev['reasoning']}"
            )
        return "\n".join(lines)


class SentinelMainWindow(QMainWindow):
    """
    Main window: a summary strip, an open-incidents table (double-click
    a row for detail), and Resolve/Reopen/Show-resolved controls acting
    on whatever row is currently selected.
    """

    request_resolve = Signal(str)
    request_reopen = Signal(str)
    request_detail = Signal(str)
    request_stop = Signal()

    _COLUMNS = ["Key", "Status", "Verdict", "Risk", "Detectors", "Evidence", "Last seen"]

    def __init__(self, base_url: str, api_key: Optional[str], refresh_interval_seconds: float):
        super().__init__()
        self.setWindowTitle("Sentinel — Incidents")
        self.resize(1000, 600)

        self._incident_keys_by_row: list[str] = []
        self._incidents_by_key: dict[str, dict] = {}

        self._build_ui()
        self._start_worker_thread(base_url, api_key, refresh_interval_seconds)

    # ------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------

    def _build_ui(self) -> None:
        central = QWidget(self)
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        self.summary_label = QLabel("Connecting…", central)
        self.summary_label.setStyleSheet("font-weight: bold; padding: 6px;")
        layout.addWidget(self.summary_label)

        self.table = QTableWidget(0, len(self._COLUMNS), central)
        self.table.setHorizontalHeaderLabels(self._COLUMNS)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.doubleClicked.connect(self._on_row_double_clicked)
        layout.addWidget(self.table)

        controls = QHBoxLayout()
        self.show_resolved_button = QPushButton("Show resolved: Off", central)
        self.show_resolved_button.setCheckable(True)
        self.show_resolved_button.toggled.connect(self._on_toggle_resolved)
        controls.addWidget(self.show_resolved_button)

        self.resolve_button = QPushButton("Resolve selected", central)
        self.resolve_button.clicked.connect(self._on_resolve_clicked)
        controls.addWidget(self.resolve_button)

        self.reopen_button = QPushButton("Reopen selected", central)
        self.reopen_button.clicked.connect(self._on_reopen_clicked)
        controls.addWidget(self.reopen_button)

        layout.addLayout(controls)

    # ------------------------------------------------------------
    # Worker thread wiring
    # ------------------------------------------------------------

    def _start_worker_thread(self, base_url: str, api_key: Optional[str], refresh_interval_seconds: float) -> None:
        client = SyncSentinelAPIClient(base_url, api_key)
        refresh_interval_ms = int(refresh_interval_seconds * 1000)
        self._worker = ApiWorker(client, refresh_interval_ms)
        self._thread = QThread(self)
        self._worker.moveToThread(self._thread)

        self._worker.summary_ready.connect(self._on_summary_ready)
        self._worker.incidents_ready.connect(self._on_incidents_ready)
        self._worker.incident_detail_ready.connect(self._on_detail_ready)
        self._worker.action_succeeded.connect(self._on_action_succeeded)
        self._worker.error.connect(self._on_error)

        # Queued cross-thread calls - connecting a signal emitted on the
        # GUI thread to a slot living on the worker thread; Qt detects
        # the thread-affinity mismatch (self._worker and its QTimer
        # share the worker thread's affinity, see ApiWorker.__init__)
        # and auto-queues these correctly - because these are direct
        # bound-method connections, no lambda in between.
        self.request_resolve.connect(self._worker.resolve)
        self.request_reopen.connect(self._worker.reopen)
        self.request_detail.connect(self._worker.fetch_detail)
        self.request_stop.connect(self._worker.stop_polling)

        self._thread.started.connect(self._worker.start_polling)
        self._thread.start()

    def closeEvent(self, event) -> None:
        self.request_stop.emit()
        self._thread.quit()
        self._thread.wait(2000)
        event.accept()

    # ------------------------------------------------------------
    # Signal handlers (run on the GUI thread)
    # ------------------------------------------------------------

    def _on_summary_ready(self, summary: dict) -> None:
        tiers = summary["risk_tier_breakdown"]
        tier_str = "  ".join(f"{tier}: {count}" for tier, count in tiers.items())
        self.summary_label.setText(
            f"Open incidents: {summary['open_incident_count']}   {tier_str}   "
            f"Blocked IPs: {summary['blocked_ip_count']}"
        )
        self.summary_label.setStyleSheet("font-weight: bold; padding: 6px; color: black;")

    def _on_incidents_ready(self, incidents: list) -> None:
        self._incidents_by_key = {i["key"]: i for i in incidents}
        incidents_sorted = sorted(incidents, key=lambda i: i["risk"]["score"], reverse=True)

        self.table.setRowCount(len(incidents_sorted))
        self._incident_keys_by_row = []
        for row, incident in enumerate(incidents_sorted):
            risk = incident["risk"]
            self._set_cell(row, 0, incident["key"])
            self._set_cell(row, 1, incident["status"], _STATUS_COLOR.get(incident["status"]))
            self._set_cell(row, 2, incident["highest_verdict"])
            self._set_cell(row, 3, f"{risk['score']} ({risk['tier']})", _RISK_TIER_COLOR.get(risk["tier"]))
            self._set_cell(row, 4, ", ".join(incident["detectors_involved"]))
            self._set_cell(row, 5, str(incident["evidence_count"]))
            self._set_cell(row, 6, _format_ts(incident["last_seen"]))
            self._incident_keys_by_row.append(incident["key"])

    def _set_cell(self, row: int, col: int, text: str, color: Optional[QColor] = None) -> None:
        item = QTableWidgetItem(text)
        if color is not None:
            item.setForeground(color)
        self.table.setItem(row, col, item)

    def _on_detail_ready(self, incident: dict) -> None:
        dialog = IncidentDetailDialog(incident, parent=self)
        dialog.exec()

    def _on_action_succeeded(self, action: str, result: dict) -> None:
        # No manual table patch needed - the next poll (within
        # refresh_interval_seconds) will reflect the new status. This
        # keeps the table's contents always sourced from one place
        # (the last poll response), never from a locally-patched guess
        # that could drift from the server's actual state.
        self.statusBar().showMessage(f"{_ACTION_PAST_TENSE.get(action, action)} {result['key']}", 3000)

    def _on_error(self, message: str) -> None:
        self.summary_label.setText(f"⚠ {message}")
        self.summary_label.setStyleSheet("font-weight: bold; padding: 6px; color: #c62828;")

    # ------------------------------------------------------------
    # User actions (run on the GUI thread)
    # ------------------------------------------------------------

    def _selected_key(self) -> Optional[str]:
        row = self.table.currentRow()
        if row < 0 or row >= len(self._incident_keys_by_row):
            return None
        return self._incident_keys_by_row[row]

    def _on_row_double_clicked(self) -> None:
        key = self._selected_key()
        if key is not None:
            self.request_detail.emit(key)

    def _on_resolve_clicked(self) -> None:
        key = self._selected_key()
        if key is None:
            QMessageBox.information(self, "No selection", "Select an incident first.")
            return
        self.request_resolve.emit(key)

    def _on_reopen_clicked(self) -> None:
        key = self._selected_key()
        if key is None:
            QMessageBox.information(self, "No selection", "Select an incident first.")
            return
        self.request_reopen.emit(key)

    def _on_toggle_resolved(self, checked: bool) -> None:
        self._worker.show_resolved = checked
        self.show_resolved_button.setText(f"Show resolved: {'On' if checked else 'Off'}")


def run_gui(config: dict) -> None:
    """
    Entry point called from main.py's --gui flag. Reuses config.yaml's
    `api:` and `dashboard:` sections exactly like the TUI does - same
    host/port/refresh interval, since this is just another client of
    the same API.
    """
    api_config = config.get("api", {})
    host = api_config.get("host", "127.0.0.1")
    port = int(api_config.get("port", 8787))
    base_url = f"http://{host}:{port}"

    dashboard_config = config.get("dashboard", {})
    refresh_interval_seconds = float(dashboard_config.get("refresh_interval_seconds", 2.0))

    api_key = os.environ.get(_API_KEY_ENV_VAR)

    app = QApplication.instance() or QApplication(sys.argv)
    window = SentinelMainWindow(base_url, api_key, refresh_interval_seconds)
    window.show()
    app.exec()