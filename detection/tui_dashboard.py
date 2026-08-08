"""
detection/tui_dashboard.py

The Phase 4.2' Textual dashboard - see PHASES.md's Phase 4 section for
the original design decision. This is a REAL HTTP CLIENT of the
Incidents API (api/app.py), not an in-process view - it never touches
CorrelationEngine, the DB, or any other Sentinel internals directly.

Why this is a separate process from live capture, not embedded in it:
--------------------------------------------------------------------
Textual apps take over the terminal (alternate screen, their own
asyncio event loop) the same way `top` or `htop` does. Sentinel's live
capture already owns the terminal for cli_display.py's flat scrolling
log. Trying to run both the capture loop AND a Textual app in the same
process/terminal would mean either fighting over terminal control or
a much bigger integration than this phase needs.

The actual intended usage is two terminals:
    Terminal 1: sudo python main.py                 # live capture, starts the API
    Terminal 2: python main.py --dashboard           # this module, connects to it

This is also exactly the point of having built the Incidents API
BEFORE the dashboard (see api/app.py's module docstring) - the
dashboard is a genuine API client, so it works identically whether
it's running on the same box or a different one on the network, and
whether the thing on the other end is a live capture run or a pcap
replay's leftover process (pcap replay doesn't start an API server -
see main.py's run_pcap - so the dashboard has nothing to connect to
during a pcap run; that's expected, not a bug).

Why httpx.AsyncClient, not requests:
--------------------------------------------------------------------
Textual apps run on asyncio. requests is a blocking/synchronous
client - calling it directly from an async method would stall the
entire UI (no key handling, no redraw) for the duration of every HTTP
call. httpx's async client is a drop-in equivalent that plays
correctly with Textual's event loop instead.

What v1 does NOT do:
--------------------------------------------------------------------
No websocket/push updates - api/app.py doesn't expose one, so this
polls /summary and /incidents on a timer (dashboard.refresh_interval_
seconds in config.yaml, default 2.0s) via Textual's set_interval. A
push-based version is a reasonable Phase 4.3 candidate once the polling
version has proven the API's shape is actually sufficient in practice.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Optional

import httpx
from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Header, Static

# Mirrors api/auth.py's env var name exactly - the dashboard is just
# another client of the same auth scheme every other API consumer uses.
_API_KEY_ENV_VAR = "SENTINEL_API_KEY"

_RISK_TIER_STYLE = {
    "LOW": "green",
    "MEDIUM": "yellow",
    "HIGH": "bold orange3",
    "CRITICAL": "bold red",
}

_STATUS_STYLE = {
    "OPEN": "bold red",
    "RESOLVED": "dim green",
}


class SentinelAPIError(Exception):
    """Raised for any API call failure - connection refused, timeout,
    auth failure, unexpected status. Caught at the call site and shown
    as a status message rather than crashing the whole TUI, since a
    momentary API hiccup (or the capture process not being up yet)
    shouldn't kill the dashboard - it should just show "disconnected"
    and keep retrying on the next poll."""


class SentinelAPIClient:
    """
    Thin async wrapper over the three GET endpoints the dashboard
    needs. Deliberately does NOT wrap the resolve/reopen actions -
    v1 is read-only/observational, matching the "fuller v1: summary +
    incidents list + incident detail" scope decided for this pass.
    Actions can be added once the read side has proven itself.
    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str],
        timeout_seconds: float = 5.0,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ):
        """
        transport: normally left None (real network I/O against
        base_url). Tests pass httpx.ASGITransport(app=api_app) instead,
        so the API client can be exercised against a real FastAPI app
        object in-process - no real socket, no background server
        thread, no port-collision flakiness - while still going
        through the exact same request/response code path production
        traffic does.
        """
        headers = {"X-API-Key": api_key} if api_key else {}
        self._client = httpx.AsyncClient(
            base_url=base_url, headers=headers, timeout=timeout_seconds, transport=transport
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def get_summary(self) -> dict:
        return await self._get("/summary")

    async def get_incidents(self, include_resolved: bool = False) -> list[dict]:
        return await self._get("/incidents", params={"include_resolved": include_resolved})

    async def get_incident(self, key: str) -> dict:
        return await self._get(f"/incidents/{key}")

    async def _get(self, path: str, params: Optional[dict] = None):
        try:
            response = await self._client.get(path, params=params)
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


class SummaryPanel(Static):
    """Top headline strip - GET /summary rendered as a single line of
    stat blocks, refreshed on the same timer as everything else."""

    summary_data: reactive[Optional[dict]] = reactive(None)
    connection_error: reactive[Optional[str]] = reactive(None)

    def render(self) -> Text:
        if self.connection_error:
            return Text(f"⚠ {self.connection_error}", style="bold red")

        if self.summary_data is None:
            return Text("Connecting…", style="dim")

        s = self.summary_data
        tiers = s["risk_tier_breakdown"]
        tier_str = "  ".join(
            f"[{_RISK_TIER_STYLE.get(tier, 'white')}]{tier}: {count}[/]"
            for tier, count in tiers.items()
        )
        text = Text()
        text.append(f" Open incidents: {s['open_incident_count']}   ", style="bold")
        text.append_text(Text.from_markup(tier_str))
        text.append(f"   Blocked IPs: {s['blocked_ip_count']} ", style="bold")
        return text


class IncidentDetailScreen(ModalScreen):
    """Full-detail view for one incident - GET /incidents/{key},
    including its evidence timeline. Pushed as a modal so Escape
    always returns cleanly to the incident list underneath, rather
    than needing its own separate refresh/navigation state."""

    BINDINGS = [Binding("escape", "dismiss", "Back")]

    def __init__(self, client: SentinelAPIClient, incident_key: str):
        super().__init__()
        self._client = client
        self._incident_key = incident_key

    def compose(self) -> ComposeResult:
        with Vertical(id="detail-container"):
            yield Static("Loading…", id="detail-body")
        yield Footer()

    def on_mount(self) -> None:
        self._load()

    @work(exclusive=True)
    async def _load(self) -> None:
        body = self.query_one("#detail-body", Static)
        try:
            incident = await self._client.get_incident(self._incident_key)
        except SentinelAPIError as exc:
            body.update(Text(f"⚠ {exc}", style="bold red"))
            return
        body.update(self._render_incident(incident))

    def _render_incident(self, incident: dict) -> Text:
        text = Text()
        status_style = _STATUS_STYLE.get(incident["status"], "white")
        text.append(f"Incident: {incident['key']}\n", style="bold underline")
        text.append("Status: ", style="bold")
        text.append(f"{incident['status']}\n", style=status_style)
        text.append(f"Highest verdict: {incident['highest_verdict']}\n")
        risk = incident["risk"]
        tier_style = _RISK_TIER_STYLE.get(risk["tier"], "white")
        text.append("Risk: ", style="bold")
        text.append(f"{risk['score']} ({risk['tier']})\n", style=tier_style)
        text.append(f"{risk['explanation']}\n\n", style="dim")
        text.append(f"Detectors involved: {', '.join(incident['detectors_involved'])}\n")
        text.append(f"First seen: {_format_ts(incident['first_seen'])}\n")
        text.append(f"Last seen:  {_format_ts(incident['last_seen'])}\n\n")

        text.append(f"Evidence ({len(incident['evidence'])}):\n", style="bold underline")
        for ev in incident["evidence"]:
            text.append(f"  [{_format_ts(ev['timestamp'])}] ", style="dim")
            text.append(f"{ev['detector']:<12} ", style="bold")
            text.append(f"{ev['verdict']:<10} ")
            text.append(f"{ev['reasoning']}\n")

        text.append("\n[Esc to go back]", style="dim italic")
        return text


class SentinelDashboardApp(App):
    """
    Main Textual app. Polls /summary and /incidents on a timer and
    renders: the SummaryPanel strip, plus a DataTable of open
    incidents. Selecting a row (Enter) opens IncidentDetailScreen for
    the full evidence timeline. Toggle "r" to include resolved
    incidents in the list.
    """

    CSS = """
    SummaryPanel {
        height: 3;
        background: $panel;
        content-align: center middle;
        border: solid $primary;
    }
    #detail-container {
        background: $surface;
        border: thick $primary;
        margin: 4 8;
        padding: 1 2;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "toggle_resolved", "Toggle resolved"),
        Binding("enter", "open_selected", "Open incident"),
    ]

    show_resolved: reactive[bool] = reactive(False)

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str],
        refresh_interval_seconds: float,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ):
        super().__init__()
        self._client = SentinelAPIClient(base_url, api_key, transport=transport)
        self._refresh_interval_seconds = refresh_interval_seconds
        self._incident_keys_by_row: list[str] = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield SummaryPanel(id="summary")
        with VerticalScroll():
            yield DataTable(id="incidents-table", cursor_type="row", zebra_stripes=True)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#incidents-table", DataTable)
        table.add_columns("Key", "Status", "Verdict", "Risk", "Detectors", "Evidence", "Last seen")
        self._poll()
        self.set_interval(self._refresh_interval_seconds, self._poll)

    async def on_unmount(self) -> None:
        await self._client.close()

    def action_toggle_resolved(self) -> None:
        self.show_resolved = not self.show_resolved
        self._poll()

    def action_open_selected(self) -> None:
        table = self.query_one("#incidents-table", DataTable)
        if table.cursor_row is None or table.cursor_row >= len(self._incident_keys_by_row):
            return
        key = self._incident_keys_by_row[table.cursor_row]
        self.push_screen(IncidentDetailScreen(self._client, key))

    @work(exclusive=True)
    async def _poll(self) -> None:
        summary_panel = self.query_one(SummaryPanel)
        try:
            summary = await self._client.get_summary()
            incidents = await self._client.get_incidents(include_resolved=self.show_resolved)
        except SentinelAPIError as exc:
            summary_panel.connection_error = str(exc)
            return

        summary_panel.connection_error = None
        summary_panel.summary_data = summary
        self._render_incidents_table(incidents)

    def _render_incidents_table(self, incidents: list[dict]) -> None:
        table = self.query_one("#incidents-table", DataTable)
        table.clear()
        self._incident_keys_by_row = []

        # Highest risk first - the whole point of a dashboard is
        # "what needs my attention right now", not chronological order.
        incidents_sorted = sorted(incidents, key=lambda i: i["risk"]["score"], reverse=True)

        for incident in incidents_sorted:
            risk = incident["risk"]
            table.add_row(
                incident["key"],
                Text(incident["status"], style=_STATUS_STYLE.get(incident["status"], "white")),
                incident["highest_verdict"],
                Text(f"{risk['score']} ({risk['tier']})", style=_RISK_TIER_STYLE.get(risk["tier"], "white")),
                ", ".join(incident["detectors_involved"]),
                str(incident["evidence_count"]),
                _format_ts(incident["last_seen"]),
            )
            self._incident_keys_by_row.append(incident["key"])


def _format_ts(unix_timestamp: float) -> str:
    return datetime.fromtimestamp(unix_timestamp).strftime("%H:%M:%S")


def run_dashboard(config: dict) -> None:
    """
    Entry point called from main.py's --dashboard flag. Connects to
    whatever host/port config.yaml's `api:` section says (the same
    section live capture uses to START the API) - the dashboard is
    just another client of it, so it reuses that config rather than
    needing its own separate host/port settings.
    """
    api_config = config.get("api", {})
    host = api_config.get("host", "127.0.0.1")
    port = int(api_config.get("port", 8787))
    base_url = f"http://{host}:{port}"

    dashboard_config = config.get("dashboard", {})
    refresh_interval_seconds = float(dashboard_config.get("refresh_interval_seconds", 2.0))

    api_key = os.environ.get(_API_KEY_ENV_VAR)

    app = SentinelDashboardApp(base_url, api_key, refresh_interval_seconds)
    app.run()