"""
detection/cli_display.py
==========================
Live terminal display for Sentinel's detection results.

This module owns ONLY presentation — it takes DetectionResult objects
(from detection/anomaly.py) and prints them. It does not make any
decisions about what's an attack; it just displays whatever verdict
it's given.

Design note — why this is no longer a `rich.Live` table:
------------------------------------------------------------
The previous version used `rich.live.Live` to redraw a fixed-size
table in place. That's exactly why it never scrolled: Live is
*designed* to overwrite, not append, so anything older than
`max_rows` was gone with no way to review it — a real problem if a
packet burst went by while you were looking away.

This version prints ONE line per flow via `console.print()` instead.
That's ordinary terminal output, which means your terminal's native
scrollback (or `less`, or tmux copy-mode) captures everything, not
just the last N rows. Nothing is ever silently lost from view.

Status column accuracy:
---------------------------
The "Status" column shown for each flow is never computed or cached
here — it's a live call to `blocker.is_blocked(src_ip)` at the moment
the row is printed. This is deliberate: `blocker` is the exact same
object main.py calls to perform real blocks, so this column can never
drift out of sync with reality (e.g. showing BLOCKED for something
that was never actually blocked, or missing a block that happened).
If no blocker is wired in (blocker=None), the column shows "—" rather
than guessing.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.panel import Panel

from detection.anomaly import DetectionResult, Verdict
from detection.ddos_tracker import DDoSCheckResult, DDoSVerdict

# Colour mapping for each verdict — used consistently so the eye can
# scan for red/yellow instantly while scrolling.
_VERDICT_STYLE = {
    Verdict.NORMAL: "green",
    Verdict.SUSPICIOUS: "yellow",
    Verdict.ATTACK: "bold red",
    Verdict.WARMING_UP: "dim cyan",
}

_PROTOCOL_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP"}

# How often (in flows) to reprint a running summary line, so a long
# scrolling session still gives an at-a-glance status without having
# to scroll back and recount.
_SUMMARY_EVERY_N_FLOWS = 50


class LiveDetectionDisplay:
    """
    Prints one line per detection result as it happens, plus periodic
    summary lines and DDoS status changes. Everything printed stays
    in the terminal's scrollback — this class holds no "current view"
    that can overwrite older rows.

    Usage:
        display = LiveDetectionDisplay(blocker=blocker)
        with display:
            for result in stream_of_detection_results:
                display.add(result)
    """

    def __init__(self, max_rows: int = 20, blocker=None):
        # max_rows is kept as a constructor argument for backward
        # compatibility with existing call sites, but no longer bounds
        # what's visible — every row is printed and kept in
        # scrollback. It's unused internally now.
        self.max_rows = max_rows
        self.blocker = blocker
        self._console = Console()

        self.total_flows_seen = 0
        self.counts = {verdict: 0 for verdict in Verdict}
        self.dropped_packet_count = 0

        self._ddos_status: Optional[DDoSCheckResult] = None
        self._last_dropped_notified = 0

    def __enter__(self) -> "LiveDetectionDisplay":
        self._console.print(Panel.fit(
            "[bold cyan]Live flow log[/bold cyan] — every flow is printed and kept in your "
            "terminal's scrollback (scroll up / use search / pipe to `less` to review anything).",
            border_style="cyan",
        ))
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        # Nothing to tear down — there's no Live session to close.
        pass

    def add(self, result: DetectionResult, predicted_label: str | None = None) -> None:
        """
        Print one line for this detection result and update running
        counters. predicted_label is an optional attack-type
        prediction from the Phase 2 classifier — "—" is shown when
        none is available (no classifier trained yet, or this flow
        wasn't flagged enough to warrant classification).
        """
        self.total_flows_seen += 1
        self.counts[result.verdict] += 1

        self._console.print(self._format_row(result, predicted_label))

        # Packet-loss warnings must never be silent, but also
        # shouldn't spam a line for every single flow — repeat every
        # time the dropped count has grown since the last notice.
        if self.dropped_packet_count > self._last_dropped_notified:
            self._console.print(
                f"  [bold yellow]⚠ Dropped packets so far: {self.dropped_packet_count} "
                f"(capture buffer overloaded — see docs/performance.md)[/bold yellow]"
            )
            self._last_dropped_notified = self.dropped_packet_count

        if self.total_flows_seen % _SUMMARY_EVERY_N_FLOWS == 0:
            self._print_summary_line()

    def set_ddos_status(self, ddos_result: DDoSCheckResult) -> None:
        """
        Print a highlighted line on a DDoS status change. Called by
        main.py only on verdict TRANSITIONS, so this fires once per
        state change rather than once per flow.
        """
        self._ddos_status = ddos_result
        if ddos_result.verdict == DDoSVerdict.ATTACK:
            self._console.print(
                f"[bold red]⚠ POSSIBLE DDoS IN PROGRESS[/bold red] — "
                f"{ddos_result.total_flows_in_window} flows / "
                f"{ddos_result.distinct_sources_in_window} sources "
                f"in {ddos_result.window_seconds:.0f}s"
            )
        elif ddos_result.verdict == DDoSVerdict.SUSPICIOUS:
            self._console.print(
                f"[yellow]⚠ Elevated aggregate traffic[/yellow] — "
                f"{ddos_result.total_flows_in_window} flows / "
                f"{ddos_result.distinct_sources_in_window} sources "
                f"in {ddos_result.window_seconds:.0f}s"
            )
        else:
            self._console.print("[dim]Aggregate traffic back to normal.[/dim]")

    def print_summary(self) -> None:
        """Public wrapper so main.py can request an on-demand summary
        line (e.g. right before printing the shutdown report)."""
        self._print_summary_line()

    # ------------------------------------------------------------
    # Internal — row / summary formatting
    # ------------------------------------------------------------

    def _format_row(self, result: DetectionResult, predicted_label: str | None) -> str:
        features = result.features
        proto_name = _PROTOCOL_NAMES.get(features.get("protocol"), str(features.get("protocol")))
        score_str = f"{result.score:.4f}" if result.score is not None else "—"
        style = _VERDICT_STYLE[result.verdict]
        label_str = predicted_label if predicted_label is not None else "—"

        src_ip = features.get("src_ip", "?")
        src = f"{src_ip}:{features.get('src_port', '?')}"
        dst = f"{features.get('dst_ip', '?')}:{features.get('dst_port', '?')}"
        pkts = features.get("total_packets", "?")
        time_str = datetime.now().strftime("%H:%M:%S")

        status_str, status_style = self._status_for(src_ip)

        return (
            f"[dim]{time_str}[/dim] "
            f"{proto_name:<5} "
            f"{src:<21} -> {dst:<21} "
            f"pkts={pkts!s:<5} "
            f"score={score_str:<8} "
            f"[{style}]{result.verdict.value:<10}[/{style}] "
            f"type={label_str:<14} "
            f"[{status_style}]{status_str}[/{status_style}]"
        )

    def _status_for(self, src_ip: str) -> tuple[str, str]:
        """
        Live status lookup — always asks `blocker` directly, never a
        locally cached flag, so this can never disagree with reality.
        Returns (label, rich_style).
        """
        if self.blocker is None:
            return "—", "dim"
        try:
            blocked = self.blocker.is_blocked(src_ip)
        except Exception:
            # A blocker query failure must never crash the display —
            # show unknown rather than guessing either way.
            return "UNKNOWN", "dim"
        return ("BLOCKED", "bold red") if blocked else ("ALLOWED", "green")

    def _print_summary_line(self) -> None:
        base = (
            f"[bold]-- summary after {self.total_flows_seen} flows --[/bold]  "
            f"Normal: {self.counts[Verdict.NORMAL]}  "
            f"Suspicious: {self.counts[Verdict.SUSPICIOUS]}  "
            f"Attack: {self.counts[Verdict.ATTACK]}  "
            f"Warming up: {self.counts[Verdict.WARMING_UP]}"
        )
        if self.dropped_packet_count > 0:
            base += f"  [bold yellow]Dropped: {self.dropped_packet_count}[/bold yellow]"
        if self.blocker is not None:
            blocked_count = len(self.blocker.currently_blocked())
            base += f"  Currently blocked IPs: {blocked_count}"
        self._console.print(base)