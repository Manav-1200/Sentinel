"""
detection/cli_display.py
==========================
Live, colour-coded terminal display for Sentinel's detection results.

This module owns ONLY presentation — it takes DetectionResult objects
(from detection/anomaly.py) and renders them as a live-updating table
in the terminal using the `rich` library. It does not make any
decisions about what's an attack; it just displays whatever verdict
it's given.

Kept as a separate module (rather than inline in main.py) so the
display logic can be swapped out later — e.g. once the web dashboard
(Phase 4) exists, this CLI table becomes optional/secondary rather
than the only way to see what Sentinel is doing.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime

from rich.console import Console
from rich.live import Live
from rich.table import Table

from detection.anomaly import DetectionResult, Verdict
from detection.ddos_tracker import DDoSCheckResult, DDoSVerdict


# Colour mapping for each verdict — used consistently across the
# table rows so the eye can scan for red/yellow instantly.
_VERDICT_STYLE = {
    Verdict.NORMAL: "green",
    Verdict.SUSPICIOUS: "yellow",
    Verdict.ATTACK: "bold red",
    Verdict.WARMING_UP: "dim cyan",
}

_PROTOCOL_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP"}


class LiveDetectionDisplay:
    """
    Maintains a rolling window of the most recent detection results
    and renders them as a live-updating `rich` table.

    Usage:
        display = LiveDetectionDisplay(max_rows=20)
        with display:
            for result in stream_of_detection_results:
                display.add(result)
    """

    def __init__(self, max_rows: int = 20):
        self.max_rows = max_rows
        # Each entry is (DetectionResult, predicted_label_or_None) —
        # the predicted label comes from the Phase 2 supervised
        # classifier (detection/classifier.py), shown alongside the
        # anomaly detector's bare verdict whenever a trained
        # classifier is available. None means either no classifier is
        # trained yet, or this particular flow wasn't flagged enough
        # to warrant classification.
        self._recent_results: deque[tuple[DetectionResult, str | None]] = deque(maxlen=max_rows)
        self._console = Console()
        self._live: Live | None = None

        # Running counters shown in the table footer — give a sense
        # of overall activity even though only the last N rows are
        # visible at once.
        self.total_flows_seen = 0
        self.counts = {verdict: 0 for verdict in Verdict}

        # Set externally by main.py from sniffer.dropped_packet_count
        # before each render, so packet loss under heavy load is
        # always visible to the operator rather than silent. See
        # docs/performance.md for what this means and how to fix it.
        self.dropped_packet_count = 0

        # Current aggregate DDoS status, set via set_ddos_status().
        # None means no DDoS check has run yet (e.g. still in warm-up).
        # This is deliberately a SEPARATE, system-wide status — unlike
        # individual flow rows, a DDoS verdict describes the overall
        # state of the network right now, not any one flow, so it's
        # shown prominently in the table title rather than as a row.
        self._ddos_status: DDoSCheckResult | None = None

    def __enter__(self) -> "LiveDetectionDisplay":
        self._live = Live(self._render(), console=self._console, refresh_per_second=4)
        self._live.__enter__()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self._live is not None:
            self._live.__exit__(exc_type, exc_value, traceback)

    def add(self, result: DetectionResult, predicted_label: str | None = None) -> None:
        """
        Add a new detection result and refresh the live table.

        predicted_label is an optional attack-type prediction from the
        Phase 2 supervised classifier (e.g. "port_scan", "ddos") —
        only meaningful once enough labelled data exists to have
        trained a classifier at all. None (the default) means no
        classifier prediction is available for this flow, and the
        display falls back to showing just the anomaly verdict, which
        is the correct, expected behaviour during Phase 1-only
        operation or before enough data has accumulated.
        """
        self._recent_results.append((result, predicted_label))
        self.total_flows_seen += 1
        self.counts[result.verdict] += 1

        if self._live is not None:
            self._live.update(self._render())

    def set_ddos_status(self, ddos_result: DDoSCheckResult) -> None:
        """
        Update the current aggregate DDoS status and refresh the
        display. Called by main.py only on verdict TRANSITIONS (not
        every single flow) to avoid spamming re-renders — but it's
        safe to call this every flow too, since rendering is cheap.
        """
        self._ddos_status = ddos_result
        if self._live is not None:
            self._live.update(self._render())

    def _render(self) -> Table:
        table = Table(
            title=self._title(),
            caption=self._caption(),
            expand=True,
        )
        table.add_column("Time", style="dim", width=8)
        table.add_column("Proto", width=5)
        table.add_column("Source", overflow="fold")
        table.add_column("Destination", overflow="fold")
        table.add_column("Pkts", justify="right", width=5)
        table.add_column("Score", justify="right", width=8)
        table.add_column("Verdict", width=11)
        table.add_column("Attack Type", width=14)

        for result, predicted_label in self._recent_results:
            features = result.features
            proto_name = _PROTOCOL_NAMES.get(features.get("protocol"), str(features.get("protocol")))
            score_str = f"{result.score:.4f}" if result.score is not None else "—"
            style = _VERDICT_STYLE[result.verdict]
            # "—" when no classifier prediction is available for this
            # row (no trained classifier yet, or this flow wasn't
            # flagged enough to warrant classification) — never
            # fabricated, always an honest absence marker.
            label_str = predicted_label if predicted_label is not None else "—"

            table.add_row(
                datetime.now().strftime("%H:%M:%S"),
                proto_name,
                f"{features.get('src_ip', '?')}:{features.get('src_port', '?')}",
                f"{features.get('dst_ip', '?')}:{features.get('dst_port', '?')}",
                str(features.get("total_packets", "?")),
                score_str,
                f"[{style}]{result.verdict.value}[/{style}]",
                label_str,
            )

        return table

    def _title(self) -> str:
        base_title = "Sentinel — Live Flow Detection"

        if self._ddos_status is None or self._ddos_status.verdict == DDoSVerdict.NORMAL:
            return base_title

        if self._ddos_status.verdict == DDoSVerdict.ATTACK:
            style = "bold red"
            label = "POSSIBLE DDoS IN PROGRESS"
        else:
            style = "yellow"
            label = "ELEVATED AGGREGATE TRAFFIC"

        return (
            f"{base_title}   "
            f"[{style}]\u26a0 {label} "
            f"({self._ddos_status.total_flows_in_window} flows / "
            f"{self._ddos_status.distinct_sources_in_window} sources "
            f"in {self._ddos_status.window_seconds:.0f}s)[/{style}]"
        )

    def _caption(self) -> str:
        base = (
            f"Total flows: {self.total_flows_seen}  |  "
            f"Normal: {self.counts[Verdict.NORMAL]}  "
            f"Suspicious: {self.counts[Verdict.SUSPICIOUS]}  "
            f"Attack: {self.counts[Verdict.ATTACK]}  "
            f"Warming up: {self.counts[Verdict.WARMING_UP]}"
        )
        if self.dropped_packet_count > 0:
            # Packet loss is never silent — flagged clearly so the
            # operator knows detection may be incomplete under load.
            # See docs/performance.md for remediation.
            base += f"  |  [bold yellow]Dropped packets: {self.dropped_packet_count}[/bold yellow]"
        return base