"""
response/alerting.py
=======================
Sends alerts (email / Slack / generic webhook) when Sentinel confirms
an attack, so the operator finds out without having to watch the
live terminal table.

Why this is a separate module from detection/logger.py:
-----------------------------------------------------------
detection/logger.py (Phase 1) writes EVERY detection result to disk,
unconditionally, as a complete audit trail — it doesn't make
decisions about what's noteworthy. This module is the opposite: it
makes a judgment call about what's worth interrupting a human for,
and pushes that judgment out to email/Slack/webhook. Conflating the
two would mean either spamming alert channels with every SUSPICIOUS
flow, or losing the complete audit trail whenever a channel is
disabled — keeping them separate avoids both failure modes.

What triggers an alert:
-------------------------
This module is deliberately dumb about WHAT counts as an attack — it
trusts its caller (main.py) completely, the same way process_ddos_attack
and process_port_scan_attack trust their callers to only invoke them on
a genuine transition into ATTACK. `AlertManager.send_alert(...)` should
be called for:
  - A per-flow ATTACK verdict (flood-guard or LLM-confirmed promotion,
    see pipeline/labeller.py's promotion logic).
  - A DDoS ATTACK verdict, on the transition into it (same call site
    as labeller.process_ddos_attack).
  - A port-scan ATTACK verdict, on the transition into it, per source
    IP (same call site as labeller.process_port_scan_attack).
SUSPICIOUS verdicts are intentionally never alerted on directly —
that would defeat the purpose of having a SUSPICIOUS tier at all
(see labeller.py's verdict-promotion docstring for the false-positive
story that motivated keeping SUSPICIOUS and ATTACK distinct).

Rate limiting:
---------------
alerting.rate_limit_seconds bounds how often the SAME source IP can
generate a fresh alert, regardless of channel. A repeat offender
(e.g. a scanner that keeps re-triggering ATTACK) would otherwise
flood every configured channel — this is a per-source cooldown, not a
global one, so an alert about a genuinely NEW attacker is never
suppressed by an unrelated one currently on cooldown.

Channel isolation:
--------------------
Each channel (email, slack, webhook) is attempted independently.
A failure in one (bad SMTP credentials, Slack API down, webhook URL
unreachable) is caught, logged, and never prevents the others from
being attempted, and never propagates up to crash the live detection
pipeline — an alerting failure must never take down detection itself.
"""

from __future__ import annotations

import json
import logging
import os
import smtplib
import threading
import time
from dataclasses import dataclass, field
from email.mime.text import MIMEText
from typing import Optional

from detection.geoip_lookup import GeoIPLookup

logger = logging.getLogger("sentinel.alerting")


@dataclass
class AlertEvent:
    """
    Everything needed to describe one alert-worthy event, independent
    of which detector produced it. Callers build one of these and
    pass it to AlertManager.send_alert() — this keeps the three
    different attack sources (per-flow, ddos, port-scan) from needing
    three different method signatures on AlertManager itself.
    """
    attack_type: str          # e.g. "port_scan", "ddos", "flood", or a classifier label
    src_ip: str
    verdict: str              # "ATTACK" — kept as a field for message formatting/future reuse
    reasoning: Optional[str] = None
    extra: dict = field(default_factory=dict)  # detector-specific detail (ports touched, pps, etc.)


class AlertManager:
    """
    Dispatches alerts to whichever channels are enabled in
    config.yaml's `alerting` section, with per-source-IP rate
    limiting. Construct ONE instance and share it across the whole
    pipeline (same pattern as LLMAnalyser/GlobalRateTracker), since
    rate-limiting state must be shared to be meaningful.
    """

    def __init__(self, config: dict, geoip: Optional[GeoIPLookup] = None):
        """
        geoip is accepted as an optional, already-constructed instance
        (rather than building one internally) so it can be shared with
        other callers (e.g. a future dashboard) and so tests can inject
        a fake lookup without needing real network/DB access — same
        reasoning as Labeller accepting an external LLMAnalyser.
        """
        alerting_config = config.get("alerting", {})
        self.rate_limit_seconds: float = float(alerting_config.get("rate_limit_seconds", 600))

        self.email_config: dict = alerting_config.get("email", {})
        self.slack_config: dict = alerting_config.get("slack", {})
        self.webhook_config: dict = alerting_config.get("webhook", {})

        self.geoip = geoip

        # Per-source-IP cooldown tracking: src_ip -> last alert unix timestamp.
        self._last_alert_time: dict[str, float] = {}
        self._lock = threading.Lock()

        self._requests = None
        if self.slack_config.get("enabled") or self.webhook_config.get("enabled"):
            try:
                import requests
                self._requests = requests
            except ImportError:
                logger.warning(
                    "Slack and/or webhook alerting is enabled but the 'requests' library "
                    "is not installed (pip install requests). Those channels will be "
                    "skipped until it's installed."
                )

        if alerting_config.get("test_on_startup"):
            self._send_test_alert()

    def send_alert(self, event: AlertEvent) -> None:
        """
        Attempt to send `event` to every enabled channel, subject to
        per-source-IP rate limiting. Never raises — a totally failed
        alert (rate-limited, or every channel erroring) is logged and
        swallowed, since a failure here must never interrupt the live
        detection pipeline that called it.
        """
        if not self._should_alert(event.src_ip):
            logger.debug(
                "Alert for %s suppressed (rate limit, last alert < %.0fs ago).",
                event.src_ip, self.rate_limit_seconds,
            )
            return

        location = "location unknown"
        if self.geoip is not None:
            try:
                geo_result = self.geoip.lookup(event.src_ip)
                location = geo_result.display_str()
            except Exception as e:
                # A GeoIP failure must never block the alert itself —
                # worst case, the alert just says "location unknown".
                logger.debug("GeoIP enrichment failed for %s: %s", event.src_ip, e)

        subject, body = self._format_message(event, location)

        if self.email_config.get("enabled"):
            self._safe_send("email", self._send_email, subject, body)
        if self.slack_config.get("enabled") and self._requests is not None:
            self._safe_send("slack", self._send_slack, subject, body)
        if self.webhook_config.get("enabled") and self._requests is not None:
            self._safe_send("webhook", self._send_webhook, event, subject, body)

    # ------------------------------------------------------------
    # Internal — rate limiting
    # ------------------------------------------------------------

    def _should_alert(self, src_ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            last = self._last_alert_time.get(src_ip)
            if last is not None and (now - last) < self.rate_limit_seconds:
                return False
            self._last_alert_time[src_ip] = now
            return True

    # ------------------------------------------------------------
    # Internal — message formatting
    # ------------------------------------------------------------

    def _format_message(self, event: AlertEvent, location: str) -> tuple[str, str]:
        subject = f"[Sentinel] {event.verdict}: {event.attack_type} from {event.src_ip}"

        lines = [
            f"Sentinel detected a confirmed {event.verdict.lower()}.",
            "",
            f"Attack type : {event.attack_type}",
            f"Source IP   : {event.src_ip}",
            f"Location    : {location}",
        ]
        if event.reasoning:
            lines += ["", f"Reasoning: {event.reasoning}"]
        if event.extra:
            lines += ["", "Additional detail:"]
            for key, value in event.extra.items():
                lines.append(f"  {key}: {value}")

        body = "\n".join(lines)
        return subject, body

    # ------------------------------------------------------------
    # Internal — per-channel senders
    # ------------------------------------------------------------

    def _safe_send(self, channel_name: str, fn, *args) -> None:
        """
        Runs one channel's send function, isolating any failure so it
        never propagates to the caller or blocks other channels. This
        is the single point where all three channels' exceptions are
        caught — individual _send_* methods are allowed to let
        exceptions bubble up to here.
        """
        try:
            fn(*args)
        except Exception as e:
            logger.warning("Failed to send %s alert: %s", channel_name, e)

    def _send_email(self, subject: str, body: str) -> None:
        smtp_host = self.email_config.get("smtp_host", "smtp.gmail.com")
        smtp_port = int(self.email_config.get("smtp_port", 587))
        sender = self.email_config.get("sender") or os.environ.get("SENTINEL_EMAIL_SENDER")
        recipient = self.email_config.get("recipient") or os.environ.get("SENTINEL_EMAIL_RECIPIENT")
        password = os.environ.get("SENTINEL_EMAIL_PASSWORD")

        if not sender or not recipient or not password:
            raise RuntimeError(
                "Email alerting is enabled but sender/recipient/password are not fully "
                "configured. Set SENTINEL_EMAIL_SENDER, SENTINEL_EMAIL_RECIPIENT, and "
                "SENTINEL_EMAIL_PASSWORD in .env (or sender/recipient directly in "
                "config.yaml's alerting.email section)."
            )

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = recipient

        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.starttls()
            server.login(sender, password)
            server.sendmail(sender, [recipient], msg.as_string())

    def _send_slack(self, subject: str, body: str) -> None:
        webhook_url = os.environ.get("SENTINEL_SLACK_WEBHOOK")
        if not webhook_url:
            raise RuntimeError(
                "Slack alerting is enabled but SENTINEL_SLACK_WEBHOOK is not set in .env."
            )

        payload = {"text": f"*{subject}*\n```{body}```"}
        response = self._requests.post(webhook_url, json=payload, timeout=5)
        response.raise_for_status()

    def _send_webhook(self, event: AlertEvent, subject: str, body: str) -> None:
        webhook_url = os.environ.get("SENTINEL_WEBHOOK_URL")
        if not webhook_url:
            raise RuntimeError(
                "Webhook alerting is enabled but SENTINEL_WEBHOOK_URL is not set in .env."
            )

        payload = {
            "subject": subject,
            "body": body,
            "attack_type": event.attack_type,
            "src_ip": event.src_ip,
            "verdict": event.verdict,
            "reasoning": event.reasoning,
            "extra": event.extra,
        }
        response = self._requests.post(webhook_url, json=payload, timeout=5)
        response.raise_for_status()

    # ------------------------------------------------------------
    # Internal — startup self-test
    # ------------------------------------------------------------

    def _send_test_alert(self) -> None:
        """
        Fires a synthetic alert through every enabled channel on
        startup, when alerting.test_on_startup is true. Bypasses rate
        limiting (uses a dedicated fake source IP) so it always fires
        exactly once per startup, regardless of recent real alerts.
        """
        logger.info("Sending test alert (alerting.test_on_startup=true)...")
        test_event = AlertEvent(
            attack_type="test",
            src_ip="0.0.0.0",
            verdict="TEST",
            reasoning="This is a startup self-test alert, not a real detection.",
        )
        subject, body = self._format_message(test_event, location="N/A (test alert)")

        if self.email_config.get("enabled"):
            self._safe_send("email", self._send_email, subject, body)
        if self.slack_config.get("enabled") and self._requests is not None:
            self._safe_send("slack", self._send_slack, subject, body)
        if self.webhook_config.get("enabled") and self._requests is not None:
            self._safe_send("webhook", self._send_webhook, test_event, subject, body)