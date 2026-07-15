"""
tests/test_alerting.py
==========================
Unit tests for response/alerting.py (AlertManager).

All three channels are mocked — smtplib.SMTP and requests.post never
touch anything real. Focus areas: rate limiting correctness, channel
isolation (one failing channel must never stop the others or bubble
up to the caller), and that disabled channels are truly never called.
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from response.alerting import AlertManager, AlertEvent


def make_config(**overrides):
    alerting = {
        "rate_limit_seconds": 600,
        "email": {"enabled": False},
        "slack": {"enabled": False},
        "webhook": {"enabled": False},
    }
    alerting.update(overrides)
    return {"alerting": alerting}


def make_event(src_ip="198.51.101.5", attack_type="port_scan"):
    return AlertEvent(
        attack_type=attack_type,
        src_ip=src_ip,
        verdict="ATTACK",
        reasoning="touched 30 ports in 10s",
        extra={"distinct_ports_in_window": 30},
    )


# ------------------------------------------------------------
# Rate limiting
# ------------------------------------------------------------

class TestRateLimiting:
    def test_second_alert_for_same_ip_within_window_is_suppressed(self):
        manager = AlertManager(make_config(email={"enabled": True, "sender": "a@x.com",
                                                    "recipient": "b@x.com"}))
        with patch.object(manager, "_send_email") as mock_send:
            manager.send_alert(make_event())
            manager.send_alert(make_event())  # same src_ip, immediately after

        assert mock_send.call_count == 1

    def test_different_source_ip_is_never_suppressed_by_another_ips_cooldown(self):
        manager = AlertManager(make_config(email={"enabled": True, "sender": "a@x.com",
                                                    "recipient": "b@x.com"}))
        with patch.object(manager, "_send_email") as mock_send:
            manager.send_alert(make_event(src_ip="198.51.101.5"))
            manager.send_alert(make_event(src_ip="198.51.101.6"))

        assert mock_send.call_count == 2

    def test_alert_allowed_again_after_rate_limit_window_elapses(self):
        manager = AlertManager(make_config(
            rate_limit_seconds=1,
            email={"enabled": True, "sender": "a@x.com", "recipient": "b@x.com"},
        ))
        with patch.object(manager, "_send_email") as mock_send:
            with patch("response.alerting.time.monotonic", return_value=1000.0):
                manager.send_alert(make_event())
            with patch("response.alerting.time.monotonic", return_value=1002.0):
                manager.send_alert(make_event())

        assert mock_send.call_count == 2


# ------------------------------------------------------------
# Channel isolation
# ------------------------------------------------------------

class TestChannelIsolation:
    def test_email_failure_does_not_prevent_slack_from_firing(self):
        config = make_config(
            email={"enabled": True, "sender": "a@x.com", "recipient": "b@x.com"},
            slack={"enabled": True},
        )
        manager = AlertManager(config)
        manager._requests = MagicMock()

        with patch.object(manager, "_send_email", side_effect=RuntimeError("smtp down")), \
             patch.object(manager, "_send_slack") as mock_slack:
            # Should not raise, and slack should still be attempted —
            # NOT mocking _send_slack via a fake webhook URL/env var,
            # since a missing SENTINEL_SLACK_WEBHOOK would fail slack
            # too and mask exactly the isolation behaviour under test.
            manager.send_alert(make_event())

        mock_slack.assert_called_once()

    def test_send_alert_never_raises_even_if_every_channel_fails(self):
        config = make_config(
            email={"enabled": True, "sender": "a@x.com", "recipient": "b@x.com"},
            slack={"enabled": True},
            webhook={"enabled": True},
        )
        manager = AlertManager(config)
        manager._requests = MagicMock()
        manager._requests.post.side_effect = RuntimeError("network down")

        with patch.object(manager, "_send_email", side_effect=RuntimeError("smtp down")):
            manager.send_alert(make_event())  # must not raise

    def test_disabled_channels_are_never_called(self):
        manager = AlertManager(make_config())  # everything disabled
        manager._requests = MagicMock()

        with patch.object(manager, "_send_email") as mock_email:
            manager.send_alert(make_event())

        mock_email.assert_not_called()
        manager._requests.post.assert_not_called()

    def test_missing_email_credentials_raises_internally_but_caller_is_safe(self):
        # Enabled but no sender/recipient/password configured anywhere.
        manager = AlertManager(make_config(email={"enabled": True}))
        # Should not raise out of send_alert — the RuntimeError from
        # _send_email must be caught by _safe_send.
        manager.send_alert(make_event())


# ------------------------------------------------------------
# GeoIP enrichment
# ------------------------------------------------------------

class TestGeoIPEnrichment:
    def test_geoip_failure_falls_back_to_location_unknown_not_a_crash(self):
        fake_geoip = MagicMock()
        fake_geoip.lookup.side_effect = RuntimeError("geoip down")
        manager = AlertManager(make_config(email={"enabled": True, "sender": "a@x.com",
                                                    "recipient": "b@x.com"}), geoip=fake_geoip)

        with patch.object(manager, "_send_email") as mock_send:
            manager.send_alert(make_event())

        body = mock_send.call_args.args[1]
        assert "location unknown" in body

    def test_geoip_result_included_in_message_body(self):
        fake_geoip = MagicMock()
        fake_geoip.lookup.return_value.display_str.return_value = "Kathmandu, Nepal (WorldLink)"
        manager = AlertManager(make_config(email={"enabled": True, "sender": "a@x.com",
                                                    "recipient": "b@x.com"}), geoip=fake_geoip)

        with patch.object(manager, "_send_email") as mock_send:
            manager.send_alert(make_event())

        body = mock_send.call_args.args[1]
        assert "Kathmandu, Nepal (WorldLink)" in body


# ------------------------------------------------------------
# Message formatting
# ------------------------------------------------------------

class TestMessageFormatting:
    def test_format_message_includes_reasoning_and_extra_fields(self):
        manager = AlertManager(make_config())
        subject, body = manager._format_message(make_event(), location="Nepal")

        assert "port_scan" in subject
        assert "198.51.101.5" in subject
        assert "touched 30 ports in 10s" in body
        assert "distinct_ports_in_window: 30" in body

    def test_send_test_alert_bypasses_rate_limit_and_uses_placeholder_ip(self):
        with patch.object(AlertManager, "_send_email") as mock_send:
            manager = AlertManager(make_config(
                email={"enabled": True, "sender": "a@x.com", "recipient": "b@x.com"},
                test_on_startup=True,
            ))
            mock_send.reset_mock()  # clear the automatic startup call
            manager._send_test_alert()

        assert mock_send.called
        subject = mock_send.call_args.args[0]
        assert "TEST" in subject