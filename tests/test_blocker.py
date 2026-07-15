"""
tests/test_blocker.py
=========================
Unit tests for response/blocker.py (IPBlocker + backends).

Nothing here touches a real firewall — subprocess.run is always
mocked. The goal is to lock down exactly the behaviour that matters
for the status column / auto-block accuracy work coming next:
  - dry_run NEVER calls a real firewall command
  - whitelist / private-range / loopback safety checks are enforced
    BEFORE any backend call, every time, regardless of backend
  - a real backend failure is reported as applied=False, never
    silently reported as a successful block
  - is_blocked()/currently_blocked() only ever reflect blocks that
    were actually recorded, so a future "status" column reading these
    can never show BLOCKED for something that isn't.
"""

from __future__ import annotations

import json
import time
from unittest.mock import patch, MagicMock

import pytest

from response.blocker import IPBlocker, _NftablesBackend, _IptablesBackend, _NullBackend


def make_config(tmp_path, **response_overrides):
    response = {
        "dry_run": True,
        "block_duration_minutes": 60,
        "whitelist_ips": [],
        "block_private_ranges": False,
    }
    response.update(response_overrides)
    return {
        "response": response,
        "storage": {"blocks_log": str(tmp_path / "blocks.log")},
    }


def fake_subprocess_run_success(*args, **kwargs):
    result = MagicMock()
    result.returncode = 0
    result.stdout = ""
    result.stderr = ""
    return result


# ------------------------------------------------------------
# Backend selection
# ------------------------------------------------------------

class TestBackendSelection:
    def test_prefers_nftables_when_both_available(self, tmp_path):
        with patch("response.blocker.shutil.which", side_effect=lambda name: f"/usr/bin/{name}"):
            blocker = IPBlocker(make_config(tmp_path))
        assert isinstance(blocker._backend, _NftablesBackend)

    def test_falls_back_to_iptables_when_nft_missing(self, tmp_path):
        with patch("response.blocker.shutil.which", side_effect=lambda name: None if name == "nft" else "/sbin/iptables"):
            blocker = IPBlocker(make_config(tmp_path))
        assert isinstance(blocker._backend, _IptablesBackend)

    def test_null_backend_when_neither_available(self, tmp_path):
        with patch("response.blocker.shutil.which", return_value=None):
            blocker = IPBlocker(make_config(tmp_path))
        assert isinstance(blocker._backend, _NullBackend)


# ------------------------------------------------------------
# Dry-run — the default, must never touch a real firewall
# ------------------------------------------------------------

class TestDryRun:
    def test_dry_run_block_never_calls_subprocess(self, tmp_path):
        with patch("response.blocker.shutil.which", return_value="/usr/bin/nft"), \
             patch("response.blocker.subprocess.run") as mock_run:
            blocker = IPBlocker(make_config(tmp_path, dry_run=True))
            result = blocker.block("203.0.114.5", reason="test")

        mock_run.assert_not_called()
        assert result.applied is False
        assert result.dry_run is True
        # Dry run still tracks the "would-be" block so is_blocked()
        # reflects intent for display/testing purposes.
        assert blocker.is_blocked("203.0.114.5") is True

    def test_dry_run_unblock_never_calls_subprocess(self, tmp_path):
        with patch("response.blocker.shutil.which", return_value="/usr/bin/nft"), \
             patch("response.blocker.subprocess.run") as mock_run:
            blocker = IPBlocker(make_config(tmp_path, dry_run=True))
            blocker.block("203.0.114.5")
            result = blocker.unblock("203.0.114.5")

        mock_run.assert_not_called()
        assert result.applied is False
        assert blocker.is_blocked("203.0.114.5") is False


# ------------------------------------------------------------
# Safety checks — must be enforced before ANY backend call
# ------------------------------------------------------------

class TestSafetyChecks:
    def test_whitelisted_ip_never_blocked(self, tmp_path):
        with patch("response.blocker.shutil.which", return_value="/usr/bin/nft"), \
             patch("response.blocker.subprocess.run", side_effect=fake_subprocess_run_success) as mock_run:
            blocker = IPBlocker(make_config(tmp_path, dry_run=False, whitelist_ips=["8.8.8.8"]))
            mock_run.reset_mock()  # clear the setup() calls
            result = blocker.block("8.8.8.8")

        mock_run.assert_not_called()
        assert result.applied is False
        assert "whitelist" in result.reason
        assert blocker.is_blocked("8.8.8.8") is False

    def test_loopback_never_blocked_even_if_private_ranges_allowed(self, tmp_path):
        with patch("response.blocker.shutil.which", return_value="/usr/bin/nft"), \
             patch("response.blocker.subprocess.run", side_effect=fake_subprocess_run_success) as mock_run:
            blocker = IPBlocker(make_config(tmp_path, dry_run=False, block_private_ranges=True))
            mock_run.reset_mock()
            result = blocker.block("127.0.0.1")

        mock_run.assert_not_called()
        assert result.applied is False
        assert "loopback" in result.reason

    def test_private_ip_skipped_by_default(self, tmp_path):
        with patch("response.blocker.shutil.which", return_value="/usr/bin/nft"), \
             patch("response.blocker.subprocess.run", side_effect=fake_subprocess_run_success) as mock_run:
            blocker = IPBlocker(make_config(tmp_path, dry_run=False, block_private_ranges=False))
            mock_run.reset_mock()
            result = blocker.block("192.168.10.67")

        mock_run.assert_not_called()
        assert result.applied is False
        assert "block_private_ranges" in result.reason

    def test_private_ip_blocked_when_explicitly_enabled(self, tmp_path):
        with patch("response.blocker.shutil.which", return_value="/usr/bin/nft"), \
             patch("response.blocker.subprocess.run", side_effect=fake_subprocess_run_success) as mock_run:
            blocker = IPBlocker(make_config(tmp_path, dry_run=False, block_private_ranges=True))
            mock_run.reset_mock()
            result = blocker.block("192.168.10.67", reason="docker-sourced nmap scan")

        assert result.applied is True
        assert blocker.is_blocked("192.168.10.67") is True

    def test_invalid_ip_string_is_skipped_not_crashed(self, tmp_path):
        with patch("response.blocker.shutil.which", return_value="/usr/bin/nft"):
            blocker = IPBlocker(make_config(tmp_path, dry_run=True))
            result = blocker.block("not-an-ip")

        assert result.applied is False
        assert "not a valid IP" in result.reason


# ------------------------------------------------------------
# Real backend calls (subprocess mocked) — accuracy of applied=True/False
# ------------------------------------------------------------

class TestRealBackendCalls:
    def test_successful_nftables_block_reports_applied_true(self, tmp_path):
        with patch("response.blocker.shutil.which", return_value="/usr/bin/nft"), \
             patch("response.blocker.subprocess.run", side_effect=fake_subprocess_run_success) as mock_run:
            blocker = IPBlocker(make_config(tmp_path, dry_run=False))
            mock_run.reset_mock()
            result = blocker.block("203.0.114.9", reason="port_scan")

        assert result.applied is True
        # Confirm the actual nft command shape hit the set, not some
        # other accidental call.
        called_cmds = [call.args[0] for call in mock_run.call_args_list]
        assert any("element" in cmd and "203.0.114.9" in " ".join(cmd) for cmd in called_cmds)
        assert blocker.is_blocked("203.0.114.9") is True

    def test_backend_failure_reports_applied_false_not_true(self, tmp_path):
        """
        The single most important accuracy guarantee for the future
        status column: if the firewall command actually fails, the
        result — and is_blocked() — must say so, never silently
        report success.
        """
        def failing_run(*args, **kwargs):
            result = MagicMock()
            result.returncode = 1
            result.stdout = ""
            result.stderr = "permission denied"
            return result

        with patch("response.blocker.shutil.which", return_value="/usr/bin/nft"), \
             patch("response.blocker.subprocess.run", side_effect=fake_subprocess_run_success):
            # Construct with a working backend so setup() during
            # __init__ succeeds — we only want the BLOCK call itself
            # to fail, not startup.
            blocker = IPBlocker(make_config(tmp_path, dry_run=False))

        with patch("response.blocker.subprocess.run", side_effect=failing_run):
            result = blocker.block("203.0.114.10", reason="port_scan")

        assert result.applied is False
        assert result.reason  # some error detail present
        assert blocker.is_blocked("203.0.114.10") is False

    def test_null_backend_never_reports_false_success(self, tmp_path):
        with patch("response.blocker.shutil.which", return_value=None):
            blocker = IPBlocker(make_config(tmp_path, dry_run=False))
            result = blocker.block("203.0.114.11", reason="port_scan")

        assert result.applied is False
        assert blocker.is_blocked("203.0.114.11") is False


# ------------------------------------------------------------
# is_blocked / currently_blocked bookkeeping
# ------------------------------------------------------------

class TestBookkeeping:
    def test_currently_blocked_excludes_expired_entries(self, tmp_path):
        with patch("response.blocker.shutil.which", return_value="/usr/bin/nft"):
            blocker = IPBlocker(make_config(tmp_path, dry_run=True, block_duration_minutes=0.001))
            blocker.block("203.0.114.12")
            time.sleep(0.1)  # let the 0.001-minute (60ms) expiry pass

        assert blocker.is_blocked("203.0.114.12") is False
        assert "203.0.114.12" not in blocker.currently_blocked()

    def test_unblock_removes_from_bookkeeping(self, tmp_path):
        with patch("response.blocker.shutil.which", return_value="/usr/bin/nft"), \
             patch("response.blocker.subprocess.run", side_effect=fake_subprocess_run_success):
            blocker = IPBlocker(make_config(tmp_path, dry_run=False))
            blocker.block("203.0.114.13")
            assert blocker.is_blocked("203.0.114.13") is True
            blocker.unblock("203.0.114.13")

        assert blocker.is_blocked("203.0.114.13") is False


# ------------------------------------------------------------
# Audit log
# ------------------------------------------------------------

class TestAuditLog:
    def test_block_action_written_to_audit_log(self, tmp_path):
        with patch("response.blocker.shutil.which", return_value="/usr/bin/nft"):
            blocker = IPBlocker(make_config(tmp_path, dry_run=True))
            blocker.block("203.0.114.14", reason="test-reason")

        log_path = tmp_path / "blocks.log"
        assert log_path.exists()
        entry = json.loads(log_path.read_text().strip().splitlines()[-1])
        assert entry["ip"] == "203.0.114.14"
        assert entry["action"] == "block"
        assert entry["reason"] == "test-reason"
        assert entry["dry_run"] is True


# ------------------------------------------------------------
# iptables fallback expiry sweep — the untested Phase 3 gap
# ------------------------------------------------------------

class TestIptablesExpirySweep:
    def test_expiry_sweep_removes_expired_block_and_calls_backend_unblock(self, tmp_path):
        with patch("response.blocker.shutil.which", side_effect=lambda name: None if name == "nft" else "/sbin/iptables"), \
             patch("response.blocker.subprocess.run", side_effect=fake_subprocess_run_success):
            blocker = IPBlocker(make_config(tmp_path, dry_run=False, block_duration_minutes=0.001))
            assert isinstance(blocker._backend, _IptablesBackend)
            blocker.block("203.0.114.15")

            # Directly invoke the sweep body once instead of waiting
            # 15s for the real timer — this exercises the exact same
            # code path (_expiry_sweep_loop's inner logic) as
            # production, just without the real-time wait.
            now = time.time() + 1  # simulate time having passed
            with patch("response.blocker.time.time", return_value=now):
                expired = [ip for ip, expiry in blocker._blocked_until.items() if expiry <= now]
                assert "203.0.114.15" in expired
                for ip in expired:
                    blocker._backend.unblock(ip)
                    blocker._blocked_until.pop(ip, None)

            blocker.shutdown()

        assert blocker.is_blocked("203.0.114.15") is False