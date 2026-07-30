"""
tests/test_extractor.py
==========================
Guards features/extractor.py's CURRENT_FEATURE_KEYS constant against
silent drift from what extract() actually produces.

CURRENT_FEATURE_KEYS exists specifically so detection/classifier.py
can determine "is this stored sample's schema current?" from a single
source of truth instead of an empirical majority vote (see that
constant's docstring for the real incident this fixes). That only
works if CURRENT_FEATURE_KEYS is kept in exact sync with extract()'s
real output — if a future feature is added to extract() without also
updating this constant, canonical-schema selection would silently
exclude every CURRENT sample (mismatched against a now-stale
constant), which is just as bad as the original bug, only inverted.
This test is what makes that drift impossible to miss: it fails CI
the moment the two disagree.
"""

from __future__ import annotations

import time

import pytest

from capture.sniffer import Flow, PacketRecord, make_flow_key
from features.extractor import extract, CURRENT_FEATURE_KEYS, MIN_PACKETS_FOR_EXTRACTION

IDENTITY_FIELDS = {"src_ip", "dst_ip", "src_port", "dst_port"}


def make_test_flow(num_packets: int = 10, protocol: int = 6) -> Flow:
    """Builds a minimal, realistic TCP Flow with alternating
    forward/backward packets and TCP flags, enough for every feature
    in extract() to compute a real (non-degenerate) value."""
    now = time.time()
    flow_key = make_flow_key("10.0.0.1", 51000, "10.0.0.2", 443, protocol)
    flow = Flow(
        flow_key=flow_key,
        src_ip="10.0.0.1", dst_ip="10.0.0.2",
        src_port=51000, dst_port=443,
        protocol=protocol,
        start_time=now, last_seen=now,
    )
    flags_cycle = ["S", "SA", "A", "PA", "A", "PA", "A", "FA", "A", "A"]
    for i in range(num_packets):
        flow.add_packet(PacketRecord(
            timestamp=now + i * 0.01,
            direction="forward" if i % 2 == 0 else "backward",
            size=100 + i,
            header_size=40,
            payload_size=60 + i,
            tcp_flags=flags_cycle[i % len(flags_cycle)] if protocol == 6 else None,
        ))
    return flow


class TestCurrentFeatureKeysStaysInSync:
    """
    The core guard: a real extract() call's output keys (minus
    identity fields) must exactly match CURRENT_FEATURE_KEYS, in both
    directions — no keys extract() produces that the constant is
    missing, and no keys in the constant that extract() doesn't
    actually produce.
    """

    def test_real_extract_output_matches_current_feature_keys_exactly(self):
        flow = make_test_flow()
        features = extract(flow)
        assert features is not None

        actual_keys = frozenset(k for k in features.keys() if k not in IDENTITY_FIELDS)

        missing_from_constant = actual_keys - CURRENT_FEATURE_KEYS
        missing_from_extract = CURRENT_FEATURE_KEYS - actual_keys

        assert not missing_from_constant, (
            f"extract() now produces keys not listed in CURRENT_FEATURE_KEYS: "
            f"{sorted(missing_from_constant)}. Update CURRENT_FEATURE_KEYS in "
            f"features/extractor.py or classifier.py's canonical-schema "
            f"selection will incorrectly treat every CURRENT sample as stale."
        )
        assert not missing_from_extract, (
            f"CURRENT_FEATURE_KEYS lists keys extract() no longer produces: "
            f"{sorted(missing_from_extract)}. Update the constant to match."
        )

    def test_stays_in_sync_for_udp_flows_too(self):
        """TCP-flag features are zeroed (not absent) for UDP — confirms
        the key SET stays identical across protocols, only the values differ."""
        flow = make_test_flow(protocol=17)
        features = extract(flow)
        actual_keys = frozenset(k for k in features.keys() if k not in IDENTITY_FIELDS)
        assert actual_keys == CURRENT_FEATURE_KEYS

    def test_too_short_flow_returns_none_not_a_partial_schema(self):
        """Below MIN_PACKETS_FOR_EXTRACTION, extract() must return None
        outright rather than a dict with a partial/different key set —
        a partial schema slipping through would itself be a form of the
        exact drift this test file exists to prevent."""
        flow = make_test_flow(num_packets=MIN_PACKETS_FOR_EXTRACTION - 1)
        assert extract(flow) is None