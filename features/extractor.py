"""
features/extractor.py
======================
Feature extraction: turns a finished `Flow` object (from
capture/sniffer.py) into a flat dictionary of numbers — the actual
input format that machine learning models can use.

This module does NOT do any detection or decision-making. Its only
job is measurement: given a flow, compute statistics that describe
its "shape" (how big, how fast, how bursty, what kind of packets).

Why these specific features?
------------------------------
These are loosely based on the well-known CIC-IDS2017 feature set
(the same family of features used in most network intrusion research),
reduced to a practical subset we can compute cheaply in real time:

  - Size/volume features (bytes, packets) distinguish a quick DNS
    lookup from a large file transfer.
  - Timing features (inter-arrival time) distinguish a human typing
    commands from a script firing requests as fast as possible.
  - TCP flag features distinguish a normal handshake from a SYN flood
    or port scan (which sends SYN packets with no intention of
    completing the handshake).
  - Payload features distinguish "real" data exchange from bare
    control traffic (pure ACKs, scans with no payload at all).

None of this module decides what's an attack — it just measures. The
anomaly detector (Phase 1.4) is what interprets these numbers.
"""

from __future__ import annotations

import statistics
from typing import Optional

# Importing Flow only for type hints — this module never constructs
# or mutates a Flow, it only reads from one.
from capture.sniffer import Flow


# A flow needs at least this many packets before its statistics are
# meaningful. A 1-packet flow (e.g. a single stray UDP packet) has no
# useful timing or rate information, so we skip it rather than feed
# the model noisy, low-confidence numbers.
MIN_PACKETS_FOR_EXTRACTION = 2


def extract(flow: Flow) -> Optional[dict]:
    """
    Convert a finished Flow into a flat dict of numeric features.

    Returns None if the flow is too short to extract meaningful
    features from (see MIN_PACKETS_FOR_EXTRACTION) — the caller
    (main.py) is expected to skip flows where this returns None.
    """
    if len(flow.packets) < MIN_PACKETS_FOR_EXTRACTION:
        return None

    forward_packets = [p for p in flow.packets if p.direction == "forward"]
    backward_packets = [p for p in flow.packets if p.direction == "backward"]

    duration_seconds = max(flow.last_seen - flow.start_time, 1e-6)  # avoid divide-by-zero

    features = {}

    # ------------------------------------------------------------
    # Identity fields — not used as ML input directly, but useful
    # for logging, debugging, and for the response layer (blocking,
    # alerting) to know WHO this flow belongs to. The detection model
    # should be trained on everything EXCEPT these identity fields,
    # since an IP address or port number is not a generalisable
    # pattern — we want the model to learn behaviour, not memorise
    # specific addresses.
    # ------------------------------------------------------------
    features["src_ip"] = flow.src_ip
    features["dst_ip"] = flow.dst_ip
    features["src_port"] = flow.src_port
    features["dst_port"] = flow.dst_port
    features["protocol"] = flow.protocol

    # ------------------------------------------------------------
    # Flow-level volume and duration features
    # ------------------------------------------------------------
    features["duration_seconds"] = duration_seconds
    features["total_packets"] = len(flow.packets)
    features["total_bytes"] = sum(p.size for p in flow.packets)

    features["fwd_packets"] = len(forward_packets)
    features["bwd_packets"] = len(backward_packets)
    features["fwd_bytes"] = sum(p.size for p in forward_packets)
    features["bwd_bytes"] = sum(p.size for p in backward_packets)

    features["bytes_per_second"] = features["total_bytes"] / duration_seconds
    features["packets_per_second"] = features["total_packets"] / duration_seconds

    # ------------------------------------------------------------
    # Packet size statistics (forward and backward separately —
    # an attack often looks very different in one direction only,
    # e.g. a DoS flood is huge in the forward direction but the
    # backward direction barely exists)
    # ------------------------------------------------------------
    features.update(_size_stats("fwd_pkt_len", forward_packets))
    features.update(_size_stats("bwd_pkt_len", backward_packets))

    # ------------------------------------------------------------
    # Inter-arrival time (IAT) statistics — the gaps between
    # consecutive packets. A normal human-driven connection has
    # irregular, relatively large gaps. A scripted attack (port scan,
    # flood) tends to have very small, very regular gaps.
    # ------------------------------------------------------------
    features.update(_iat_stats("iat", flow.packets))

    # ------------------------------------------------------------
    # TCP flag features (only meaningful for TCP; zeroed for
    # UDP/ICMP so the feature vector shape is always consistent
    # regardless of protocol)
    # ------------------------------------------------------------
    features.update(_tcp_flag_features(flow.packets))

    # ------------------------------------------------------------
    # Payload features
    # ------------------------------------------------------------
    payload_sizes = [p.payload_size for p in flow.packets]
    zero_payload_count = sum(1 for size in payload_sizes if size == 0)

    features["avg_payload_size"] = (
        sum(payload_sizes) / len(payload_sizes) if payload_sizes else 0.0
    )
    features["zero_payload_ratio"] = (
        zero_payload_count / len(payload_sizes) if payload_sizes else 0.0
    )

    # ------------------------------------------------------------
    # Port/protocol features
    # ------------------------------------------------------------
    features["is_well_known_dst_port"] = 1 if flow.dst_port < 1024 else 0

    return features


# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------

def _size_stats(prefix: str, packets: list) -> dict:
    """
    Compute mean/max/min/std of packet size for a list of packets.
    Returns all-zero values if the list is empty, so the feature
    vector always has the same keys regardless of whether this
    direction had any traffic.
    """
    sizes = [p.size for p in packets]

    if not sizes:
        return {
            f"{prefix}_mean": 0.0,
            f"{prefix}_max": 0.0,
            f"{prefix}_min": 0.0,
            f"{prefix}_std": 0.0,
        }

    return {
        f"{prefix}_mean": statistics.mean(sizes),
        f"{prefix}_max": max(sizes),
        f"{prefix}_min": min(sizes),
        # statistics.stdev() requires at least 2 data points
        f"{prefix}_std": statistics.stdev(sizes) if len(sizes) >= 2 else 0.0,
    }


def _iat_stats(prefix: str, packets: list) -> dict:
    """
    Compute mean/max/min/std of inter-arrival time (the time gap
    between consecutive packets, in seconds) across an entire flow.

    Packets are assumed to already be in arrival order (sniffer.py
    appends them as they arrive, so this holds true).
    """
    if len(packets) < 2:
        return {
            f"{prefix}_mean": 0.0,
            f"{prefix}_max": 0.0,
            f"{prefix}_min": 0.0,
            f"{prefix}_std": 0.0,
        }

    gaps = [
        packets[i].timestamp - packets[i - 1].timestamp
        for i in range(1, len(packets))
    ]
    # Guard against any out-of-order timestamps producing a negative
    # gap (shouldn't normally happen, but real-world capture timing
    # can occasionally jitter) — clamp to zero rather than let a
    # negative number distort the statistics.
    gaps = [max(gap, 0.0) for gap in gaps]

    return {
        f"{prefix}_mean": statistics.mean(gaps),
        f"{prefix}_max": max(gaps),
        f"{prefix}_min": min(gaps),
        f"{prefix}_std": statistics.stdev(gaps) if len(gaps) >= 2 else 0.0,
    }


def _tcp_flag_features(packets: list) -> dict:
    """
    Count TCP flags across the whole flow. For non-TCP flows
    (tcp_flags is None on every packet), this naturally returns all
    zeros, which keeps the feature vector shape consistent across
    TCP, UDP, and ICMP flows.

    Scapy's flag string uses single letters, e.g.:
      S = SYN, A = ACK, F = FIN, R = RST, P = PSH, U = URG
    """
    syn_count = 0
    ack_count = 0
    fin_count = 0
    rst_count = 0
    psh_count = 0
    urg_count = 0
    tcp_packet_count = 0

    for packet in packets:
        if packet.tcp_flags is None:
            continue
        tcp_packet_count += 1
        flags = packet.tcp_flags
        if "S" in flags:
            syn_count += 1
        if "A" in flags:
            ack_count += 1
        if "F" in flags:
            fin_count += 1
        if "R" in flags:
            rst_count += 1
        if "P" in flags:
            psh_count += 1
        if "U" in flags:
            urg_count += 1

    # SYN ratio is a strong port-scan / SYN-flood indicator: a normal
    # connection has exactly one SYN out of many packets, but a scan
    # sends SYN after SYN with little else.
    syn_ratio = (syn_count / tcp_packet_count) if tcp_packet_count > 0 else 0.0

    return {
        "syn_count": syn_count,
        "ack_count": ack_count,
        "fin_count": fin_count,
        "rst_count": rst_count,
        "psh_count": psh_count,
        "urg_count": urg_count,
        "syn_ratio": syn_ratio,
    }


# ----------------------------------------------------------------------
# FeatureExtractor class
# ----------------------------------------------------------------------
# main.py expects a class with an `extract(flow)` method (see the
# pipeline wiring in main.py's run_live_capture / run_pcap functions).
# This thin wrapper exists purely for that consistent interface — the
# real logic lives in the module-level extract() function above so it
# can also be unit tested directly without constructing a class first.

class FeatureExtractor:
    """
    Thin wrapper around the module-level extract() function, so it
    matches the same class-based interface as PacketSniffer and
    AnomalyDetector in the rest of the pipeline.
    """

    def __init__(self, config: dict):
        # No configuration is currently needed for extraction itself,
        # but we accept config here for interface consistency, and in
        # case future feature toggles are added (e.g. enabling payload
        # inspection features behind a config flag).
        self.config = config

    def extract(self, flow: Flow) -> Optional[dict]:
        return extract(flow)
        