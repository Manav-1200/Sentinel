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
  - Directionality features (added July 2026) distinguish a
    legitimate high-volume transfer from a flood — see
    "bulk-transfer/ddos confusion fix" below.
  - Burstiness/timing-regularity features (added July 2026)
    distinguish uniform, script-driven timing from normal bursty
    traffic — see "flood/DoS separability" below.
  - Header-length features (fwd/bwd_header_len_*, added July 2026):
    header_size was already recorded per-packet to derive
    payload_size, but was never itself surfaced to the model. Exposed
    as an explicit mean/max/min/std feature pair (forward/backward,
    mirroring the packet-size stats above) — a weaker signal on its
    own than payload/timing/directionality, but a real, already-
    computed measurement that was previously discarded, and gives the
    model visibility into unusual TCP option usage (e.g. a stripped-
    down scanner stack) that packet size alone wouldn't reveal.

None of this module decides what's an attack — it just measures. The
anomaly detector (Phase 1.4) is what interprets these numbers.

Bulk-transfer/ddos confusion fix (July 2026):
-------------------------------------------------
Real-world testing found the Phase 2 classifier mislabelling a
legitimate 16,133-packet HTTPS download as "ddos" purely because
total_packets/packets_per_second looked similar to a genuine flood.
Root cause: the classifier's training data (LLM-labelled samples) had
essentially no high-volume "benign" examples, because labeller.process()
only runs on already-SUSPICIOUS/ATTACK flows, and a legitimate bulk
transfer rarely lands in that narrow band — it's usually either NORMAL
or gets shot straight to ATTACK by the deterministic flood-rate guard,
so the LLM almost never got a chance to correctly call one "benign".
Existing features (packet count, rate) genuinely cannot separate the
two patterns on their own. `fwd_packet_share` and (in the TCP flag
block below) `ack_ratio` give both the LLM (see
detection/llm_analyser.py's updated prompt) and the classifier a real,
distinguishing signal: a legitimate download is backward-heavy with a
high ACK ratio (properly established connection); a real flood/
syn_flood is forward-heavy with a low ACK ratio (no real handshake
completion).

Flood/DoS separability (July 2026, partial improvement):
-------------------------------------------------------------
config.yaml documents a known, previously-unsolved limitation: flood-
style attacks are only weakly separable from normal bursty traffic
using packet-rate features alone, since a normal traffic burst (page
load, video buffering) can have a similarly high rate. The real
missing signal is timing REGULARITY, not just rate: a script-driven
flood fires packets at near-identical intervals (low coefficient of
variation on inter-arrival time), while normal bursty traffic is
irregular even at a similarly high rate. `iat_cv` (see _iat_stats)
adds this as an explicit feature. This is a genuine improvement, not
a full fix — see config.yaml's comment for the ongoing backlog item.
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


# The complete, current set of feature keys produced by extract()
# below, EXCLUDING identity fields (src_ip, dst_ip, src_port, dst_port
# — see detection/anomaly.py's IDENTITY_FIELDS). This is the ground
# truth for "what does a current-schema sample look like" — used by
# detection/classifier.py's train() to pick which stored samples are
# safe to train on.
#
# Why this exists (fixed July 2026, second schema-consistency
# incident): train() previously derived its notion of "canonical
# schema" empirically, by majority vote across whatever samples
# happened to be in the database (Counter.most_common() on each
# sample's actual feature-key set). That approach silently breaks in
# exactly the situation it was built for: right after THIS module
# gains a new feature (as it did for fwd_packet_share/ack_ratio/
# iat_cv), new-schema samples are — by definition — a small minority
# for a while. Majority vote then picks the OLD schema as canonical
# and excludes the very samples the fix was meant to preserve,
# reproducing the original bug through a different mechanism.
# Confirmed via direct simulation (July 2026): 700 old-schema samples
# + 40 new-schema samples reproduced the exact failure, while the
# reverse ratio (majority new-schema) "happened" to work — meaning the
# old fix's correctness depended entirely on accumulated sample counts
# rather than being reliably correct at the moment it mattered most.
#
# The fix: canonical schema is no longer inferred from stored data at
# all. It's read directly from THIS module — the single source of
# truth for what a flow's features currently look like — so it's
# correct on the very first sample collected after any future feature
# change, with zero dependency on how many old-schema samples still
# exist in the database.
#
# Kept in sync with extract() by test_extractor.py, which asserts a
# real extract() call's output keys (minus identity fields) exactly
# equal this set — so an extractor.py change that adds/removes a
# feature without updating this constant fails CI immediately, rather
# than silently drifting the way the old majority-vote logic did.
CURRENT_FEATURE_KEYS = frozenset({
    "protocol",
    "duration_seconds", "total_packets", "total_bytes",
    "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
    "bytes_per_second", "packets_per_second",
    "bwd_fwd_packet_ratio", "fwd_packet_share",
    "fwd_pkt_len_mean", "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_std",
    "bwd_pkt_len_mean", "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_std",
    "fwd_header_len_mean", "fwd_header_len_max", "fwd_header_len_min", "fwd_header_len_std",
    "bwd_header_len_mean", "bwd_header_len_max", "bwd_header_len_min", "bwd_header_len_std",
    "iat_mean", "iat_max", "iat_min", "iat_std", "iat_cv",
    "syn_count", "ack_count", "fin_count", "rst_count", "psh_count", "urg_count",
    "syn_ratio", "ack_ratio",
    "avg_payload_size", "zero_payload_ratio",
    "is_well_known_dst_port",
})


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
    # Directional asymmetry (added July 2026) — distinguishes a
    # legitimate download (heavily backward: server->client data,
    # client sends only small ACKs) from a flood/DDoS (heavily
    # forward: attacker->target, target barely responds because it's
    # overwhelmed or doesn't complete the handshake). Packet-count/
    # rate features alone can't tell these apart — a 16k-packet
    # download and a 16k-packet flood can have near-identical
    # total_packets and packets_per_second. This ratio is what
    # actually separates them. See module docstring's
    # "bulk-transfer/ddos confusion fix" section.
    #
    # Two features are kept, not one, deliberately: bwd_fwd_packet_
    # ratio can blow up to very large or unstable values when
    # fwd_packets is tiny, which is noisy for a tree-based model to
    # split on cleanly. fwd_packet_share is bounded [0, 1] and gives a
    # cleaner signal for both the Isolation Forest and the classifier
    # — a real flood sits close to 1.0 (almost all forward, target
    # barely answers), a real download sits closer to 0.2-0.4 (client
    # sends far fewer, smaller ACKs back).
    # ------------------------------------------------------------
    total_directional = features["fwd_packets"] + features["bwd_packets"]
    features["bwd_fwd_packet_ratio"] = (
        features["bwd_packets"] / features["fwd_packets"]
        if features["fwd_packets"] > 0 else 0.0
    )
    features["fwd_packet_share"] = (
        features["fwd_packets"] / total_directional
        if total_directional > 0 else 0.0
    )

    # ------------------------------------------------------------
    # Packet size statistics (forward and backward separately —
    # an attack often looks very different in one direction only,
    # e.g. a DoS flood is huge in the forward direction but the
    # backward direction barely exists)
    # ------------------------------------------------------------
    features.update(_size_stats("fwd_pkt_len", forward_packets))
    features.update(_size_stats("bwd_pkt_len", backward_packets))

    # ------------------------------------------------------------
    # Header length statistics (forward and backward separately,
    # added as an explicit feature rather than staying purely
    # internal). header_size was already recorded per-packet (see
    # PacketRecord in capture/sniffer.py) to derive payload_size, but
    # was never itself surfaced to the model. Header size is mostly
    # constant for a given protocol/options combination (e.g. a bare
    # TCP header vs. one carrying options like timestamps or SACK), so
    # it's a much weaker signal on its own than the payload/timing/
    # directionality features above — but it's a real, free-to-compute
    # measurement that was already being thrown away, and gives the
    # model a way to notice unusual option usage (e.g. a scanner using
    # a stripped-down, options-free TCP stack) that packet size alone
    # wouldn't reveal.
    # ------------------------------------------------------------
    features.update(_header_stats("fwd_header_len", forward_packets))
    features.update(_header_stats("bwd_header_len", backward_packets))

    # ------------------------------------------------------------
    # Inter-arrival time (IAT) statistics — the gaps between
    # consecutive packets. A normal human-driven connection has
    # irregular, relatively large gaps. A scripted attack (port scan,
    # flood) tends to have very small, very regular gaps. See
    # _iat_stats for the added iat_cv (coefficient of variation)
    # feature, which specifically targets timing regularity.
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


def _header_stats(prefix: str, packets: list) -> dict:
    """
    Compute mean/max/min/std of header size (IP + transport header
    bytes — see PacketRecord.header_size in capture/sniffer.py) for a
    list of packets. Mirrors _size_stats exactly, just reading
    header_size instead of total packet size. Returns all-zero values
    for an empty list, same reasoning as _size_stats: the feature
    vector must always have the same keys regardless of whether this
    direction had any traffic.
    """
    header_sizes = [p.header_size for p in packets]

    if not header_sizes:
        return {
            f"{prefix}_mean": 0.0,
            f"{prefix}_max": 0.0,
            f"{prefix}_min": 0.0,
            f"{prefix}_std": 0.0,
        }

    return {
        f"{prefix}_mean": statistics.mean(header_sizes),
        f"{prefix}_max": max(header_sizes),
        f"{prefix}_min": min(header_sizes),
        f"{prefix}_std": statistics.stdev(header_sizes) if len(header_sizes) >= 2 else 0.0,
    }


def _iat_stats(prefix: str, packets: list) -> dict:
    """
    Compute mean/max/min/std/cv of inter-arrival time (the time gap
    between consecutive packets, in seconds) across an entire flow.

    Packets are assumed to already be in arrival order (sniffer.py
    appends them as they arrive, so this holds true).

    iat_cv (coefficient of variation = std/mean, added July 2026):
    the real missing signal for flood/DoS separability (see module
    docstring). A script-driven flood fires packets at near-identical
    intervals — very low CV, often close to 0. Normal bursty traffic
    (page loads, video buffering, parallel connections) has irregular
    timing — meaningfully higher CV — even at a similarly high rate.
    Raw mean/std alone don't normalise for scale, so a fast-but-steady
    flood and a fast-but-jittery normal burst can end up with similar
    std values despite very different underlying regularity; CV
    captures that difference directly.
    """
    if len(packets) < 2:
        return {
            f"{prefix}_mean": 0.0,
            f"{prefix}_max": 0.0,
            f"{prefix}_min": 0.0,
            f"{prefix}_std": 0.0,
            f"{prefix}_cv": 0.0,
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

    mean_gap = statistics.mean(gaps)
    std_gap = statistics.stdev(gaps) if len(gaps) >= 2 else 0.0
    iat_cv = (std_gap / mean_gap) if mean_gap > 0 else 0.0

    return {
        f"{prefix}_mean": mean_gap,
        f"{prefix}_max": max(gaps),
        f"{prefix}_min": min(gaps),
        f"{prefix}_std": std_gap,
        f"{prefix}_cv": iat_cv,
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

    # ACK ratio (added July 2026) is a strong "legitimate established
    # connection" indicator — a normal download/upload is nearly all
    # ACKs after the initial handshake. A SYN flood or scan has a very
    # low ACK ratio (SYNs sent with no real handshake completion).
    # See module docstring's "bulk-transfer/ddos confusion fix"
    # section for why this was added.
    ack_ratio = (ack_count / tcp_packet_count) if tcp_packet_count > 0 else 0.0

    return {
        "syn_count": syn_count,
        "ack_count": ack_count,
        "fin_count": fin_count,
        "rst_count": rst_count,
        "psh_count": psh_count,
        "urg_count": urg_count,
        "syn_ratio": syn_ratio,
        "ack_ratio": ack_ratio,
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