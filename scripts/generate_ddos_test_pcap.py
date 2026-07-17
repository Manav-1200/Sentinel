"""
scripts/generate_ddos_test_pcap.py
======================================
Generates a synthetic .pcap file that reliably reproduces the exact
pattern detection/ddos_tracker.py's GlobalRateTracker is built to
catch: many distinct sources, each sending a small, individually
unremarkable amount of traffic, all within a short time window.

Why this exists instead of live Docker containers:
-------------------------------------------------------
Manual testing on 2026-07-17 showed that rapid `docker run --rm ...`
loops don't reliably produce N genuinely distinct, simultaneous
source IPs — short-lived containers free their bridge-network IP
almost immediately (visible as "Exit 7" / connection refused), so
fast, repeated runs end up REUSING a handful of IPs (observed:
172.17.0.6-9 only, regardless of how many containers were launched)
rather than giving 20+ truly distinct ones inside any single 10s
window. That's a live-testing/timing limitation, not a bug in
GlobalRateTracker itself (which already has passing unit tests
proving its threshold logic in isolation — see tests/test_ddos_tracker.py).

This script sidesteps that entirely: it builds packets with EXPLICIT,
controlled timestamps and however many distinct source IPs you ask
for, using Scapy (already a required Sentinel dependency — nothing
new to install). Replaying the result via `python main.py --pcap
<file>` uses PcapReader, which reads packets using their RECORDED
timestamps, not wall-clock time (see tests/test_pcap_reader.py's
test_pcap_reader_uses_recorded_timestamps_not_wall_clock) — so every
packet lands inside detection.ddos.window_seconds deterministically,
no matter how long packet generation or replay itself takes.

Each synthetic source sends exactly 2 packets (SYN then ACK) on the
same 5-tuple, so it forms ONE real flow per source (matching
detection/extractor.py's minimum-packet requirement for a flow to be
extracted at all — a single lone SYN packet's flow would otherwise be
silently skipped by extractor.extract() returning None, meaning
ddos_tracker.check() would never even be called for it — see
main.py's `if features is None: continue`).

Usage:
    python scripts/generate_ddos_test_pcap.py
    python main.py --pcap ddos_test.pcap

Defaults (25 sources x 25 flows each = 625 total flows) comfortably
clear config.yaml's real, default ddos thresholds
(attack_total_flows_threshold: 500, attack_distinct_sources_threshold: 20)
with no need to lower them for this test.
"""

from __future__ import annotations

import argparse

from scapy.all import IP, TCP, wrpcap


def _synthetic_src_ip(index: int) -> str:
    """
    Generates a distinct, ordinary-looking public IP per source index.
    203.0.114.0/24 (NOT 203.0.113.0/24 — that specific /24 is an IANA
    documentation range that Python's ipaddress module treats as
    private, which would make GeoIPLookup/IPBlocker's private-range
    checks skip it) — chosen deliberately to avoid that exact trap.
    """
    third_octet = 114 + (index // 250)
    fourth_octet = (index % 250) + 1
    return f"203.0.{third_octet}.{fourth_octet}"


def build_packets(num_sources: int, flows_per_source: int, dst_ip: str,
                   dst_port: int, window_seconds: float) -> list:
    packets = []
    total_flows = num_sources * flows_per_source
    # Spread all flows across the first half of the window, so the
    # whole burst is comfortably inside a single sliding-window check
    # even accounting for real replay/processing overhead.
    span = window_seconds / 2

    flow_index = 0
    for source_index in range(num_sources):
        src_ip = _synthetic_src_ip(source_index)
        for _ in range(flows_per_source):
            sport = 40000 + flow_index
            t = (flow_index / total_flows) * span

            syn = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dst_port, flags="S", seq=1000)
            syn.time = t
            ack = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dst_port, flags="A", seq=1001, ack=1)
            ack.time = t + 0.001  # 1ms later, same flow (same 5-tuple)

            packets.append(syn)
            packets.append(ack)
            flow_index += 1

    return packets


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=int, default=25,
                         help="Number of distinct synthetic source IPs (default: 25)")
    parser.add_argument("--flows-per-source", type=int, default=25,
                         help="Flows per source (default: 25)")
    parser.add_argument("--dst-ip", default="192.168.10.67",
                         help="Destination IP — use your real LAN IP so features look realistic")
    parser.add_argument("--dst-port", type=int, default=80)
    parser.add_argument("--window-seconds", type=float, default=10.0,
                         help="Must match detection.ddos.window_seconds in config.yaml (default: 10.0)")
    parser.add_argument("--out", default="ddos_test.pcap")
    args = parser.parse_args()

    packets = build_packets(
        args.sources, args.flows_per_source, args.dst_ip, args.dst_port, args.window_seconds,
    )
    wrpcap(args.out, packets)

    total_flows = args.sources * args.flows_per_source
    print(
        f"Wrote {len(packets)} packets "
        f"({args.sources} distinct sources x {args.flows_per_source} flows each "
        f"= {total_flows} total flows) to {args.out}"
    )
    print(f"Replay with: python main.py --pcap {args.out}")


if __name__ == "__main__":
    main()