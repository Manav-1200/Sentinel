"""
capture/pcap_reader.py
========================
Offline flow assembly from a saved .pcap file.

This module exists so Sentinel's flow-assembly and feature-extraction
logic can be tested and demonstrated WITHOUT a live network — useful
for:
  - Automated tests (no root privileges or real traffic needed)
  - Reproducing a specific captured scenario exactly, every time
  - Demonstrating Sentinel's behaviour on a known dataset (e.g. a
    saved port-scan or flood capture) without needing to regenerate
    that traffic live

PcapReader uses the EXACT SAME flow-assembly rules as PacketSniffer
(live capture) — both inherit from FlowAssembler in capture/sniffer.py.
This guarantees a flow built from a live capture and a flow built from
replaying a saved .pcap of that same traffic will always be identical,
since they share the underlying logic rather than reimplementing it.
"""

from __future__ import annotations

from typing import Iterator

from scapy.utils import rdpcap

from capture.sniffer import FlowAssembler, Flow


class PcapReader(FlowAssembler):
    """
    Reads a .pcap file and assembles its packets into flows, using
    the same flow-assembly rules as live capture (see FlowAssembler
    in capture/sniffer.py).

    Unlike PacketSniffer, this has no concept of "live" timing — it
    processes every packet in the file as fast as possible, in the
    order they were recorded, using each packet's own recorded
    timestamp rather than the current wall-clock time. This means
    re-running the same .pcap file always produces identical flows
    and identical timing-based features (IAT, duration, etc.),
    making it ideal for reproducible tests.
    """

    def __init__(self, config: dict, pcap_path: str):
        super().__init__(
            flow_timeout=float(config["capture"]["flow_timeout_seconds"]),
            max_active_flows=int(config["capture"]["max_active_flows"]),
        )
        self.pcap_path = pcap_path

    def stream_flows(self) -> Iterator[Flow]:
        """
        Read every packet from the .pcap file, assemble them into
        flows, and yield each flow once it's finished.

        Since a .pcap file has a definite end (unlike live capture,
        which runs until stop() is called), this method finishes ALL
        remaining active flows after the last packet is processed —
        there's no "still waiting for more packets" state once the
        file is exhausted.

        Yield order: flows that finished mid-file (via a TCP FIN/RST
        seen before the last packet) are yielded first, in the order
        they finished. Flows still active when the file ends (e.g. a
        UDP flow, or a TCP connection with no clean close recorded)
        are yielded last. This is a deliberate, documented order —
        not strictly chronological by finish time — chosen so the
        common case (a clean trace where most flows close themselves)
        reads naturally, with any "leftover" flows clearly grouped at
        the end.
        """
        packets = rdpcap(self.pcap_path)

        for packet in packets:
            # Use the packet's own recorded timestamp (when it was
            # actually captured originally), not the current time —
            # this is what makes replays reproducible and keeps
            # timing-based features (IAT, duration) meaningful and
            # consistent with the original capture.
            timestamp = float(packet.time)
            self._process_one_packet(timestamp, packet)

        # First: yield flows that finished mid-file (via TCP FIN/RST),
        # in the order they finished.
        with self._lock:
            already_finished = self._finished_flows
            self._finished_flows = []

        for flow in already_finished:
            yield flow

        # Then: the file is exhausted, so every flow still "active" is
        # as finished as it's ever going to be. Flush them all rather
        # than waiting for a timeout that will never come (there are
        # no more packets to advance the clock).
        with self._lock:
            remaining = list(self._active_flows.values())
            self._active_flows.clear()

        for flow in remaining:
            yield flow

            