"""
capture/sniffer.py
===================
Live packet capture and flow assembly.

This module is the very first stage of the Sentinel pipeline. It does
NOT do any detection or analysis — its only job is to:

  1. Capture raw packets from one or more network interfaces using
     Scapy (WiFi, Ethernet, or any other working interface — see
     `resolve_interfaces()` for auto-detection).
  2. Group those packets into "flows" (a flow = one conversation
     between two endpoints, identified by source/destination IP,
     source/destination port, and protocol) — combined into a single
     unified view regardless of which interface the traffic arrived on.
  3. Decide when a flow is "finished" (either it timed out from
     inactivity, or a TCP connection closed cleanly) and hand the
     finished flow off to the rest of the pipeline.

Why flows instead of raw packets?
----------------------------------
A single packet tells you almost nothing on its own. A SYN packet is
completely normal — every TCP connection starts with one. But 500 SYN
packets to 500 different ports from the same source IP within two
seconds is a textbook port scan. That pattern only becomes visible
when you look at packets *grouped together over time*, which is
exactly what a flow represents.
"""

from __future__ import annotations

import time
import threading
import queue
import socket
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterator, Optional

from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
from scapy.packet import Packet
from scapy.interfaces import get_working_ifaces


# Requested socket receive buffer size, in bytes, applied globally via
# Scapy's `conf.bufsize` setting before any capture socket is opened.
# This is the documented, version-stable way to influence Scapy's
# socket buffer size (rather than reaching into internal socket
# objects, which vary across Scapy versions and is riskier).
#
# Why this matters: the OS kernel's default receive buffer
# (net.core.rmem_default, often ~200KB) can fill up in milliseconds
# during a fast burst (a flood attack, or even a fast port scan),
# silently dropping packets before Scapy/Python ever sees them. This
# setting asks for a much larger buffer per socket. The OS may still
# cap it at `net.core.rmem_max` — see docs/performance.md for how to
# raise that system-wide ceiling too, since both the per-socket
# request AND the system ceiling need to be large enough.
SCAPY_BUFSIZE_BYTES = 16 * 1024 * 1024  # 16 MB
conf.bufsize = SCAPY_BUFSIZE_BYTES


def resolve_interfaces(configured_value) -> list[str]:
    """
    Turn the `capture.interfaces` config value into a concrete list of
    interface names to capture on.

    - If configured_value is the string "auto", detect every working,
      non-loopback interface on the machine (WiFi, Ethernet, etc.).
    - If configured_value is a list, use it exactly as given.

    Raises ValueError if auto-detection finds no usable interfaces,
    so the caller fails fast with a clear error instead of silently
    capturing nothing.
    """
    if isinstance(configured_value, str) and configured_value.strip().lower() == "auto":
        detected = [
            iface.name for iface in get_working_ifaces()
            if iface.name != "lo"  # exclude loopback — not useful for NIDS
        ]
        if not detected:
            raise ValueError(
                "Auto-detection found no usable network interfaces. "
                "Check `ip link show` and set `capture.interfaces` explicitly in config.yaml."
            )
        return detected

    if isinstance(configured_value, list):
        return list(configured_value)

    raise ValueError(
        f"Invalid value for capture.interfaces: {configured_value!r}. "
        'Expected the string "auto" or a list of interface names.'
    )


# ----------------------------------------------------------------------
# Flow data structure
# ----------------------------------------------------------------------
# A "flow key" uniquely identifies a conversation. We sort the two
# (ip, port) endpoints so that traffic going A->B and B->A both map to
# the SAME flow key — this is what makes the flow "bidirectional".
#
# Example: a request from 192.168.1.5:51000 to 8.8.8.8:443 and the
# reply from 8.8.8.8:443 back to 192.168.1.5:51000 are two directions
# of the same conversation, and must be tracked as one flow.

FlowKey = tuple  # (ip_a, port_a, ip_b, port_b, protocol)


def make_flow_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: int) -> FlowKey:
    """
    Build a canonical flow key that is the same regardless of which
    direction the packet is travelling.

    We do this by sorting the two endpoints alphabetically/numerically
    so that (A, B) and (B, A) always produce the identical key.
    """
    endpoint_a = (src_ip, src_port)
    endpoint_b = (dst_ip, dst_port)

    if endpoint_a <= endpoint_b:
        return (src_ip, src_port, dst_ip, dst_port, protocol)
    else:
        return (dst_ip, dst_port, src_ip, src_port, protocol)


@dataclass
class PacketRecord:
    """
    A lightweight record of a single packet's relevant metadata.
    We deliberately do NOT store the packet payload/contents here —
    only metadata needed for feature extraction. This keeps memory
    usage low and avoids ever logging sensitive packet contents.
    """
    timestamp: float
    direction: str          # "forward" or "backward" relative to flow start
    size: int                # total packet length in bytes
    header_size: int         # IP + transport header length in bytes
    payload_size: int        # size of payload only (size - header_size)
    tcp_flags: Optional[str] = None  # e.g. "S", "SA", "FA" (Scapy flag string)


@dataclass
class Flow:
    """
    Represents one bidirectional conversation between two endpoints.
    Packets are appended to `packets` as they arrive. Once the flow
    is considered finished, this object is handed to feature extraction.
    """
    flow_key: FlowKey
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int             # 6 = TCP, 17 = UDP, 1 = ICMP
    start_time: float
    last_seen: float
    packets: list = field(default_factory=list)
    finished_cleanly: bool = False  # True if a TCP FIN/RST closed this flow

    def add_packet(self, record: PacketRecord) -> None:
        self.packets.append(record)
        self.last_seen = record.timestamp


# ----------------------------------------------------------------------
# PacketSniffer
# ----------------------------------------------------------------------
# Size of the in-memory queue between the raw capture callback and the
# flow-assembly worker thread. This decouples "reading packets off the
# wire" from "doing Python-level work on them" — under a sudden burst
# (e.g. a flood attack, which is exactly the traffic we most need to
# see), the capture callback can stay extremely fast and just hand off
# raw packets, while a separate thread catches up on flow assembly
# without blocking the socket read. Bounded (not unbounded) so a
# truly extreme flood can't grow memory without limit — see
# _enqueue_packet's drop-counting behaviour for what happens if this
# queue itself fills up.
#
# Note on kernel-level buffering: this queue protects against
# Python-level processing lag, but the OS kernel's own socket receive
# buffer (upstream of this queue entirely) can still drop packets
# under an extreme burst if it's too small. On Linux, that buffer is
# controlled by `net.core.rmem_max` / `net.core.rmem_default` — see
# docs/performance.md for how to increase it system-wide if you
# observe packet loss even with this queue in place.
CAPTURE_QUEUE_MAXSIZE = 50_000


class FlowAssembler:
    """
    Shared flow-assembly logic, used by both PacketSniffer (live
    capture) and PcapReader (offline .pcap replay). This exists so the
    two capture mechanisms can never drift apart in how they interpret
    packets into flows — a flow assembled from a live capture and one
    assembled by replaying the same traffic from a saved .pcap file
    will always behave identically, since they share this exact code.

    Subclasses are responsible only for the SOURCE of packets (a live
    socket, or a file on disk) — everything about what a "flow" means
    and when it's "finished" lives here, once.
    """

    def __init__(self, flow_timeout: float, max_active_flows: int, on_new_flow=None):
        self.flow_timeout = flow_timeout
        self.max_active_flows = max_active_flows

        # Optional callback invoked with (src_ip, timestamp) every time
        # a brand new flow is created (NOT once per packet). This is
        # how aggregate, cross-flow tracking (e.g. DDoS detection —
        # see detection/ddos_tracker.py) observes flow creation events
        # without FlowAssembler needing to know anything about what
        # that tracking does. None is a valid value (no-op) — most
        # tests and simple uses don't need this hook at all.
        self.on_new_flow = on_new_flow

        # Active flows currently being assembled, keyed by FlowKey.
        self._active_flows: dict[FlowKey, Flow] = {}

        # Finished flows ready to be consumed by the subclass's public
        # streaming method.
        self._finished_flows: list[Flow] = []
        self._lock = threading.Lock()

    def _process_one_packet(self, timestamp: float, packet: Packet) -> None:
        """
        The core flow-assembly logic for a single packet: identify
        which flow it belongs to (creating a new one if needed), add
        it to that flow, and finish the flow immediately if this
        packet carries a TCP FIN or RST flag.
        """
        if IP not in packet:
            # We only handle IPv4 for now. IPv6 support can be added later
            # by also checking for the IPv6 layer.
            return

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto  # 6=TCP, 17=UDP, 1=ICMP

        src_port = 0
        dst_port = 0
        tcp_flags = None

        if TCP in packet:
            tcp_layer = packet[TCP]
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)
            tcp_flags = str(tcp_layer.flags)
        elif UDP in packet:
            udp_layer = packet[UDP]
            src_port = int(udp_layer.sport)
            dst_port = int(udp_layer.dport)
        elif ICMP in packet:
            # ICMP has no ports — leave both at 0. The (0, 0) port pair
            # combined with protocol=1 still uniquely identifies the
            # conversation for our purposes.
            pass
        else:
            # Some other IP protocol we don't currently handle (e.g. GRE,
            # ESP). Skip it for Phase 1 — can be added later if needed.
            return

        flow_key = make_flow_key(src_ip, src_port, dst_ip, dst_port, protocol)

        header_size = len(ip_layer) - len(ip_layer.payload)
        total_size = len(packet)
        payload_size = max(total_size - header_size, 0)

        with self._lock:
            flow = self._active_flows.get(flow_key)

            if flow is None:
                # This is the first packet we've seen for this conversation —
                # start a new flow. The direction of THIS packet defines
                # "forward"; the reply direction will be "backward".
                flow = Flow(
                    flow_key=flow_key,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    start_time=timestamp,
                    last_seen=timestamp,
                )
                self._enforce_flow_limit()
                self._active_flows[flow_key] = flow
                direction = "forward"

                if self.on_new_flow is not None:
                    # Notify any aggregate/cross-flow tracking (e.g.
                    # DDoS detection) that a brand new flow has just
                    # started. Called once per flow, not once per
                    # packet — that distinction matters for accurate
                    # rate tracking.
                    self.on_new_flow(src_ip, timestamp)
            else:
                # Determine direction relative to how the flow started.
                direction = "forward" if (src_ip == flow.src_ip and src_port == flow.src_port) else "backward"

            record = PacketRecord(
                timestamp=timestamp,
                direction=direction,
                size=total_size,
                header_size=header_size,
                payload_size=payload_size,
                tcp_flags=tcp_flags,
            )
            flow.add_packet(record)

            # A TCP connection that sends FIN or RST is telling us the
            # conversation is over — we don't need to wait for the
            # inactivity timeout, we can finish the flow immediately.
            if tcp_flags and ("F" in tcp_flags or "R" in tcp_flags):
                flow.finished_cleanly = True
                self._finish_flow(flow_key)

    def _finish_flow(self, flow_key: FlowKey) -> None:
        """
        Move a flow from active to finished. MUST be called while
        holding self._lock (it is only called from within locked
        sections in this class).
        """
        flow = self._active_flows.pop(flow_key, None)
        if flow is not None:
            self._finished_flows.append(flow)

    def _sweep_timed_out_flows(self) -> None:
        """
        Check all active flows for inactivity timeout. Any flow that
        hasn't seen a packet in `flow_timeout` seconds is considered
        finished (the conversation has gone quiet) and is moved to the
        finished queue.
        """
        now = time.time()
        with self._lock:
            timed_out_keys = [
                key for key, flow in self._active_flows.items()
                if (now - flow.last_seen) >= self.flow_timeout
            ]
            for key in timed_out_keys:
                self._finish_flow(key)

    def _enforce_flow_limit(self) -> None:
        """
        If we are at the maximum number of active flows, evict the
        single oldest (least recently active) flow to make room for
        a new one. MUST be called while holding self._lock.

        This protects against memory exhaustion during something like
        a SYN flood, where an attacker opens huge numbers of flows.
        """
        if len(self._active_flows) < self.max_active_flows:
            return

        oldest_key = min(
            self._active_flows,
            key=lambda k: self._active_flows[k].last_seen,
        )
        self._finish_flow(oldest_key)


class PacketSniffer(FlowAssembler):
    """
    Captures live packets on a network interface and assembles them
    into flows. Use `stream_flows()` to get a generator that yields
    each finished Flow object as soon as it is ready.

    This class is intentionally NOT responsible for feature extraction
    or detection — it only captures and assembles. This separation
    means we can test flow assembly independently of the ML pipeline.

    Flow-assembly logic itself lives in the FlowAssembler base class,
    shared with PcapReader — this class adds only what's specific to
    LIVE capture: managing network interfaces, capture threads, and
    the packet queue used to keep up with high packet rates.
    """

    def __init__(self, config: dict, on_new_flow=None):
        super().__init__(
            flow_timeout=float(config["capture"]["flow_timeout_seconds"]),
            max_active_flows=int(config["capture"]["max_active_flows"]),
            on_new_flow=on_new_flow,
        )
        self.interfaces: list[str] = resolve_interfaces(config["capture"]["interfaces"])

        # Raw packets land here from the capture callback(s) and are
        # drained by a single dedicated worker thread. This is the key
        # architectural change for handling high packet rates: the
        # capture callback itself does almost no work, so the kernel
        # socket gets drained as fast as possible even if flow-assembly
        # is momentarily behind. Bounded size — see _enqueue_packet.
        self._packet_queue: queue.Queue = queue.Queue(maxsize=CAPTURE_QUEUE_MAXSIZE)

        # Counts packets that had to be dropped because the queue was
        # completely full (i.e. the worker thread could not keep up
        # even with the queue as a buffer). This is reported in the
        # CLI summary so it's never a SILENT loss — if Sentinel is
        # dropping packets under load, the operator must be able to
        # see that clearly, since it directly affects detection
        # reliability.
        self.dropped_packet_count: int = 0
        self._drop_count_lock = threading.Lock()

        # Set by stop() to signal the capture loop to halt.
        self._stop_requested = threading.Event()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def stream_flows(self) -> Iterator[Flow]:
        """
        Start live capture (one background thread per network interface,
        plus one dedicated flow-assembly worker thread) and yield
        finished flows as they become available. This is a generator —
        it will keep yielding flows until stop() is called.

        All interfaces feed into the SAME flow table, so a flow is
        identified purely by its (ip, port, protocol) — Sentinel gives
        you one unified view of traffic regardless of which physical
        interface (WiFi, Ethernet, etc.) it arrived on.

        Architecture note: capture callbacks only push raw packets onto
        a queue (see _enqueue_packet) — they do NOT do flow assembly
        directly. A separate worker thread (_process_queue) drains that
        queue and does the actual dict-building/locking/flow-assembly
        work. This keeps the capture callback fast enough to keep up
        with bursty traffic (e.g. floods, scans) without the kernel
        socket buffer overflowing and silently dropping packets.
        """
        capture_threads = []
        for interface in self.interfaces:
            thread = threading.Thread(
                target=self._run_capture,
                args=(interface,),
                daemon=True,
                name=f"sentinel-capture-{interface}",
            )
            thread.start()
            capture_threads.append(thread)

        worker_thread = threading.Thread(
            target=self._process_queue,
            daemon=True,
            name="sentinel-flow-assembly-worker",
        )
        worker_thread.start()

        # Main loop: periodically check for finished flows (both flows
        # that finished cleanly via FIN/RST, and flows that timed out
        # from inactivity), and yield them one at a time.
        while not self._stop_requested.is_set():
            self._sweep_timed_out_flows()

            with self._lock:
                ready = self._finished_flows
                self._finished_flows = []

            for flow in ready:
                yield flow

            # Small sleep to avoid busy-looping. The capture thread does
            # the real work; this loop just checks for finished flows.
            time.sleep(0.5)

        # On stop, flush every remaining active flow (even if it hasn't
        # technically timed out yet) so no data is silently dropped.
        with self._lock:
            remaining = list(self._active_flows.values())
            self._active_flows.clear()
        for flow in remaining:
            yield flow

    def stop(self) -> None:
        """Signal the capture loop to stop and flush remaining flows."""
        self._stop_requested.set()

    # ------------------------------------------------------------------
    # Internal: live capture
    # ------------------------------------------------------------------

    def _run_capture(self, interface: str) -> None:
        """
        Runs Scapy's sniff() loop on a single interface. This call
        blocks until stop_filter returns True, so each interface gets
        its own thread.

        The callback (_enqueue_packet) is intentionally minimal — it
        does not do flow assembly itself, only a fast push onto a
        queue drained by a separate worker thread. See stream_flows()
        for why this matters under high packet rates.

        The socket Scapy opens here will request a larger receive
        buffer than the OS default, via the module-level `conf.bufsize`
        setting (applied once, at import time — see SCAPY_BUFSIZE_BYTES
        above). This works together with the system-wide
        `net.core.rmem_max` sysctl setting (see docs/performance.md) —
        both need to be large enough, since the OS caps any per-socket
        request at that system ceiling.

        Requires root privileges to open a raw socket on most systems.
        If this interface goes down mid-capture (e.g. WiFi disconnects),
        we log it and let the thread end gracefully rather than crashing
        the whole sniffer — other interfaces keep running.
        """
        try:
            sniff(
                iface=interface,
                prn=self._enqueue_packet,
                store=False,  # Don't let Scapy buffer packets in memory — we handle storage ourselves
                stop_filter=lambda pkt: self._stop_requested.is_set(),
            )
        except OSError as e:
            # Common cause: the interface was unplugged/disabled while
            # capturing (e.g. WiFi toggled off, USB ethernet unplugged).
            print(f"[sentinel] Warning: capture on interface '{interface}' stopped: {e}")

    def _enqueue_packet(self, packet: Packet) -> None:
        """
        Capture callback — invoked by Scapy for every captured packet.

        This is intentionally as cheap as possible: it just timestamps
        the packet and pushes it onto the processing queue. All real
        work (parsing layers, building flows) happens in
        _process_queue(), on a separate thread, so this callback never
        becomes the bottleneck that causes kernel-level packet drops.

        If the queue is completely full (the worker thread truly cannot
        keep up even with a 50,000-packet buffer), the packet is
        dropped HERE rather than blocking — blocking this callback
        would stall Scapy's read loop and risk kernel-level drops
        anyway, so a fast, counted, visible drop is the safer failure
        mode. The count is exposed via dropped_packet_count so this is
        never a silent, invisible loss.
        """
        try:
            self._packet_queue.put_nowait((time.time(), packet))
        except queue.Full:
            with self._drop_count_lock:
                self.dropped_packet_count += 1

    def _process_queue(self) -> None:
        """
        Worker thread loop: continuously drains the packet queue and
        runs the real flow-assembly logic for each packet. Runs on its
        own dedicated thread so capture callbacks (_enqueue_packet)
        never have to wait for this work to finish.

        Uses a short timeout on queue.get() so the loop can notice
        _stop_requested promptly even if no packets are arriving.
        """
        while not self._stop_requested.is_set():
            try:
                timestamp, packet = self._packet_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            self._process_one_packet(timestamp, packet)

        # Drain any remaining queued packets on shutdown so the very
        # last burst of traffic before Ctrl+C isn't silently lost.
        while True:
            try:
                timestamp, packet = self._packet_queue.get_nowait()
            except queue.Empty:
                break
            self._process_one_packet(timestamp, packet)

    # _process_one_packet, _finish_flow, _sweep_timed_out_flows, and
    # _enforce_flow_limit are all inherited from FlowAssembler — no
    # override needed here, since live capture uses the exact same
    # flow-assembly rules as offline pcap replay.