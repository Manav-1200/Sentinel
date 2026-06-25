"""
tests/conftest.py
====================
Shared pytest fixtures and helper classes used across the test suite.

The fake packet classes here mimic just enough of Scapy's packet
interface (the `in` operator, `[layer]` indexing, `len()`) for our
flow-assembly code to work with them, WITHOUT needing real Scapy
packet construction or root privileges to run. This is what lets the
test suite run in CI (GitHub Actions) and on any machine, without
needing a live network interface.
"""

import pytest

from capture.sniffer import IP, TCP, UDP, ICMP


class FakeIPLayer:
    """Mimics the fields our code reads from a Scapy IP layer."""

    def __init__(self, src, dst, proto, payload_len=20):
        self.src = src
        self.dst = dst
        self.proto = proto
        self._payload_len = payload_len

    def __len__(self):
        # Total IP layer length = header (assumed 20 bytes for these
        # tests) + payload length.
        return 20 + self._payload_len

    @property
    def payload(self):
        # Only used via len(ip_layer.payload) in sniffer.py — content
        # doesn't matter, only length.
        return "x" * self._payload_len


class FakeTCPLayer:
    """Mimics the fields our code reads from a Scapy TCP layer."""

    def __init__(self, sport, dport, flags=""):
        self.sport = sport
        self.dport = dport
        self.flags = flags


class FakeUDPLayer:
    """Mimics the fields our code reads from a Scapy UDP layer."""

    def __init__(self, sport, dport):
        self.sport = sport
        self.dport = dport


class FakePacket(dict):
    """
    Mimics Scapy's packet[Layer] indexing and `Layer in packet` checks
    by using the real IP/TCP/UDP/ICMP classes (imported from
    capture.sniffer, which re-exports them from scapy.all) as dict
    keys. `time` mimics Scapy's packet.time attribute (used only by
    PcapReader, which reads recorded timestamps rather than wall-clock
    time).
    """

    def __contains__(self, layer):
        return layer in self.layers

    def __getitem__(self, layer):
        return self.layers[layer]

    def __len__(self):
        return self._len

    def __init__(self, layers, total_len, time=0.0):
        self.layers = layers
        self._len = total_len
        self.time = time


def make_tcp_packet(src_ip, src_port, dst_ip, dst_port, flags, total_len=60, payload_len=20, time=0.0):
    """Convenience builder for a single fake TCP packet."""
    ip_layer = FakeIPLayer(src_ip, dst_ip, 6, payload_len=payload_len)
    tcp_layer = FakeTCPLayer(src_port, dst_port, flags)
    return FakePacket({IP: ip_layer, TCP: tcp_layer}, total_len=total_len, time=time)


def make_udp_packet(src_ip, src_port, dst_ip, dst_port, total_len=60, payload_len=20, time=0.0):
    """Convenience builder for a single fake UDP packet."""
    ip_layer = FakeIPLayer(src_ip, dst_ip, 17, payload_len=payload_len)
    udp_layer = FakeUDPLayer(src_port, dst_port)
    return FakePacket({IP: ip_layer, UDP: udp_layer}, total_len=total_len, time=time)


def make_icmp_packet(src_ip, dst_ip, total_len=60, payload_len=20, time=0.0):
    """Convenience builder for a single fake ICMP packet."""
    ip_layer = FakeIPLayer(src_ip, dst_ip, 1, payload_len=payload_len)
    return FakePacket({IP: ip_layer, ICMP: object()}, total_len=total_len, time=time)


@pytest.fixture
def basic_config():
    """A minimal, valid config dict covering everything the test suite needs."""
    return {
        "capture": {
            "interfaces": ["fake0"],
            "flow_timeout_seconds": 30,
            "max_active_flows": 10000,
        },
        "detection": {
            "warmup_flows": 30,
            "contamination": 0.05,
            "thresholds": {
                "suspicious": -0.02,
                "attack": -0.08,
            },
        },
    }
