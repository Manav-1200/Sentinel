"""
tests/test_pcap_reader.py
============================
Unit tests for capture/pcap_reader.py. Monkeypatches scapy's rdpcap()
to return fake packets (see conftest.py) rather than reading a real
.pcap file from disk — this keeps tests fast and dependency-free while
still exercising the real flow-assembly logic end to end.
"""

import capture.pcap_reader as pcap_module
from tests.conftest import make_tcp_packet, make_udp_packet


def test_pcap_reader_assembles_flows_correctly(basic_config, monkeypatch):
    """
    Regression test for a real bug found during Phase 1 development:
    an earlier version of this test incorrectly reused a single IP
    layer object (with a fixed src/dst) for packets travelling in
    BOTH directions, which produced an extra, spurious flow. This
    test uses correctly-directional packets and locks in the right
    behaviour: one TCP flow (closed via FIN) and one UDP flow.
    """
    fake_packets = [
        make_tcp_packet("192.168.1.50", 51000, "93.184.216.34", 443, flags="S", time=1000.0),
        make_tcp_packet("93.184.216.34", 443, "192.168.1.50", 51000, flags="SA", time=1000.02),
        make_tcp_packet("192.168.1.50", 51000, "93.184.216.34", 443, flags="A", time=1000.021),
        make_tcp_packet("192.168.1.50", 51000, "93.184.216.34", 443, flags="FA", time=1000.5),
        make_udp_packet("192.168.1.50", 53000, "8.8.8.8", 53, time=1001.0),
        make_udp_packet("192.168.1.50", 53000, "8.8.8.8", 53, time=1001.01),
    ]

    monkeypatch.setattr(pcap_module, "rdpcap", lambda path: fake_packets)

    reader = pcap_module.PcapReader(basic_config, "fake_path.pcap")
    flows = list(reader.stream_flows())

    assert len(flows) == 2

    tcp_flows = [f for f in flows if f.protocol == 6]
    udp_flows = [f for f in flows if f.protocol == 17]
    assert len(tcp_flows) == 1
    assert len(udp_flows) == 1

    tcp_flow = tcp_flows[0]
    assert len(tcp_flow.packets) == 4
    assert tcp_flow.finished_cleanly is True

    udp_flow = udp_flows[0]
    assert len(udp_flow.packets) == 2
    # UDP has no FIN/RST concept, so it should never be marked as
    # "cleanly" finished — it only ends because the file ran out.
    assert udp_flow.finished_cleanly is False


def test_pcap_reader_yields_finished_before_leftover_flows(basic_config, monkeypatch):
    """
    Verifies the documented yield order: flows that finished mid-file
    (via FIN/RST) come first, then flows still active when the file
    ends. This locks in PcapReader's documented behaviour so it
    doesn't silently change in a future refactor.
    """
    fake_packets = [
        # This TCP flow finishes mid-file via FIN.
        make_tcp_packet("10.0.0.1", 1000, "10.0.0.2", 80, flags="S", time=1.0),
        make_tcp_packet("10.0.0.1", 1000, "10.0.0.2", 80, flags="FA", time=1.1),
        # This UDP flow never closes — it's still active when the file ends.
        make_udp_packet("10.0.0.1", 2000, "10.0.0.2", 53, time=2.0),
    ]
    monkeypatch.setattr(pcap_module, "rdpcap", lambda path: fake_packets)

    reader = pcap_module.PcapReader(basic_config, "fake_path.pcap")
    flows = list(reader.stream_flows())

    assert len(flows) == 2
    assert flows[0].protocol == 6  # finished-via-FIN flow comes first
    assert flows[1].protocol == 17  # leftover-at-EOF flow comes last


def test_pcap_reader_uses_recorded_timestamps_not_wall_clock(basic_config, monkeypatch):
    """
    PcapReader must use each packet's own recorded `.time` value for
    flow timing, NOT the current wall-clock time — this is what makes
    replaying the same file always produce identical, reproducible
    timing-based features (duration, IAT) regardless of how long the
    test itself takes to run.
    """
    fake_packets = [
        make_tcp_packet("10.0.0.1", 1000, "10.0.0.2", 80, flags="S", time=5000.0),
        make_tcp_packet("10.0.0.1", 1000, "10.0.0.2", 80, flags="FA", time=5003.5),
    ]
    monkeypatch.setattr(pcap_module, "rdpcap", lambda path: fake_packets)

    reader = pcap_module.PcapReader(basic_config, "fake_path.pcap")
    flows = list(reader.stream_flows())

    assert len(flows) == 1
    flow = flows[0]
    assert flow.start_time == 5000.0
    assert flow.last_seen == 5003.5
