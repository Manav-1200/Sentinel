"""
tests/test_sniffer.py
========================
Unit tests for flow key symmetry and flow assembly logic in
capture/sniffer.py. Uses fake packet objects (see conftest.py) so
these tests run without root privileges, a live network interface,
or real Scapy packet construction.
"""

from capture.sniffer import PacketSniffer, make_flow_key
from tests.conftest import make_tcp_packet, make_udp_packet, make_icmp_packet


class TestFlowKeySymmetry:
    """
    A flow key must be identical regardless of which direction a
    packet is travelling — this is what makes a flow "bidirectional"
    rather than two separate, unrelated half-flows.
    """

    def test_tcp_flow_key_symmetric(self):
        forward = make_flow_key("192.168.1.5", 51000, "8.8.8.8", 443, 6)
        backward = make_flow_key("8.8.8.8", 443, "192.168.1.5", 51000, 6)
        assert forward == backward

    def test_icmp_flow_key_symmetric_with_no_ports(self):
        # ICMP has no ports — both src_port and dst_port are 0. This
        # should still produce a symmetric key, the same as TCP/UDP.
        forward = make_flow_key("192.168.1.5", 0, "8.8.8.8", 0, 1)
        backward = make_flow_key("8.8.8.8", 0, "192.168.1.5", 0, 1)
        assert forward == backward

    def test_different_ports_produce_different_keys(self):
        key_a = make_flow_key("192.168.1.5", 51000, "8.8.8.8", 443, 6)
        key_b = make_flow_key("192.168.1.5", 51000, "8.8.8.8", 80, 6)
        assert key_a != key_b

    def test_different_protocols_produce_different_keys(self):
        # Same IPs and ports, different protocol — must not collide.
        tcp_key = make_flow_key("192.168.1.5", 51000, "8.8.8.8", 53, 6)
        udp_key = make_flow_key("192.168.1.5", 51000, "8.8.8.8", 53, 17)
        assert tcp_key != udp_key


class TestFlowAssembly:
    """
    Tests that packets are correctly grouped into Flow objects, with
    correct direction assignment and correct packet counts.
    """

    def test_single_packet_creates_one_flow(self, basic_config):
        sniffer = PacketSniffer(basic_config)
        packet = make_tcp_packet("10.0.0.5", 51000, "10.0.0.9", 443, flags="S")

        sniffer._process_one_packet(1000.0, packet)

        assert len(sniffer._active_flows) == 1
        flow = list(sniffer._active_flows.values())[0]
        assert flow.src_ip == "10.0.0.5"
        assert flow.dst_ip == "10.0.0.9"
        assert len(flow.packets) == 1

    def test_bidirectional_packets_join_same_flow(self, basic_config):
        sniffer = PacketSniffer(basic_config)

        syn = make_tcp_packet("10.0.0.5", 51000, "10.0.0.9", 443, flags="S", time=0.0)
        syn_ack = make_tcp_packet("10.0.0.9", 443, "10.0.0.5", 51000, flags="SA", time=0.02)

        sniffer._process_one_packet(1000.0, syn)
        sniffer._process_one_packet(1000.02, syn_ack)

        # Both packets must have joined the SAME flow, not created two.
        assert len(sniffer._active_flows) == 1
        flow = list(sniffer._active_flows.values())[0]
        assert len(flow.packets) == 2
        assert flow.packets[0].direction == "forward"
        assert flow.packets[1].direction == "backward"

    def test_tcp_fin_finishes_flow_immediately(self, basic_config):
        sniffer = PacketSniffer(basic_config)

        syn = make_tcp_packet("10.0.0.5", 51000, "10.0.0.9", 443, flags="S")
        fin = make_tcp_packet("10.0.0.5", 51000, "10.0.0.9", 443, flags="FA")

        sniffer._process_one_packet(1000.0, syn)
        assert len(sniffer._active_flows) == 1

        sniffer._process_one_packet(1000.5, fin)

        # The FIN should have moved the flow from active to finished
        # immediately, without waiting for a timeout.
        assert len(sniffer._active_flows) == 0
        assert len(sniffer._finished_flows) == 1
        assert sniffer._finished_flows[0].finished_cleanly is True

    def test_tcp_rst_finishes_flow_immediately(self, basic_config):
        sniffer = PacketSniffer(basic_config)

        syn = make_tcp_packet("10.0.0.5", 51000, "10.0.0.9", 443, flags="S")
        rst = make_tcp_packet("10.0.0.9", 443, "10.0.0.5", 51000, flags="RA")

        sniffer._process_one_packet(1000.0, syn)
        sniffer._process_one_packet(1000.1, rst)

        assert len(sniffer._active_flows) == 0
        assert len(sniffer._finished_flows) == 1

    def test_udp_packets_never_close_automatically(self, basic_config):
        sniffer = PacketSniffer(basic_config)

        p1 = make_udp_packet("10.0.0.5", 53000, "8.8.8.8", 53, time=0.0)
        p2 = make_udp_packet("8.8.8.8", 53, "10.0.0.5", 53000, time=0.01)

        sniffer._process_one_packet(1000.0, p1)
        sniffer._process_one_packet(1000.01, p2)

        # UDP has no FIN/RST concept — the flow should still be active,
        # waiting for a timeout (which we are not testing here).
        assert len(sniffer._active_flows) == 1
        assert len(sniffer._finished_flows) == 0

    def test_icmp_packets_grouped_correctly(self, basic_config):
        sniffer = PacketSniffer(basic_config)

        ping = make_icmp_packet("10.0.0.5", "8.8.8.8", time=0.0)
        pong = make_icmp_packet("8.8.8.8", "10.0.0.5", time=0.02)

        sniffer._process_one_packet(1000.0, ping)
        sniffer._process_one_packet(1000.02, pong)

        assert len(sniffer._active_flows) == 1
        flow = list(sniffer._active_flows.values())[0]
        assert len(flow.packets) == 2
        assert flow.protocol == 1

    def test_different_destination_ports_create_separate_flows(self, basic_config):
        """
        Regression test for behaviour observed during real port-scan
        testing: many connection attempts to different ports from the
        same source IP must be tracked as separate flows, not merged
        into one — each (src_ip, src_port, dst_ip, dst_port) tuple is
        a distinct conversation.
        """
        sniffer = PacketSniffer(basic_config)

        for port in range(1, 11):
            packet = make_tcp_packet("10.0.0.99", 40000, "10.0.0.5", port, flags="S")
            sniffer._process_one_packet(1000.0, packet)

        assert len(sniffer._active_flows) == 10

    def test_flow_limit_evicts_oldest_flow(self, basic_config):
        """
        When max_active_flows is reached, the single oldest flow
        should be evicted to make room — this protects against memory
        exhaustion during a flood of new connections.
        """
        basic_config["capture"]["max_active_flows"] = 3
        sniffer = PacketSniffer(basic_config)

        for port, t in zip(range(1, 5), [1000.0, 1001.0, 1002.0, 1003.0]):
            packet = make_tcp_packet("10.0.0.99", 40000, "10.0.0.5", port, flags="S")
            sniffer._process_one_packet(t, packet)

        # Should never exceed the configured limit.
        assert len(sniffer._active_flows) == 3
        # The flow to destination port 1 (the oldest) should have been evicted.
        remaining_ports = {flow.dst_port for flow in sniffer._active_flows.values()}
        assert 1 not in remaining_ports
