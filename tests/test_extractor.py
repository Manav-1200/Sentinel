"""
tests/test_extractor.py
==========================
Unit tests for features/extractor.py — verifies that flow objects are
correctly converted into feature dicts, with correct values for both
a normal-looking flow and an attack-shaped (simulated SYN scan) flow.
"""

from capture.sniffer import Flow, PacketRecord, make_flow_key
from features.extractor import extract, MIN_PACKETS_FOR_EXTRACTION


def _build_flow(packets_spec, src_ip="192.168.1.50", dst_ip="93.184.216.34",
                 src_port=51000, dst_port=443, protocol=6, start_time=1000.0):
    """
    Helper: builds a Flow object from a list of
    (direction, time_offset, size, tcp_flags, payload_size) tuples.

    payload_size is given explicitly rather than derived from `size`,
    since real packets vary in header size (TCP options, VLAN tags,
    etc.) — tests should state the payload they intend, not have it
    silently computed from an assumed fixed header size.
    """
    flow_key = make_flow_key(src_ip, src_port, dst_ip, dst_port, protocol)
    flow = Flow(
        flow_key=flow_key,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        start_time=start_time,
        last_seen=start_time,
    )
    for spec in packets_spec:
        direction, t_offset, size, flags = spec[0], spec[1], spec[2], spec[3]
        payload_size = spec[4] if len(spec) > 4 else max(size - 40, 0)
        record = PacketRecord(
            timestamp=start_time + t_offset,
            direction=direction,
            size=size,
            header_size=size - payload_size,
            payload_size=payload_size,
            tcp_flags=flags,
        )
        flow.add_packet(record)
    return flow


class TestExtractionBasics:

    def test_flow_below_minimum_packets_returns_none(self):
        flow = _build_flow([("forward", 0.0, 60, "S")])  # only 1 packet
        assert len(flow.packets) < MIN_PACKETS_FOR_EXTRACTION
        assert extract(flow) is None

    def test_extract_returns_none_for_empty_flow(self):
        flow = _build_flow([])
        assert extract(flow) is None

    def test_extract_includes_identity_fields(self):
        flow = _build_flow([
            ("forward", 0.0, 60, "S"),
            ("backward", 0.02, 60, "SA"),
        ])
        result = extract(flow)
        assert result["src_ip"] == "192.168.1.50"
        assert result["dst_ip"] == "93.184.216.34"
        assert result["src_port"] == 51000
        assert result["dst_port"] == 443
        assert result["protocol"] == 6


class TestNormalTrafficFeatures:
    """
    A realistic small HTTPS handshake: SYN, SYN-ACK, ACK, some data,
    then a clean FIN close. Values are hand-verified.
    """

    def _normal_flow(self):
        return _build_flow([
            ("forward", 0.000, 60, "S"),
            ("backward", 0.020, 60, "SA"),
            ("forward", 0.021, 52, "A"),
            ("forward", 0.025, 500, "PA"),
            ("backward", 0.090, 1400, "PA"),
            ("backward", 0.091, 1400, "PA"),
            ("forward", 0.095, 52, "A"),
            ("forward", 0.100, 52, "FA"),
            ("backward", 0.110, 52, "FA"),
        ])

    def test_packet_counts(self):
        result = extract(self._normal_flow())
        assert result["total_packets"] == 9
        assert result["fwd_packets"] == 5
        assert result["bwd_packets"] == 4

    def test_syn_ratio_is_low_for_normal_handshake(self):
        result = extract(self._normal_flow())
        # Only 2 of 9 packets carry the SYN flag (SYN and SYN-ACK) —
        # a normal handshake should have a low SYN ratio.
        assert result["syn_count"] == 2
        assert 0.0 < result["syn_ratio"] < 0.3

    def test_zero_payload_ratio_is_not_extreme(self):
        result = extract(self._normal_flow())
        # A normal flow carries real payload on at least some packets,
        # so zero_payload_ratio should not be 1.0.
        assert result["zero_payload_ratio"] < 1.0

    def test_well_known_port_flag(self):
        result = extract(self._normal_flow())
        assert result["is_well_known_dst_port"] == 1  # port 443 < 1024


class TestAttackShapedFeatures:
    """
    A simulated SYN scan: many rapid SYN packets, no replies, zero
    payload. These values were hand-verified against the synthetic
    test run during Phase 1 development and should remain stable.
    """

    def _syn_scan_flow(self, packet_count=20):
        # Bare SYN packets carry no payload at all — explicitly zero,
        # not derived from total size minus an assumed header size.
        packets_spec = [
            ("forward", i * 0.001, 60, "S", 0)
            for i in range(packet_count)
        ]
        return _build_flow(packets_spec, dst_port=22)

    def test_syn_ratio_is_maximal(self):
        result = extract(self._syn_scan_flow())
        assert result["syn_ratio"] == 1.0

    def test_zero_payload_ratio_is_maximal(self):
        result = extract(self._syn_scan_flow())
        assert result["zero_payload_ratio"] == 1.0

    def test_no_backward_packets(self):
        result = extract(self._syn_scan_flow())
        assert result["bwd_packets"] == 0

    def test_high_packets_per_second(self):
        result = extract(self._syn_scan_flow(packet_count=20))
        # 20 packets sent 1ms apart spans ~19ms — packets_per_second
        # should be very high (roughly 1000+).
        assert result["packets_per_second"] > 500

    def test_normal_and_attack_flows_are_clearly_distinguishable(self):
        """
        A direct comparison test: the SYN ratio and zero-payload ratio
        for a SYN scan must be unambiguously higher than for normal
        traffic. This is the core property the anomaly detector relies
        on downstream.
        """
        normal = extract(_build_flow([
            ("forward", 0.000, 60, "S"),
            ("backward", 0.020, 60, "SA"),
            ("forward", 0.021, 52, "A"),
            ("forward", 0.025, 500, "PA"),
        ]))
        attack = extract(self._syn_scan_flow())

        assert attack["syn_ratio"] > normal["syn_ratio"]
        assert attack["zero_payload_ratio"] > normal["zero_payload_ratio"]
