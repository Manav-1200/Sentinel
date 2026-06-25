"""
test_extractor_manual.py
==========================
A throwaway manual test that wires capture/sniffer.py and
features/extractor.py together and runs them against REAL live
traffic on your machine. This is the next verification step after
test_sniffer_manual.py — it confirms the full chain (capture -> flow
assembly -> feature extraction) works correctly end to end.

This is NOT a pytest unit test. Just a visual sanity check.

Usage:
    python test_extractor_manual.py

While it's running, generate some traffic in another terminal, e.g.:
    ping -c 5 8.8.8.8
    curl https://example.com

Press Ctrl+C to stop.
"""

import yaml
from capture.sniffer import PacketSniffer, resolve_interfaces
from features.extractor import FeatureExtractor

with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

interfaces = resolve_interfaces(config["capture"]["interfaces"])
print(f"Listening on interfaces: {', '.join(interfaces)}")
print("Generate some traffic in another terminal (e.g. `ping -c 5 8.8.8.8`).")
print("Press Ctrl+C to stop.\n")

sniffer = PacketSniffer(config)
extractor = FeatureExtractor(config)

skipped_count = 0
extracted_count = 0

try:
    for flow in sniffer.stream_flows():
        features = extractor.extract(flow)

        if features is None:
            # Flow was too short (< 2 packets) to extract meaningful
            # features from — this is expected and fine, not an error.
            skipped_count += 1
            continue

        extracted_count += 1
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(features["protocol"], str(features["protocol"]))

        print(
            f"[FEATURES] {proto_name:<4} "
            f"{features['src_ip']}:{features['src_port']} <-> "
            f"{features['dst_ip']}:{features['dst_port']} | "
            f"pkts={features['total_packets']:<4} "
            f"dur={features['duration_seconds']:.2f}s "
            f"pps={features['packets_per_second']:.1f} "
            f"syn_ratio={features['syn_ratio']:.2f} "
            f"zero_payload_ratio={features['zero_payload_ratio']:.2f} "
            f"iat_std={features['iat_std']:.4f}"
        )

except KeyboardInterrupt:
    print("\nStopping...")
    sniffer.stop()
    print(f"\nSummary: {extracted_count} flows had features extracted, "
          f"{skipped_count} flows skipped (too short).")
    print("Done.")