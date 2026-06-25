"""
test_sniffer_manual.py
=======================
A throwaway manual test for capture/sniffer.py — run this directly to
confirm packet capture and flow assembly work on your machine, BEFORE
the rest of the pipeline (feature extraction, detection) exists.

This is NOT a pytest unit test (that comes later in tests/). This is
a quick visual sanity check you run by hand.

Usage:
    python test_sniffer_manual.py

While it's running, generate some traffic in another terminal, e.g.:
    ping -c 5 8.8.8.8
    curl https://example.com

Press Ctrl+C to stop. You should see flow summaries print as each
flow finishes (either by closing cleanly or timing out).
"""

import yaml
from capture.sniffer import PacketSniffer, resolve_interfaces

# Load the same config.yaml the real pipeline will use.
with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

# Resolve "auto" (or an explicit list) into actual interface names up
# front, purely so we can print a clear startup message. PacketSniffer
# will do this same resolution internally when it's constructed below.
interfaces = resolve_interfaces(config["capture"]["interfaces"])

print(f"Listening on interfaces: {', '.join(interfaces)}")
print("Generate some traffic in another terminal (e.g. `ping -c 5 8.8.8.8`).")
print("Press Ctrl+C to stop.\n")

sniffer = PacketSniffer(config)

try:
    for flow in sniffer.stream_flows():
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(flow.protocol, str(flow.protocol))
        duration = flow.last_seen - flow.start_time

        print(
            f"[FLOW FINISHED] {proto_name:<4} "
            f"{flow.src_ip}:{flow.src_port} <-> {flow.dst_ip}:{flow.dst_port} | "
            f"packets={len(flow.packets):<4} "
            f"duration={duration:.2f}s "
            f"clean_close={flow.finished_cleanly}"
        )
except KeyboardInterrupt:
    print("\nStopping sniffer...")
    sniffer.stop()
    print("Done.")