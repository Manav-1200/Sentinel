# Sentinel — Performance Tuning

## Why this document exists

During testing (Phase 1, June 2026), we discovered that a fast burst
of traffic (2000 ICMP pings sent in well under a second, via
`ping -A`) resulted in only ~5% of the expected packets being
captured by Sentinel. This was traced to **kernel-level packet
loss**, not a bug in Sentinel's Python logic — the operating system's
network socket buffer filled up faster than Python could drain it,
and the kernel silently dropped the excess packets before Scapy ever
saw them.

This is a known, fundamental characteristic of any pure-Python packet
capture tool (Scapy included) under sustained high packet rates. It
is not unique to Sentinel — the same limitation affects any tool
built the same way. Production-grade systems handle this with a
combination of the fixes below.

## Fix 1 — Queue-based capture architecture (built in)

As of Phase 1, Sentinel's capture callback (`_enqueue_packet`) does
the absolute minimum work possible: it timestamps the packet and
pushes it onto an in-memory queue. A separate worker thread
(`_process_queue`) drains that queue and does the actual flow
assembly. This means the capture callback returns almost immediately,
so Scapy can keep reading from the socket as fast as the kernel
delivers packets, rather than being blocked by Python-level
processing.

If the queue itself fills up (50,000 packets by default — see
`CAPTURE_QUEUE_MAXSIZE` in `capture/sniffer.py`), packets are dropped
at that point instead, and the count is tracked in
`PacketSniffer.dropped_packet_count`. This is surfaced in the CLI
display so packet loss is always visible to the operator, never
silent.

## Fix 2 — Increase the kernel's socket receive buffer

The OS default receive buffer for raw sockets is often only a few
hundred KB. Increasing it gives the kernel more room to hold packets
during a burst before Sentinel's queue (Fix 1) even gets involved.

**Check current limits:**
```bash
sysctl net.core.rmem_max
sysctl net.core.rmem_default
```

**Increase them (temporary, until reboot):**
```bash
sudo sysctl -w net.core.rmem_max=33554432
sudo sysctl -w net.core.rmem_default=33554432
```

**Make it permanent:**
```bash
echo "net.core.rmem_max=33554432" | sudo tee -a /etc/sysctl.d/99-sentinel.conf
echo "net.core.rmem_default=33554432" | sudo tee -a /etc/sysctl.d/99-sentinel.conf
sudo sysctl --system
```

(33554432 bytes = 32 MB — a generous buffer for a personal machine.
Adjust based on available RAM if deploying on a constrained system.)

## Fix 3 — Know the realistic limits

Even with both fixes above, **pure Python + Scapy is not line-rate
capture** — it will never match dedicated tools like Suricata or
Zeek (which use compiled, kernel-bypass techniques like eBPF/XDP or
PF_RING). For a personal NIDS monitoring a home/small network, the
combination of Fix 1 + Fix 2 is sufficient for realistic attack
traffic (port scans, moderate floods, brute-force attempts). For
genuinely line-rate detection on a high-throughput network, a
from-scratch Python tool would need to move to a compiled capture
layer — a legitimate "Phase 6+" idea if you want to push this project
further, but out of scope for the current architecture.

## How to verify capture is keeping up

Run Sentinel and check the `dropped_packet_count` shown in the CLI
summary line after a period of traffic. A non-zero count under normal
browsing traffic suggests Fix 2 is needed. A non-zero count only
during deliberate flood testing (far exceeding realistic attack
traffic) is expected and not a cause for concern.