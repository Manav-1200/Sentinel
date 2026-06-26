# Sentinel — Safety Guide

> **Status note:** auto-blocking (the actual `iptables` enforcement this document describes) is a **Phase 3 feature, not yet implemented**. Phase 1 only detects and logs/displays verdicts — it never modifies firewall rules. The `response.dry_run` and whitelist settings already exist in `config.yaml` as forward-looking configuration, ready for when Phase 3 is built, but nothing currently reads or acts on them. This document describes the *intended* safety model for when that lands, so the design is settled before the code that enforces it exists.

## The golden rule

Always start with `dry_run: true` in `config.yaml`. In dry-run mode, Sentinel logs every blocking decision without executing any `iptables` commands. Only switch to `dry_run: false` once you have watched the system operate for a few hours and are satisfied with its accuracy.

## What Sentinel will never block

The following are hardcoded safety exceptions that cannot be overridden by config:

- `127.0.0.0/8` — loopback (your own machine)
- `::1` — IPv6 loopback
- Your own public IP (fetched from `api.ipify.org` on startup)

The following are configurable in `config.yaml` under `response.whitelist_ips` and default to protected:

- `192.168.1.1` (or your router's gateway IP — update this)
- Any IP you add to the whitelist

Private ranges (`10.x`, `172.16.x`, `192.168.x`) are protected by default via `response.block_private_ranges: false`.

## If you accidentally lock yourself out

If a bad iptables rule blocks your own access, flush all Sentinel rules:

```bash
# Flush all rules in the INPUT chain (removes all blocks)
sudo iptables -F INPUT

# Or, to remove only Sentinel's chain if implemented separately
sudo iptables -F SENTINEL
sudo iptables -X SENTINEL
```

If you locked yourself out of an SSH session on a remote VPS, most providers offer a web-based console that bypasses network rules — use that to flush iptables.

## Attack simulations

There is no dedicated `attack_simulator.py` script (yet — a reasonable Phase 2/3 addition once labelled-data generation matters more). Real testing during Phase 1 development used:

- `nmap -sS` (SYN scan) from a separate source (a Docker container on the default bridge network, or another device on the LAN) targeting your own machine's real IP — confirmed during development that scanning `127.0.0.1` or your own IP from itself does not reliably reach the capture layer (a real Linux networking quirk, not a Sentinel bug).
- `ping -A -c <count>` (a fast, repeated ping burst) from the same kind of separate source, to simulate a flood.

**Always target only machines and addresses you own or have explicit permission to test.** Sending port scans or flood traffic to addresses you do not own is illegal in most jurisdictions, including against your own ISP's infrastructure or shared/cloud IPs you don't control.

## Privacy

Sentinel logs only flow-level metadata (IPs, ports, packet counts, timing statistics). Raw packet payloads are never captured or stored. This means Sentinel cannot read the content of your HTTP traffic, emails, or any encrypted communication — only the shape of the traffic.
