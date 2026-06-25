# Sentinel — Safety Guide

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

The `tests/attack_simulator.py` script only ever targets `127.0.0.1` (localhost). Never point it at an external IP. Sending port scans or flood traffic to addresses you do not own is illegal in most jurisdictions.

## Privacy

Sentinel logs only flow-level metadata (IPs, ports, packet counts, timing statistics). Raw packet payloads are never captured or stored. This means Sentinel cannot read the content of your HTTP traffic, emails, or any encrypted communication — only the shape of the traffic.
