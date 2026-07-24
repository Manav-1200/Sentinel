# Sentinel — Safety Notes

Sentinel can automatically apply firewall rules against real traffic sources.
This document explains the safeguards in place, how to test safely, and how
to recover if something is blocked that shouldn't be.

## Never-block guarantees

Two config-driven checks run before *any* block is applied
(`response/blocker.py`'s `_check_skip()`), regardless of which detector
(anomaly, flood-guard, DDoS, port-scan, brute-force) triggered it:

1. **Loopback** — `127.0.0.1` / `::1` are never blocked, unconditionally, no
   config option can override this.
2. **Whitelist** — any IP listed in `config.yaml`'s `response.whitelist_ips`
   is never blocked. Always keep your router gateway and any machine you
   administer Sentinel from in this list.
3. **Private ranges** — by default (`response.block_private_ranges: false`),
   RFC1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
   and link-local (`169.254.0.0/16`) are never blocked. This is deliberately
   set to `true` on Azazel specifically because its whole real test network
   (LAN + Docker bridge) is private-range — if you copy this config to a
   different machine, check whether that override still makes sense for
   your network before keeping it.

If none of these apply, the source is blockable — but see "dry-run mode"
below for how to test that safely before trusting it live.

## Dry-run mode

`response.dry_run: true` (the safe default) makes Sentinel log exactly what
*would* be blocked — reason, source IP, computed duration — without ever
touching `nftables`/`iptables`. Every other part of the response pipeline
(alerting, GeoIP lookup, labelling) still runs normally in dry-run mode; only
the actual firewall mutation is skipped.

Recommended workflow when testing any new detector or threshold change:
run with `dry_run: true` first, confirm the CLI/log output looks correct for
a real attack scenario, *then* flip to `dry_run: false` for a live test.

## Escalating block duration

A repeat offender (the same source crossing an ATTACK threshold again after
a previous block — tracked per-detector via `repeat_offender_count`, see
`brute_force_tracker.py`/`port_scan_tracker.py`) gets a longer block than a
first-time offender, scaled by `response.escalation_multiplier` and capped at
`response.escalation_max_multiplier` × the base duration
(`response/blocker.py`'s `_effective_duration_minutes()`). The cap exists
specifically so a long-running attacker can't compute a block duration of
days or weeks — which would be operationally a permanent ban, but without
ever being reviewed as one.

## Recovering from an unwanted block

If Sentinel blocks an IP you didn't mean to lose access to (yourself, a
teammate, a service you rely on):

**Fastest — remove just that one rule:**
```bash
# nftables (preferred backend)
sudo nft list ruleset | grep <the-ip>          # find the exact rule/handle
sudo nft delete element inet sentinel blocked_ips { <the-ip> }

# iptables (fallback backend)
sudo iptables -L SENTINEL -n --line-numbers    # find the rule's line number
sudo iptables -D SENTINEL <line-number>
```

**Nuclear option — clear every Sentinel-applied rule:**
```bash
# nftables
sudo nft flush ruleset

# iptables
sudo iptables -F SENTINEL
```
⚠️ `nft flush ruleset` clears *all* nftables rules on the machine, not just
Sentinel's — only use this if you're comfortable rebuilding any other
firewall rules you had, or don't have any.

**Prevent it from re-blocking:** add the IP to `response.whitelist_ips` in
`config.yaml` before restarting Sentinel, or it may get blocked again the
next time the same traffic pattern is observed.

## What Sentinel never does

- Never logs raw packet payloads — flow-level metadata only (source/dest
  IP+port, protocol, timing, byte/packet counts). A block/alert decision is
  always explainable from metadata alone, never from payload content
  Sentinel doesn't have.
- Never blocks based on a single ambiguous signal alone — every ATTACK-level
  block is backed by an explicit, documented rule (a threshold crossing, not
  a vague "felt suspicious" judgment) — see each tracker's module docstring
  for its exact logic.
- Never silently fails a block and reports success — a firewall-level
  failure (missing `nft`/`iptables` binary, a backend command erroring) is
  always surfaced as `applied=False` in the returned `BlockResult`, logged as
  a warning, and never disguised as a working block.
