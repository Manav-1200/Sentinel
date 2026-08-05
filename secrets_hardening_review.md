# Secrets & Hardening Review

## Status

Review of the files actually available this session. Several
security-relevant modules (`response/blocker.py`, `pipeline/labeller.py`,
`main.py`, `config.yaml`) were **not uploaded** and are explicitly called
out below as unreviewed rather than assumed safe — this is a partial
review, not a clean bill of health for the whole codebase.

## What was checked

Scanned every uploaded `.py` file for: hardcoded credentials, shell
injection risk (`subprocess`/`os.system` with untrusted input,
`shell=True`), unsafe deserialization (`pickle`, `yaml.load` without a
safe loader), and unrestricted network bind addresses. Also read
`api/app.py`, `observability/cef_export.py`, and
`detection/geoip_lookup.py` in full for anything credential- or
network-facing.

## Findings

### 1. API keys — handled correctly, one gap

`detection/llm_analyser.py` pulls both `NVIDIA_NIM_API_KEY` and
`ANTHROPIC_API_KEY` from environment variables (`os.environ.get`), never
hardcoded, and raises a clear `RuntimeError` if missing rather than
silently proceeding with an empty key. This is the right pattern — keep
it.

**Gap:** nothing in the reviewed files enforces that `.env` (or wherever
these are actually stored) is git-ignored. This is a config/repo-hygiene
check, not a code check — confirm `.env` is listed in `.gitignore` and
was never committed historically (`git log --all --full-history -- .env`
is worth running once, since a key committed even in an old, since-
deleted commit is still recoverable from git history until the key
itself is rotated).

### 2. `api/app.py` has no authentication at all

Every route (`/incidents`, `/incidents/{key}`, `/incidents/{key}/resolve`,
`/incidents/{key}/reopen`) is open to anyone who can reach the port —
including the two ACTION routes (`resolve`/`reopen`), not just the
read-only ones. On a single trusted LAN box this is a low-severity gap;
it stops being acceptable the moment `api.host` is anything other than
`127.0.0.1`, or the moment the multi-sensor aggregator design (see
`docs/multi_sensor_architecture.md`) has this reachable from another
segment.

**Recommendation:** a static per-deployment API key, checked via a
FastAPI dependency (`Depends(require_api_key)`) applied to all routes —
same mechanism already proposed in the multi-sensor doc for
aggregator-to-sensor auth, so this isn't a second, separate piece of
work, it's the same fix serving both needs. Config-driven
(`api.api_key`, empty/unset = auth disabled, with a clear startup log
warning if so, rather than silently running open).

**Not reviewed:** whether `config.yaml` currently sets `api.host` to
`127.0.0.1` or `0.0.0.0` by default — that file wasn't uploaded this
session. This matters a lot: `0.0.0.0` with no auth means anyone on the
LAN (or further, if port-forwarded) can resolve/reopen incidents.
Confirm the actual default before treating this as low-severity.

### 3. `observability/cef_export.py`'s syslog exporter — no transport auth/encryption

`CEFSyslogExporter` defaults to UDP syslog with no TLS and no shared
secret — standard for CEF/syslog generally (most SIEM listeners expect
exactly this), but worth being explicit that this means CEF events
travel in plaintext, over UDP (so also droppable/spoofable) by default.
Acceptable for a local, single-host SIEM listener; **not** acceptable
as-is if the SIEM ingestion point is ever on a different host reached
over an untrusted network. Recommend documenting this as a deployment
constraint (bind to a loopback/trusted-segment SIEM listener, or add a
TLS-syslog option later) rather than silently letting someone assume
CEF export is safe over the open network.

### 4. GeoIP `api` method sends attacker IPs to a third party

`detection/geoip_lookup.py`'s `"api"` method sends every non-private
source IP it resolves to `ip-api.com` over plain HTTP (not HTTPS —
`http://ip-api.com/json/{ip}`, confirmed in the code). Two things worth
flagging together:
  - Every attacker (and, if `is_private_or_reserved` ever misjudges an
    edge case, potentially every legitimate visitor) IP gets sent to a
    third-party service — a real, if minor, data-sharing consideration
    worth being explicit about in `docs/` if this tool is ever deployed
    somewhere with data-handling policies to respect.
  - The request itself travels unencrypted, so it's also observable/
    tamperable in transit. `ip-api.com` does offer an HTTPS endpoint on
    their paid tier only; the free tier used here is HTTP-only by their
    design, not a Sentinel oversight — but it's still worth documenting
    as a reason to prefer the `"maxmind"` (fully offline, no third-party
    calls at all) method for any real deployment, exactly as
    `geoip_lookup.py`'s own module docstring already recommends for
    unrelated (rate-limit) reasons. This finding just adds a second,
    stronger reason to prefer `maxmind`.

### 5. `response/blocker.py` reviewed — no injection risk found

Follow-up from the original review (this file wasn't available at the
time): now reviewed in full. Every subprocess call
(`_NftablesBackend._run`, `_IptablesBackend._run`/`_rule_exists`) uses
list-form `subprocess.run(cmd, ...)`, never `shell=True` — no shell
injection surface at all. More importantly, every `block()`/`unblock()`
call runs through `_check_skip()` first, which calls
`ipaddress.ip_address(ip)` and returns a skip reason
(`"'{ip}' is not a valid IP address"`) for anything that doesn't parse
as a real IP, BEFORE the value ever reaches a backend command — so a
malformed or adversarially-crafted string can't reach a subprocess
argument in the first place. This is a clean, correctly-defended call
site. No action needed here.

### 6. No unsafe deserialization found

No `pickle`, no unsafe `yaml.load` calls in the reviewed files.
`detection/evidence.py`'s `_serialise()` helper (used for the DB storage
path per its docstring) wasn't fully read this session — worth a quick
confirming look, but nothing in what WAS read suggests unsafe
deserialization anywhere in the reviewed set.

## Priority order for follow-up

1. **`config.yaml`'s `api.host` default is now confirmed** — see the
   observability wiring pass: `api:` section added, defaults to
   `127.0.0.1`, matching the recommendation below. No longer an open
   question, just noting it's resolved.
2. **Implement the API key check** on `api/app.py` — serves both this
   review's finding #2 and the multi-sensor doc's auth requirement in
   one piece of work. Still not done — `api/app.py` itself hasn't been
   touched yet.
3. **Confirm `.env` git-hygiene** (gitignored, never historically
   committed).
4. Document the GeoIP third-party data-sharing consideration in
   `docs/` (finding #4) — low urgency, but cheap to write down now
   while it's fresh.
5. ~~Upload and review `response/blocker.py`~~ — done, see finding #5
   above. Clean.

## What this review does NOT cover

- `pipeline/labeller.py`, `main.py`, `config.yaml` — not uploaded this
  session, not reviewed at all (not even a partial scan, since they
  weren't available to read).
- Dependency-level vulnerabilities (e.g. a CVE in `fastapi`, `scapy`, or
  any other third-party package Sentinel depends on) — this review only
  covers Sentinel's own code, not a `pip-audit`/`safety`-style scan of
  the dependency tree. Worth running one of those tools separately.
- Anything about the Arch/Azazel host-level hardening (firewall rules
  outside Sentinel's own nftables/iptables use, SSH config, etc.) — out
  of scope for a code-level review of Sentinel itself.