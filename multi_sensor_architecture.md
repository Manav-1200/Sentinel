# Multi-Sensor Architecture

## Status

Design proposal — not yet implemented. This document describes how
Sentinel would extend from a single-box deployment to multiple sensors
covering different network segments, reporting into one place. Nothing
in this doc requires touching the current single-sensor code path; it's
additive.

## Why this matters for "enterprise level"

Today, Sentinel is one process on one box: one `CorrelationEngine`, one
SQLite file, one `AttackClassifier`, one `main.py` loop reading from one
set of interfaces. That's the right shape for a home network or a single
segment, but it doesn't match how a real organization's network looks —
multiple sites, VLANs, or cloud VPCs, each needing its own vantage point,
with a security team that wants ONE place to see everything, not one
dashboard per segment.

## What doesn't change

The per-sensor detection pipeline is untouched by this design:

- `detection/anomaly.py`, `ddos_tracker.py`, `port_scan_tracker.py`,
  `brute_force_tracker.py`, `llm_analyser.py` all keep running exactly as
  they do today, per-sensor, per-segment.
- `detection/evidence.py`'s `Evidence` objects are still the atomic unit
  each detector produces.
- A single sensor's local `CorrelationEngine` still groups Evidence into
  Incidents for that sensor's own traffic, same as today.

Multi-sensor is about what happens ABOVE that layer — how many of these
already-working single-sensor pipelines get aggregated into one view —
not a rework of detection itself.

## Two candidate shapes

### Option A: Central aggregator polls each sensor's API

Each sensor runs exactly what it runs today, including its own
`api/app.py` instance exposing `/incidents`. A new central process
(`aggregator/`) periodically polls every registered sensor's `/incidents`
endpoint, tags each incident with the sensor it came from, and merges
them into one combined view.

**Pros:**
- Zero changes to any existing sensor-side module — `api/app.py` already
  does everything a sensor needs to expose.
- Sensors stay fully autonomous — a sensor that loses connectivity to
  the aggregator keeps detecting and blocking locally; it just stops
  being visible centrally until connectivity returns. For a security
  tool, "keep protecting even if the mothership is unreachable" is the
  right failure mode.
- Simple to reason about and to secure (aggregator initiates outbound
  polling connections to sensors, or sensors sit behind a reverse proxy —
  either way it's plain HTTP(S) with existing tooling).

**Cons:**
- Polling means the aggregator's view is only as fresh as the poll
  interval — a genuine, if minor, latency cost compared to push.
- N sensors means N HTTP round-trips per poll cycle; fine at the scale
  Sentinel realistically targets (tens of sensors, not thousands), but
  wouldn't scale to a huge fleet without pagination/backoff logic the
  current `/incidents` endpoint doesn't have yet.

### Option B: Sensors push Evidence to a central collector

Each sensor ships raw `Evidence` (not aggregated Incidents) to a central
collector as it's created — essentially, `observability/cef_export.py`'s
"ship to a remote endpoint" pattern, but the remote endpoint is
Sentinel's own aggregator instead of a third-party SIEM, and it receives
structured Evidence instead of CEF text. The aggregator runs its OWN
`CorrelationEngine`, doing correlation centrally across all sensors'
combined Evidence stream.

**Pros:**
- Real-time — evidence arrives as it happens, no poll interval.
- Enables cross-sensor correlation: a source seen probing one segment
  and brute-forcing another shows up as ONE incident centrally, which
  Option A structurally cannot do (Option A's incidents are already
  grouped per-sensor by the time the aggregator sees them).

**Cons:**
- A real new failure mode: what happens to Evidence generated while the
  central collector is unreachable? Needs a local durable queue per
  sensor (a bounded on-disk buffer, replayed on reconnect) — genuinely
  new code, not a re-use of anything that exists today.
- The aggregator's `CorrelationEngine` becomes a second, larger-scale
  instance of code that's only ever been proven at single-sensor volume.
  Untested at multi-sensor scale until built.
- Requires a new ingestion endpoint and a defined Evidence transport
  schema/protocol — more genuinely new surface area than Option A.

## Recommendation

**Option A first, Option B as a deliberate future upgrade.**

Option A is buildable almost entirely out of code that already exists —
`api/app.py`'s `/incidents` endpoint was built generally enough to serve
this without modification, and it preserves the "sensor keeps protecting
itself even if the center goes away" property that matters most for a
security tool. Cross-sensor correlation (Option B's real advantage) is a
genuinely valuable future capability, but it's also a materially bigger
and riskier piece of engineering (durable local queuing, a new ingestion
protocol, an untested second `CorrelationEngine` instance at scale) that
shouldn't gate calling multi-sensor support "done" for a solo portfolio
project's enterprise-readiness pass.

If cross-sensor correlation is ever needed later, Option A doesn't need
to be thrown away first — a central aggregator that already polls every
sensor's `/incidents` is a natural place to LATER add a secondary
push-based Evidence stream for correlation specifically, while keeping
Option A's incident view as the resilient fallback.

## Proposed shape of Option A

```
┌─────────────┐      poll /incidents      ┌──────────────────┐
│  Sensor A    │ ─────────────────────────▶│                  │
│ (segment 1)  │                            │                  │
└─────────────┘                            │   Aggregator      │
                                            │  - merges incidents
┌─────────────┐      poll /incidents       │  - tags by sensor  │
│  Sensor B    │ ─────────────────────────▶│  - one dashboard   │
│ (segment 2)  │                            │    view over all  │
└─────────────┘                            │    sensors         │
                                            └──────────────────┘
┌─────────────┐      poll /incidents
│  Sensor N    │ ─────────────────────────▶ (same)
└─────────────┘
```

### Sensor identity

Each sensor needs a stable identity for the aggregator to tag incidents
with. Simplest option: a `sensor_id` string in each sensor's
`config.yaml` (e.g. `sensor_id: "office-vlan-10"`), included in every
response from that sensor's `/incidents` and `/incidents/{key}`
endpoints. This is a small, additive change to `api/app.py`'s response
models (`IncidentSummaryOut`/`IncidentDetailOut` gain a `sensor_id`
field, populated from config rather than the `CorrelationEngine`, since
the engine itself has no concept of which sensor it's running on).

### Aggregator responsibilities

A new `aggregator/` package, roughly:

- `aggregator/config.py` — list of registered sensors: `{sensor_id, base_url, api_key}`.
- `aggregator/poller.py` — polls each sensor's `/incidents?include_resolved=true`
  on an interval, handles a sensor being temporarily unreachable
  (log + skip that sensor for this cycle, don't let one down sensor
  block polling the others).
- `aggregator/store.py` — an in-memory (or lightweight SQLite, mirroring
  Sentinel's own existing storage choice) merged view keyed by
  `(sensor_id, incident.incident_id)`, since incident IDs are already
  UUIDs and collisions across sensors are not a concern.
- `aggregator/app.py` — its own small FastAPI app (same pattern as
  `api/app.py`) exposing the merged, cross-sensor view — this is what a
  real central dashboard would point at instead of any single sensor's
  API directly.

### Authentication between aggregator and sensors

Today's `api/app.py` has no auth at all — fine for a single box on a
trusted LAN, not fine once a central aggregator is reaching out to
sensors that might sit on different networks. Recommend a simple static
API key per sensor (checked via a FastAPI dependency on every route),
config-driven (`api.api_key` in each sensor's `config.yaml`), passed as
a bearer token by the aggregator. This is intentionally the SIMPLEST
adequate option — full OAuth/mTLS is real additional infrastructure that
isn't justified until there's a concrete deployment that needs it, but
"anyone on the network can query or resolve incidents with no
credential" isn't acceptable to leave as-is once sensors are exposed
beyond one trusted box. (This same api_key mechanism is also the
natural fix for `api/app.py`'s current complete lack of access control,
independent of multi-sensor — see the secrets/hardening review item
still on the roadmap.)

### What the aggregator does NOT do

- It does not run detection of any kind — no `AnomalyDetector`, no
  trackers, no LLM calls. It is purely a merge/presentation layer over
  incidents that sensors have already produced.
- It does not currently attempt cross-sensor correlation (see Option B
  above for why that's deliberately deferred).
- It does not replace any sensor's local blocking/response — each sensor
  still blocks locally via its own `response/blocker.py`; the aggregator
  can surface a "resolve"/"reopen" action (proxied through to the right
  sensor's own endpoint) but never bypasses a sensor's local decision-
  making.

## Open questions for a future build session

- Poll interval default and whether it should be adaptive (faster
  polling for sensors with recent activity, slower for quiet ones).
- Whether `aggregator/store.py` needs to persist across restarts at all,
  given every sensor already durably stores its own incidents — the
  aggregator's merged view may be fine as a rebuild-on-poll cache with
  no persistence of its own.
- Whether the future dashboard (Phase 4) talks to individual sensors
  directly for single-sensor drill-down, or always goes through the
  aggregator even for that — leaning towards "always through the
  aggregator, which proxies through," so the dashboard only ever needs
  to know about one API surface.
