# Sentinel

**Real-time network threat detection and response.**

Sentinel is an AI-powered Network Intrusion Detection and Response System (NIDRS) built from scratch — no pre-packaged datasets, no inherited code. It's built in phases (see [`PHASES.md`](PHASES.md)); **Phases 1–3.5 are complete and verified against real attack traffic on real hardware**: detection (anomaly/flood/DDoS/port-scan/brute-force), ML classification + LLM self-labelling, auto-blocking + GeoIP + alerting, and an enterprise-readiness layer (incident correlation, risk scoring, MITRE ATT&CK tagging, observability, a REST API with auth, DB retention). **Phase 4's terminal dashboard is also complete** — a native desktop app is next.

![Tests](https://github.com/Manav-1200/sentinel/actions/workflows/test.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11+-blue)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)

---

## What makes this different

Most intrusion detection projects train on a pre-labelled dataset (like CIC-IDS2017) and stop there. Sentinel builds its own dataset as it runs, with no pre-existing labels needed to start detecting:

1. **Isolation Forest** anomaly detector flags suspicious flows from day one, with zero labels needed.
2. A dedicated **flood-rate guard** catches single-source DoS floods the general model doesn't reliably separate from bursty normal traffic.
3. A **DDoS tracker** watches connection patterns across all sources at once — visible only in aggregate, invisible to any per-flow detector.
4. A **port-scan tracker** watches distinct destination ports per source in a sliding window (vertical + horizontal fan-out), and surfaces duration/rate/confidence detail for anything that consumes it — not just a verdict.
5. A **brute-force tracker** watches per-`(source, destination, port)` auth attempts against common credential-facing ports.
6. An **LLM analyser** (NVIDIA NIM by default, Claude optional) labels flagged flows offline, turning them into training data.
7. A **supervised classifier** (RandomForest/XGBoost) adds attack-type predictions alongside the anomaly verdict — it never overrides a detection, only adds detail to one.

On top of detection, every finding — anomaly, flood, DDoS, port scan, brute force, LLM — flows through a **shared Evidence/Incident/Risk pipeline**: a single `Evidence` shape from every detector, an `IncidentCorrelationEngine` that groups evidence by source into incidents that never silently auto-close, a trust-weighted `RiskEngine` that fuses multi-detector corroboration into one score, and MITRE ATT&CK technique tagging per incident. Auto-blocking (nftables/iptables) and GeoIP-tagged alerting (email/Slack/webhook) sit downstream of that same pipeline, verified end-to-end on real hardware.

An authenticated REST API (`api/app.py`) exposes incidents/summary/resolve/reopen, with DB retention/rotation running alongside it so the SQLite store doesn't grow unbounded. A Textual terminal dashboard (`detection/tui_dashboard.py`) is a real HTTP client of that API — live incident view, sortable by risk, with a full evidence-timeline detail screen.

Along the way this surfaced and fixed several real production-grade issues — kernel-level packet loss under load, Isolation Forest sensitivity dilution, LLM prompt bias, an SDK-retry-induced hang, a silent JSON-serialization bug that broke `--pcap` replay entirely, a broken module import that would have crashed live capture the moment the API was enabled — documented in `docs/performance.md`, `PHASES.md`, and the codebase.

---

## Features

**Detection (Phase 1–2):** live multi-interface packet capture (or `.pcap` replay) · ~30 features per flow · unsupervised anomaly detection · flood-rate guard · aggregate DDoS tracker · per-source port-scan tracker (with duration/rate/confidence detail) · per-source/dest/port brute-force tracker · LLM self-labelling pipeline (rate-limit-aware retry queue) · supervised classifier (RandomForest/XGBoost) · live colour-coded CLI with BLOCKED/ALLOWED status · JSON-lines logging.

> The classifier is currently effectively untrained (~82 diverse samples, heavy class imbalance) — the bulk-transfer/`ddos` misclassification issue has a code-level fix pending live verification; flood/DoS separability remains a partial, honestly-labelled improvement, not a full fix. See [Known issues](#known-issues).

**Response (Phase 3 — complete, real-hardware verified):** nftables/iptables auto-blocking with whitelist/private-range safety and dry-run mode (block, expiry, and iptables fallback all verified) · GeoIP lookup (ip-api.com / MaxMind) · email/Slack/webhook alerting (webhook delivery verified live) · full response wiring with pytest coverage.

**Enterprise readiness (Phase 3.5 — complete):** unified `Evidence` object across every detector · `IncidentCorrelationEngine` (incidents group by source, never auto-close) · trust-weighted `RiskEngine` (multi-detector corroboration bonus) · MITRE ATT&CK technique tagging · Prometheus metrics · CEF/SIEM export · structured JSON-lines logging · Markdown incident reports · authenticated REST API (`api/app.py` — static per-deployment key via `SENTINEL_API_KEY`, every route but `/health` gated) · three-tier DB retention/rotation (`pipeline/retention.py` — bulk evidence, resolved-incident findings, training-sample size cap; batched deletes + interval-gated VACUUM).

**Dashboard (Phase 4.1′ — complete):** Textual TUI (`detection/tui_dashboard.py`, `python main.py --dashboard`) — a genuine HTTP client of the incidents API, run as a separate process alongside live capture. Live summary panel (open incidents, risk tier breakdown, blocked IP count), an open-incidents table sortable by risk, and a full incident-detail view with evidence timeline. See `PHASES.md`'s Phase 4 section for why this pivoted from an originally-planned in-process design to an HTTP-client one.

**Planned:** native desktop app (Phase 4.2′, Tauri vs PySide6 still undecided) · auto-retraining + model versioning (Phase 5). Full roadmap in [`PHASES.md`](PHASES.md).

---

## Project structure

```
sentinel/
├── capture/          Packet capture and flow assembly
├── features/         Feature extraction (30+ per flow)
├── detection/         Anomaly detector, classifier, port-scan/DDoS/brute-force trackers,
│                      LLM analyser, correlation engine, risk engine, MITRE tagging,
│                      TUI dashboard
├── response/          Auto-blocker, GeoIP lookup, alerting
├── api/                Authenticated REST API (incidents, summary, resolve/reopen)
├── observability/      Prometheus metrics, CEF/SIEM export, structured logging
├── reporting/          Markdown incident reports
├── pipeline/           Self-labelling, DB retention/rotation, auto-retraining (planned)
├── dashboard/          (legacy placeholder — the real dashboard is detection/tui_dashboard.py)
├── tests/              Unit tests for every module (348 passing)
├── docs/               Write-ups, safety notes, deployment guide
├── data/
│   ├── logs/           SQLite DB, detection logs, block logs
│   └── models/         Saved model files with versioning
├── config.yaml         All tunable parameters
├── .env.example        Credentials template (never commit .env)
└── main.py             Entry point
```

---

## Quick start

### 1. Install

No virtualenv — system Python + pacman, since the goal is a system-installable CLI tool (see `requirements.txt` header). On Arch:

```bash
git clone https://github.com/Manav-1200/sentinel.git
cd sentinel
sudo pacman -S python-scapy python-pip python-pandas python-numpy
pip install -r requirements.txt --break-system-packages
```

On other distros, install `scapy`/`pandas`/`numpy` however your platform prefers, then `pip install -r requirements.txt`.

### 2. Allow packet capture without root

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python))
```

Run as your normal user from here on. This resets on Python package updates (e.g. `pacman -Syu`) and needs reapplying.

### 3. Configure

```bash
cp .env.example .env
```

Set `SENTINEL_API_KEY` in `.env` to a random string — the incidents API (and the TUI dashboard, which talks to it) won't start without it. Check `config.yaml`:
- `capture.interfaces` — `"auto"` or an explicit list; include `docker0` if testing with Docker-sourced traffic
- `response.dry_run` — keep `true` unless you want live nftables/iptables rules applied; `response.block_private_ranges` should be `true` if your LAN is entirely private-range
- `llm.provider` — `"nim"` (free tier, default) or `"anthropic"`
- `port_scan.*` — window size and thresholds for the port-scan tracker
- `api.*` — host/port/`require_auth` for the incidents API
- `retention.*` — DB retention tiers and how often they run
- `dashboard.refresh_interval_seconds` — how often the TUI re-polls the API

### 4. Run

```bash
python main.py                              # live capture, all interfaces
python main.py --interface wlo1,enp2s0       # explicit interfaces
python main.py --pcap path/to/capture.pcap   # replay a pcap
python main.py --label                       # check labelled-sample stats
python main.py --dashboard                   # TUI dashboard (run alongside live capture, in a second terminal)
```

### 5. Simulate an attack safely

Scanning `127.0.0.1` or your own LAN IP from itself won't reach Sentinel's capture layer (same-host traffic hairpins at the kernel level). Scan from a genuinely separate source instead:

```bash
# Terminal 1
python main.py

# Terminal 2 — a container gives you a real, separate source IP
docker run -it --rm alpine sh -c "apk add --no-cache nmap iputils && sh"
nmap -sS -p 1-1000 <your-host-lan-ip>
```

This broad/fast scan tends to trigger the flood-rate guard. To exercise the dedicated port-scan tracker specifically, use a lighter, targeted scan instead:

```bash
docker run --rm nicolaka/netshoot nmap -sT -p 1-50 <your-host-lan-ip>
```

Then check `python main.py --label` for `label: port_scan`, `label_source: port_scan_tracker` to confirm the tracker (not the flood guard or LLM) flagged it. To watch it live instead, run `python main.py --dashboard` in a third terminal — the incident should appear in the open-incidents table within a couple of refresh intervals.

### 6. Run the tests

```bash
pytest tests/ -v
```

348 tests covering flow assembly, feature extraction, anomaly/flood/DDoS/port-scan/brute-force detection, the self-labelling pipeline, the LLM analyser, the classifier, the blocker, alerting, incident correlation/risk scoring, MITRE tagging, the REST API (auth included), DB retention, and the TUI dashboard — run on every push via GitHub Actions.

---

## Development phases

| Phase | What it adds | Status |
|-------|-------------|--------|
| 1 — Foundation | Capture + feature extraction + anomaly/flood/DDoS detection | ✅ Complete |
| 2 — Intelligence | Supervised ML + LLM self-labelling + port-scan detection | ✅ Complete |
| 3 — Response | Auto-blocking + GeoIP + alerting | ✅ Complete, real-hardware verified |
| 3.5 — Enterprise Readiness | Incident correlation, risk scoring, MITRE tagging, observability, authenticated REST API, DB retention | ✅ Complete |
| 4 — Dashboard | Terminal UI (done) + native desktop app (planned) | TUI complete, native app not started |
| 5 — Production | Auto-retraining + model versioning + Docker | Not started |

Full task-by-task checklist and verification log in [`PHASES.md`](PHASES.md).

---

## Known issues

- The supervised classifier is currently effectively untrained (~82 diverse current-schema samples, heavy class imbalance) — still the highest-priority gap, since no code fix compensates for too little training data. The bulk-transfer/`ddos` misclassification issue has a code-level fix (`fwd_packet_share`/`ack_ratio` features, plus a canonical-schema-selection fix for a subtler stale-feature-schema bug found afterward) that's pending live re-verification against real traffic. Flood/DoS separability has `iat_cv` as a genuine partial improvement, explicitly not a full fix.
- `ddos_tracker`/`port_scan_tracker` labelled samples are excluded from classifier training by design — their aggregate-pattern feature schema doesn't match the per-flow features the classifier uses.
- The TUI dashboard is read-only in v1 — no resolve/reopen keybindings yet, and no MITRE techniques pane (the API doesn't expose that data as its own endpoint yet). Tracked as a follow-up once the read side has proven itself.
- `docs/phase4_dashboard_architecture.md` is referenced throughout `PHASES.md`'s Phase 4 section but isn't actually present in the repo — flagged there, not yet resolved.

See [`PHASES.md`](PHASES.md) for the full history and current backlog.

---

## Safety

- Never blocks localhost, private ranges, or whitelisted IPs (configurable in `config.yaml`)
- Dry-run mode observes blocking decisions without touching iptables/nftables
- Credentials live only in `.env`, never committed
- Raw packet payloads are never logged — flow-level metadata only
- The incidents API requires a key (`SENTINEL_API_KEY` in `.env`) on every route except `/health` — a deployment has to deliberately opt out of auth, not opt in

Full details and recovery instructions: [`docs/safety.md`](docs/safety.md).

---

## Tech stack

| Layer | Tools |
|-------|-------|
| Capture | Scapy |
| ML (anomaly) | scikit-learn (Isolation Forest) |
| ML (classifier) | scikit-learn (RandomForest) / XGBoost |
| Aggregate detection | Custom sliding-window trackers (DDoS, port scan, brute force) |
| LLM | NVIDIA NIM (default) / Claude API (optional) |
| Blocking | nftables (preferred) / iptables (fallback) |
| GeoIP | ip-api.com / MaxMind GeoLite2 |
| Alerting | SMTP, Slack webhooks, generic webhook |
| Incidents API | FastAPI, static-key auth |
| Terminal dashboard | Textual, httpx (async HTTP client) |
| Native app | Tauri or PySide6 — undecided, Phase 4.2′ |
| Observability | Prometheus metrics, CEF/SIEM export |
| Storage | SQLite, with tiered retention/rotation |
| CI | GitHub Actions |

---

## Author

Built by **Manav** ([@Manav-1200](https://github.com/Manav-1200)) — a self-taught developer building production-grade AI/cybersecurity portfolio projects from scratch.

---

## License

Apache License 2.0 — see [`LICENSE`](LICENSE). Chosen over MIT for its explicit patent grant, which matters more for security tooling than most other open-source code.