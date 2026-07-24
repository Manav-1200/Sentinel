# Sentinel

**Real-time network threat detection and response.**

Sentinel is an AI-powered Network Intrusion Detection and Response System (NIDRS) built from scratch — no pre-packaged datasets, no inherited code. It's built in phases (see [`PHASES.md`](PHASES.md)); **Phases 1–3 are complete and verified against real attack traffic on real hardware**: detection (anomaly/flood/DDoS/port-scan), ML classification + LLM self-labelling, and auto-blocking + GeoIP + alerting. The web dashboard (Phase 4) is next on the roadmap.

![Tests](https://github.com/Manav-1200/sentinel/actions/workflows/test.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11+-blue)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)

---

## What makes this different

Most intrusion detection projects train on a pre-labelled dataset (like CIC-IDS2017) and stop there. Sentinel builds its own dataset as it runs, with no pre-existing labels needed to start detecting:

1. **Isolation Forest** anomaly detector flags suspicious flows from day one, with zero labels needed.
2. A dedicated **flood-rate guard** catches single-source DoS floods the general model doesn't reliably separate from bursty normal traffic.
3. A **DDoS tracker** watches connection patterns across all sources at once — visible only in aggregate, invisible to any per-flow detector.
4. A **port-scan tracker** watches distinct destination ports per source in a sliding window (vertical + horizontal fan-out) — the mirror-image gap to DDoS.
5. An **LLM analyser** (NVIDIA NIM by default, Claude optional) labels flagged flows offline, turning them into training data.
6. A **supervised classifier** (RandomForest/XGBoost) adds attack-type predictions alongside the anomaly verdict — it never overrides a detection, only adds detail to one.

Auto-blocking (nftables/iptables) and GeoIP-tagged alerting (email/Slack/webhook) are built, wired in, and verified end-to-end on real hardware as of Phase 3.

Along the way this surfaced and fixed several real production-grade issues — kernel-level packet loss under load, Isolation Forest sensitivity dilution, LLM prompt bias, an SDK-retry-induced hang — documented in `docs/performance.md` and the codebase.

---

## Features

**Detection (Phase 1–2):** live multi-interface packet capture (or `.pcap` replay) · ~30 features per flow · unsupervised anomaly detection · flood-rate guard · aggregate DDoS tracker · per-source port-scan tracker · LLM self-labelling pipeline (rate-limit-aware retry queue) · supervised classifier (RandomForest/XGBoost) · live colour-coded CLI with BLOCKED/ALLOWED status · JSON-lines logging.

> The classifier is currently effectively untrained (~82 diverse samples, heavy class imbalance) — the bulk-transfer/`ddos` misclassification issue has a code-level fix pending live verification; flood/DoS separability remains a partial, honestly-labelled improvement, not a full fix. See [Known issues](#known-issues).

**Response (Phase 3 — complete, real-hardware verified):** nftables/iptables auto-blocking with whitelist/private-range safety and dry-run mode (block, expiry, and iptables fallback all verified) · GeoIP lookup (ip-api.com / MaxMind) · email/Slack/webhook alerting (webhook delivery verified live) · full response wiring with pytest coverage.

**Planned:** brute-force/credential-stuffing detector (next up) · live web dashboard (Phase 4) · auto-retraining + model versioning (Phase 5). Full roadmap in [`PHASES.md`](PHASES.md).

---

## Project structure

```
sentinel/
├── capture/        Packet capture and flow assembly
├── features/       Feature extraction (30+ per flow)
├── detection/      Anomaly detector, classifier, port-scan/DDoS trackers, LLM analyser
├── response/       Auto-blocker, GeoIP lookup, alerting
├── dashboard/      FastAPI backend + web frontend (planned)
├── pipeline/       Self-labelling and auto-retraining
├── tests/          Unit tests for every module (153 passing)
├── docs/           Write-ups, safety notes, deployment guide
├── data/
│   ├── logs/       SQLite DB, detection logs, block logs
│   └── models/     Saved model files with versioning
├── config.yaml     All tunable parameters
├── .env.example    Credentials template (never commit .env)
└── main.py         Entry point
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

Check `config.yaml`:
- `capture.interfaces` — `"auto"` or an explicit list; include `docker0` if testing with Docker-sourced traffic
- `response.dry_run` — keep `true` unless you want live nftables/iptables rules applied; `response.block_private_ranges` should be `true` if your LAN is entirely private-range
- `llm.provider` — `"nim"` (free tier, default) or `"anthropic"`
- `port_scan.*` — window size and thresholds for the port-scan tracker

### 4. Run

```bash
python main.py                              # live capture, all interfaces
python main.py --interface wlo1,enp2s0       # explicit interfaces
python main.py --pcap path/to/capture.pcap   # replay a pcap
python main.py --label                       # check labelled-sample stats
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

Then check `python main.py --label` for `label: port_scan`, `label_source: port_scan_tracker` to confirm the tracker (not the flood guard or LLM) flagged it.

### 6. Run the tests

```bash
pytest tests/ -v
```

153 tests covering flow assembly, feature extraction, anomaly detection, the DDoS/port-scan trackers, the self-labelling pipeline, the LLM analyser, the classifier, the blocker, and alerting — run on every push via GitHub Actions.

---

## Development phases

| Phase | What it adds | Status |
|-------|-------------|--------|
| 1 — Foundation | Capture + feature extraction + anomaly/flood/DDoS detection | ✅ Complete |
| 2 — Intelligence | Supervised ML + LLM self-labelling + port-scan detection | ✅ Complete |
| 3 — Response | Auto-blocking + GeoIP + alerting | ✅ Complete, real-hardware verified |
| 4 — Dashboard | Live web UI with world map | Not started |
| 5 — Production | Auto-retraining + model versioning + Docker | Not started |

Full task-by-task checklist and verification log in [`PHASES.md`](PHASES.md).

---

## Known issues

- The supervised classifier is currently effectively untrained (~82 diverse current-schema samples, heavy class imbalance) — still the highest-priority gap, since no code fix compensates for too little training data. The bulk-transfer/`ddos` misclassification issue has a code-level fix (`fwd_packet_share`/`ack_ratio` features, plus a canonical-schema-selection fix for a subtler stale-feature-schema bug found afterward) that's pending live re-verification against real traffic. Flood/DoS separability has `iat_cv` as a genuine partial improvement, explicitly not a full fix.
- `ddos_tracker`/`port_scan_tracker` labelled samples are excluded from classifier training by design — their aggregate-pattern feature schema doesn't match the per-flow features the classifier uses.
- `Labeller`'s port-scan/DDoS methods and `LLMAnalyser`'s timeout backstop are verified functionally against real traffic but lack dedicated unit tests.

See [`PHASES.md`](PHASES.md) for the full history and current backlog.

---

## Safety

- Never blocks localhost, private ranges, or whitelisted IPs (configurable in `config.yaml`)
- Dry-run mode observes blocking decisions without touching iptables/nftables
- Credentials live only in `.env`, never committed
- Raw packet payloads are never logged — flow-level metadata only

Full details and recovery instructions: [`docs/safety.md`](docs/safety.md).

---

## Tech stack

| Layer | Tools |
|-------|-------|
| Capture | Scapy |
| ML (anomaly) | scikit-learn (Isolation Forest) |
| ML (classifier) | scikit-learn (RandomForest) / XGBoost |
| Aggregate detection | Custom sliding-window trackers (DDoS, port scan) |
| LLM | NVIDIA NIM (default) / Claude API (optional) |
| Blocking | nftables (preferred) / iptables (fallback) |
| GeoIP | ip-api.com / MaxMind GeoLite2 |
| Alerting | SMTP, Slack webhooks, generic webhook |
| Dashboard | FastAPI, React/Streamlit, Leaflet.js — planned, Phase 4 |
| Storage | SQLite → PostgreSQL — planned, Phase 4/5 |
| CI | GitHub Actions |

---

## Author

Built by **Manav** ([@Manav-1200](https://github.com/Manav-1200)) — a self-taught developer building production-grade AI/cybersecurity portfolio projects from scratch.

---

## License

Apache License 2.0 — see [`LICENSE`](LICENSE). Chosen over MIT for its explicit patent grant, which matters more for security tooling than most other open-source code.