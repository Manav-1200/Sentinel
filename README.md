# Sentinel

**Real-time network threat detection and response.**

Sentinel is an AI-powered Network Intrusion Detection and Response System (NIDRS) built from scratch — no pre-packaged datasets, no inherited code. It captures live network traffic, extracts flow-level features, detects attacks using a self-trained ML pipeline, auto-blocks attacking IPs via iptables, and presents everything on a live web dashboard.

![Tests](https://github.com/Manav-1200/sentinel/actions/workflows/test.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11+-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## What makes this different

Most intrusion detection projects train on a pre-labelled dataset (like CIC-IDS2017) and stop there. Sentinel builds its own dataset as it runs:

1. An **Isolation Forest** anomaly detector flags suspicious flows on day one with zero labels.
2. A **Claude LLM analyser** reasons over flagged flows and assigns attack type labels.
3. Those labels feed a **supervised XGBoost classifier** that gets more accurate over time.
4. When a classifier is confident enough, it triggers **auto-blocking via iptables** and sends an alert with the attacker's **live GeoIP location**.

The result is a system that genuinely improves the longer it runs — and that you fully understand because you built every part of it.

---

## Features

- Live packet capture on any network interface (or replay from `.pcap`)
- Bidirectional flow assembly with 30+ features per flow
- Unsupervised anomaly detection (works with no training data)
- Self-labelling pipeline using LLM reasoning
- Supervised classification once enough labels are collected
- Auto-blocking via `iptables` / `nftables` with configurable expiry
- GeoIP lookup (city, country, ISP, coordinates) for every attacker IP
- Alerting via email, Slack, or generic webhook
- Live web dashboard: real-time attack feed, world map, blocked IP table, model stats
- Auto-retraining pipeline with model versioning and rollback

---

## Project structure

```
sentinel/
├── capture/        Packet capture and flow assembly
├── features/       Feature extraction (30+ per flow)
├── detection/      Anomaly detector, classifier, LLM analyser
├── response/       Auto-blocker, GeoIP lookup, alerting
├── dashboard/      FastAPI backend + web frontend
├── pipeline/       Self-labelling and auto-retraining
├── tests/          Unit tests for every module
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

### 1. Clone and install

```bash
git clone https://github.com/Manav-1200/sentinel.git
cd sentinel
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env            # Add your API keys and credentials
```

Open `config.yaml` and set:
- `capture.interface` — your network interface (run `ip link show` to find it)
- `response.dry_run: true` — keep this on until you're ready to apply real iptables rules

### 3. Run

```bash
# Live capture (requires root for raw packet access)
sudo python main.py

# Replay a pcap file (no root needed — great for testing)
python main.py --pcap path/to/capture.pcap

# Dry run — logs what would be blocked without touching iptables
python main.py --dry-run
```

### 4. Simulate an attack (safe, localhost only)

```bash
# In a second terminal — port scan against yourself
nmap -sS 127.0.0.1

# Watch Sentinel flag it in the first terminal
```

---

## Development phases

This project is built in five phases, each a demonstrable milestone:

| Phase | What it adds |
|-------|-------------|
| 1 — Foundation | Capture + feature extraction + anomaly detection (CLI) |
| 2 — Intelligence | Supervised ML + LLM log analysis + self-labelling |
| 3 — Response | Auto-blocking + GeoIP + alerting |
| 4 — Dashboard | Live web UI with world map |
| 5 — Production | Auto-retraining + model versioning + Docker |

See [`PHASES.md`](PHASES.md) for the detailed task checklist.

---

## Safety

- **Never blocks** localhost, private ranges, or whitelisted IPs — configurable in `config.yaml`
- **Dry-run mode** lets you observe blocking decisions without touching iptables
- All credentials live in `.env` — never committed to git
- Raw packet payloads are never logged — only flow-level metadata

See [`docs/safety.md`](docs/safety.md) for full details and recovery instructions.

---

## Tech stack

| Layer | Tools |
|-------|-------|
| Capture | Scapy, PyShark |
| ML | scikit-learn (Isolation Forest), XGBoost |
| LLM | Claude API (Anthropic) |
| Blocking | iptables / nftables |
| GeoIP | ip-api.com, MaxMind GeoLite2 |
| Alerting | SMTP, Slack webhooks |
| Dashboard | FastAPI, React / Streamlit, Leaflet.js |
| Storage | SQLite → PostgreSQL |
| CI | GitHub Actions |

---

## License

MIT
