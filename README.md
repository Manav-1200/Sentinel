# Sentinel

**Real-time network threat detection and response.**

Sentinel is an AI-powered Network Intrusion Detection and Response System (NIDRS) built from scratch — no pre-packaged datasets, no inherited code. It's being built in phases (see [`PHASES.md`](PHASES.md)); **Phase 1 (capture, feature extraction, and detection) and Phase 2 (supervised classification, LLM self-labelling, and port-scan detection) are both complete and verified against real attack traffic.** Later phases (auto-blocking, GeoIP, alerting, web dashboard) are planned and tracked in the roadmap below.

![Tests](https://github.com/Manav-1200/sentinel/actions/workflows/test.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11+-blue)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)

---

## What makes this different

Most intrusion detection projects train on a pre-labelled dataset (like CIC-IDS2017) and stop there. Sentinel builds its own dataset as it runs, with no pre-existing labels needed to start detecting:

1. An **Isolation Forest** anomaly detector flags suspicious flows on day one with zero labels, learning what "normal" looks like from a short warm-up period on your own network.
2. A dedicated, explicit **flood-rate guard** catches single-source DoS-style floods that the general-purpose model alone doesn't reliably separate from normal bursty traffic (a real limitation discovered and documented during development, not assumed away).
3. A separate, aggregate **DDoS tracker** watches connection patterns across ALL sources at once — the one thing no per-flow detector can ever see, since a real DDoS only becomes visible in aggregate, not within any single flow.
4. A separate, per-source **port-scan tracker** watches how many distinct destination ports a single source touches within a sliding window — the mirror-image gap to DDoS: one source touching many ports looks completely unremarkable flow-by-flow (a single short connection is never unusual on its own), so this pattern is invisible to both the per-flow detector and the DDoS tracker alike.
5. An **LLM analyser** (NVIDIA NIM by default, Anthropic Claude as an optional alternative) reasons over flagged flows and assigns attack-type labels — used only offline, as a bootstrapping/labelling tool, never at runtime. Every LLM-labelled flow becomes a training example.
6. A **supervised classifier** (RandomForest/XGBoost, whichever wins evaluation by macro F1) trains on those accumulated labels and adds a specific attack-type prediction alongside the anomaly detector's verdict — without ever overriding it. The classifier only adds detail to a flow already flagged by a rule-based or statistical mechanism; it deliberately never has the authority to promote or demote a verdict, since it's trained on a comparatively small, still-growing dataset and a wrong "benign" classification suppressing a real detection would be a far worse failure than an unlabelled one.

Auto-blocking and GeoIP-tagged alerts follow in Phase 3.

The result is a system that genuinely improves the longer it runs — and that's fully understood because every part of it was built and debugged from scratch, including discovering and fixing several real production-grade issues (kernel-level packet loss under load, Isolation Forest sensitivity dilution from constant features, LLM prompt bias in both directions, and an SDK-retry-induced hang in the LLM analysis path) documented in detail in `docs/performance.md` and the codebase itself.

---

## Features

**Built and verified (Phase 1 + Phase 2):**
- Live packet capture on every active network interface simultaneously (auto-detected, or explicit list), or offline replay from a `.pcap` file
- Bidirectional flow assembly with ~30 features per flow
- Unsupervised anomaly detection (Isolation Forest) — works from day one with no training data
- Dedicated flood-rate guard for single-source DoS-style attacks
- Aggregate, cross-source DDoS detection (sliding-window rate + distinct-source tracking)
- Per-source port-scan detection (sliding-window distinct-destination-port tracking) — catches scan patterns (e.g. `nmap -sT`) invisible to both the per-flow detector and the DDoS tracker
- Self-labelling pipeline: LLM reasoning (NVIDIA NIM / Anthropic Claude, interchangeable) turns flagged flows into a growing, queryable labelled dataset with zero pre-existing data needed
- Supervised attack classifier (RandomForest vs. XGBoost, best of both by macro F1) trained automatically from accumulated labels, adding attack-type predictions alongside the anomaly detector's verdict
- Live, colour-coded CLI dashboard with a system-wide DDoS warning banner
- JSON-lines detection logging
- Automated tests (`pytest`) covering core Phase 1 modules, run on every push via GitHub Actions — Phase 2 additions (`PortScanTracker`, self-labelling, LLM analyser) are verified manually/functionally so far (see `docs/` for the verification log); dedicated automated test coverage for these is tracked as follow-up work, not yet complete

**Planned (see [`PHASES.md`](PHASES.md) for the full roadmap):**
- Auto-blocking via `iptables` / `nftables` with configurable expiry (Phase 3)
- GeoIP lookup (city, country, ISP, coordinates) for every attacker IP (Phase 3)
- Alerting via email, Slack, or generic webhook (Phase 3)
- Live web dashboard: real-time attack feed, world map, blocked IP table, model stats (Phase 4)
- Auto-retraining pipeline with model versioning and rollback (Phase 5)

---

## Project structure

```
sentinel/
├── capture/        Packet capture and flow assembly
├── features/       Feature extraction (30+ per flow)
├── detection/      Anomaly detector, classifier, port-scan/DDoS trackers, LLM analyser
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

This project deliberately does **not** use a Python virtual environment — see `requirements.txt`'s header comment for why (the end goal is a system-installable CLI/desktop tool). On Arch Linux:

```bash
git clone https://github.com/Manav-1200/sentinel.git
cd sentinel

# System packages first (precompiled, avoids source-build issues on newer Python versions)
sudo pacman -S python-scapy python-pip python-pandas python-numpy

# Then the rest via pip
pip install -r requirements.txt --break-system-packages
```

On other distros/OSes, install `scapy` and `pandas`/`numpy` however your system prefers (pip is fine if your platform doesn't hit the same precompiled-wheel gaps Arch + bleeding-edge Python did during development — see `docs/performance.md` for the full story), then run the `pip install -r requirements.txt` step.

### 2. Allow packet capture without root

Packet capture needs elevated privileges. Rather than running everything with `sudo` (which causes a separate root-vs-user Python package path mismatch), grant the capability directly to your Python binary once:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python))
```

After this, run Sentinel as your normal user — no `sudo` needed. Note this capability resets whenever your system package manager updates Python (e.g. `pacman -Syu`), so you'll need to reapply it after such updates.

### 3. Configure

```bash
cp .env.example .env            # Add your API keys and credentials (LLM provider key needed from Phase 2 onward)
```

Open `config.yaml` and check:
- `capture.interfaces: "auto"` — auto-detects every active interface; override with an explicit list (e.g. `["wlo1", "enp2s0"]`) if you only want specific ones. **If you plan to test against Docker-container-sourced traffic** (see step 6 below), make sure your interface list or `"auto"` setting includes `docker0` — container traffic does not traverse your WiFi/Ethernet interface directly.
- `response.dry_run: true` — keep this on; auto-blocking isn't implemented yet (Phase 3), this flag is forward-looking config
- `llm.provider` — `"nim"` (NVIDIA NIM, free tier, default) or `"anthropic"` (requires prepaid API credit)
- `port_scan.*` — thresholds for the per-source port-scan tracker (window size, distinct-port thresholds for SUSPICIOUS/ATTACK)

### 4. Run

```bash
# Live capture on all detected interfaces
python main.py

# Override interfaces explicitly
python main.py --interface wlo1,enp2s0

# Replay a pcap file (great for testing without live traffic)
python main.py --pcap path/to/capture.pcap

# Check accumulated labelled-sample stats (useful after Phase 2 testing)
python main.py --label
```

### 5. Simulate an attack safely

**Important:** scanning `127.0.0.1` (loopback) or your own machine's IP from itself does **not** reliably reach Sentinel's capture layer — this was confirmed during development (loopback and same-host traffic can bypass the monitored network interfaces entirely, a real Linux networking quirk, not a bug in Sentinel). For a realistic test, scan from a genuinely separate source — another device on your network, or a Docker container on the default bridge network:

```bash
# Terminal 1: run Sentinel
python main.py

# Terminal 2: a container gives you a real, separate source IP
docker run -it --rm alpine sh -c "apk add --no-cache nmap iputils && sh"

# Inside the container, scan your host's real LAN IP (not 127.0.0.1)
nmap -sS -p 1-1000 <your-host-ip>
```

Watch Sentinel's live table — scan traffic should appear and, once warm-up completes, be flagged `ATTACK` (this fast, broad scan tends to trigger the flood-rate guard rather than the dedicated port-scan tracker — see step 6 for testing that specifically).

### 6. Simulate a port scan specifically

To exercise the dedicated per-source port-scan tracker (rather than the flood-rate guard), a lighter, more targeted scan works better:

```bash
# Terminal 1: run Sentinel (make sure docker0 is in your interface list —
# see step 3's config note above)
python main.py

# Terminal 2: a lightweight scan across many ports from a container
docker run --rm nicolaka/netshoot nmap -sT -p 1-50 <your-host-lan-ip>
```

Confirm detection landed by checking the labelled sample database afterward:

```bash
python main.py --label
```

Look for `label: port_scan` and `label_source: port_scan_tracker` in the output — this confirms the port-scan tracker (not the flood guard or LLM) is what flagged it, since port-scan detection is a deterministic, per-source rule requiring no LLM confirmation.

### 7. Run the test suite

```bash
pytest tests/ -v
```

<!-- TODO: update this count after running pytest — it's the actual, current number as of this exact codebase, not carried over from before Phase 2. -->
Automated tests covering flow assembly, feature extraction, anomaly detection, and the DDoS tracker (Phase 1 modules). These run automatically on every push via GitHub Actions. Phase 2 additions (`PortScanTracker`, `Labeller`'s port-scan/DDoS methods, the classifier, and the LLM analyser) have been verified manually against real traffic (see `docs/` for the verification log) but do not yet have dedicated automated test coverage — tracked as follow-up work before Phase 3.

---

## Development phases

This project is built in five phases, each a demonstrable milestone:

| Phase | What it adds |
|-------|-------------|
| 1 — Foundation | Capture + feature extraction + anomaly/flood/DDoS detection (CLI) — ✅ complete |
| 2 — Intelligence | Supervised ML + LLM log analysis + self-labelling + port-scan detection — ✅ complete |
| 3 — Response | Auto-blocking + GeoIP + alerting |
| 4 — Dashboard | Live web UI with world map |
| 5 — Production | Auto-retraining + model versioning + Docker |

See [`PHASES.md`](PHASES.md) for the detailed task checklist.

---

## Known issues

- Under some conditions (observed specifically when `main.py`'s stdout is redirected to a non-terminal, e.g. piped to a log file in a script), `SIGINT` does not reliably produce a clean shutdown — the process has to be force-killed (`SIGKILL`) instead. This means any in-flight flow at the moment of a forced kill is lost rather than flushed. Root cause not yet identified (suspected interaction between Rich's `Live` display and non-tty stdout); a clean interactive Ctrl+C in a real terminal has not shown this issue. Tracked for a fix before Phase 3.
- Phase 2 modules (`PortScanTracker`, the self-labelling additions in `Labeller`, `AttackClassifier`, `LLMAnalyser`) are verified manually/functionally but do not yet have dedicated automated test coverage — see the "Run the test suite" section above.
- `ddos_tracker` and `port_scan_tracker` labelled samples are stored for record-keeping/audit but are deliberately excluded from classifier training (`TRAINING_LABEL_SOURCES = {"llm"}` in `detection/classifier.py`) — their synthetic, aggregate-pattern feature set (window size, distinct port/source counts) doesn't match the ~30 real per-flow features the classifier is trained and queried against. Discovered during Phase 2.5 verification, before tagging v2.0.

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
| Capture | Scapy |
| ML (anomaly) | scikit-learn (Isolation Forest) |
| ML (classifier) | scikit-learn (RandomForest) / XGBoost — best of both by macro F1, complete |
| Aggregate detection | Custom sliding-window rate tracker (DDoS) + per-source distinct-port tracker (port scan) |
| LLM | NVIDIA NIM (default, free tier) / Claude API (Anthropic, optional) — self-labelling pipeline, complete |
| Blocking | iptables / nftables — planned, Phase 3 |
| GeoIP | ip-api.com, MaxMind GeoLite2 — planned, Phase 3 |
| Alerting | SMTP, Slack webhooks — planned, Phase 3 |
| Dashboard | FastAPI, React / Streamlit, Leaflet.js — planned, Phase 4 |
| Storage | SQLite → PostgreSQL — planned, Phase 4/5 |
| CI | GitHub Actions |

---

## Author

Built by **Manav** ([@Manav-1200](https://github.com/Manav-1200)) — a self-taught developer building production-grade AI/cybersecurity portfolio projects from scratch, with no pre-packaged datasets and no inherited code.

---

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) for the full text. Chosen over MIT specifically for its explicit patent grant, which matters more for a security-tooling project than for most other open-source code.