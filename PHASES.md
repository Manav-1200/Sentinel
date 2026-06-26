# Sentinel — Project Phases

> **Tagline:** Real-time network threat detection and response.
>
> **Project goal:** Build a production-grade, AI-powered Network Intrusion Detection and Response System (NIDRS) from scratch — no pre-packaged datasets, no inherited code. Every component is designed, built, and owned by you.
>
> **Portfolio value:** This project is structured so each phase is a demonstrable, standalone milestone. Phases 1–3 can each appear as a separate project on your GitHub and CV.
>
> **Repo:** `github.com/Manav-1200/sentinel`
>
> **Stack:** Python 3.11+, Scapy, scikit-learn, XGBoost, SQLite → PostgreSQL, Streamlit → React, Claude API, iptables/nftables, ip-api.com / MaxMind GeoLite2.

---

## Quick reference — phase overview

| Phase | Name | Core deliverable | Portfolio label | Status |
|-------|------|-----------------|-----------------|--------|
| 1 | Foundation | Packet capture + feature extraction + anomaly/flood/DDoS detection (CLI) | Project 1 | ✅ Complete — 43 passing tests |
| 2 | Intelligence | Supervised ML + LLM log analysis + self-labelling pipeline | Project 1 v2 | Not started |
| 3 | Response | Auto-blocking (iptables) + GeoIP + alerting | Project 2 | Not started |
| 4 | Dashboard | Live web dashboard with world map + real-time feed | Project 2 v2 | Not started |
| 5 | Production | Auto-retraining pipeline + model versioning + hardening | Project 3 | Not started |
| 6 | Extras | Ideas to add during development (add freely) | — | Ongoing |

---

## Phase 1 — Foundation

**Goal:** Get packets off the wire, extract meaningful flow features, and flag anomalies in real time using an unsupervised model. No labels required. Runs entirely from the command line.

**Why this order:** You cannot detect attacks without first understanding what normal traffic looks like. Isolation Forest learns that baseline on its own, so the system is useful from day one without any labelled data.

### 1.1 — Project scaffold

- [x] Create GitHub repo: `sentinel`
- [x] **Decision (deviates from original plan):** no Python virtual environment — system Python + pacman-managed packages (Arch-specific), since the end goal is a system-installable CLI/desktop tool, not an isolated dev sandbox. See `requirements.txt` header and `PHASES.md` Phase 6 environment notes for the full reasoning.
- [ ] Create folder structure:
  ```
  project-root/
  ├── capture/          # Packet capture and flow assembly
  ├── features/         # Feature extraction logic
  ├── detection/        # ML models
  ├── response/         # Blocking, alerting
  ├── dashboard/        # Web UI
  ├── pipeline/         # Retraining scripts
  ├── data/
  │   ├── logs/         # Attack and flow logs (SQLite)
  │   └── models/       # Saved model files (.pkl / .joblib)
  ├── tests/            # Unit tests for each module
  ├── config.yaml       # Central config (interface, thresholds, ports)
  ├── main.py           # Entry point — ties everything together
  ├── requirements.txt
  └── README.md
  ```
- [x] Write `config.yaml` with: network interfaces (auto-detect or explicit list), capture window size (default 5s), anomaly threshold, whitelist IPs (localhost, router), log paths
- [x] Set up `requirements.txt` with initial dependencies — note: `scapy` and `pandas`/`numpy` ended up installed via `pacman` instead of `pip` (Arch-specific — pip wheels for these didn't support Python 3.14 yet; pacman builds are precompiled against the system Python/GCC). `pyshark` was dropped (unmaintained, unneeded — Scapy covers capture needs alone).

### 1.2 — Packet capture module (`capture/`) ✅ COMPLETE (verified on real traffic, Arch Linux, dual interface)

- [x] Write `capture/sniffer.py` — live packet capture using Scapy. **Design change from original plan:** rather than one configurable interface, it auto-detects and captures on *all* working interfaces simultaneously (WiFi + Ethernet), with an `interfaces: "auto"` / explicit-list override in `config.yaml`. All interfaces feed one unified flow table.
- [x] Flow assembly via `PacketSniffer` class (replaces the originally-planned standalone `PacketBuffer` class — flow buffering and assembly turned out to be one cohesive responsibility, so they're combined in one class with clear internal methods instead of two separate classes)
- [x] Implement flow assembly: group packets into bidirectional flows identified by the 5-tuple `(src_ip, dst_ip, src_port, dst_port, protocol)` — verified working via `make_flow_key()`, confirmed symmetric regardless of packet direction
- [x] Handle TCP, UDP, and ICMP separately — each parsed for its correct fields (ports for TCP/UDP, no ports for ICMP); other IP protocols (GRE, ESP, etc.) are skipped for now
- [ ] Write `capture/pcap_reader.py` — reads `.pcap` files for offline testing (not yet built — deferred until needed for Phase 1.3 testing or CI)
- [x] Implement graceful shutdown on `Ctrl+C` — flushes all remaining active flows (not just the current window) before exiting, verified working
- [x] Write formal `pytest` unit tests in `tests/` — `tests/test_sniffer.py` (11 tests covering flow key symmetry, bidirectional assembly, TCP FIN/RST closing, UDP/ICMP grouping, flow-limit eviction). Verified passing on real hardware (Arch Linux, Python 3.14.6, pytest 9.1.1).

**Extra hardening added beyond the original plan:**
- [x] `_enforce_flow_limit()` — evicts the oldest flow when `max_active_flows` is hit, protecting against memory exhaustion during a flood-style attack
- [x] Per-interface capture failures (e.g. WiFi disconnects mid-capture) are caught and logged without crashing the other interfaces' threads
- [x] No packet payloads are ever stored — only metadata (size, timing, TCP flags) — per the privacy commitment in `docs/safety.md`

**Verified manually on real hardware (Arch Linux, dual interface — `enp2s0` + `wlo1`):** correctly captured and assembled TCP (with clean FIN/RST close detection), UDP, mDNS, SSDP, and DNS flows from real `ping`/`curl` traffic, including one genuine long-lived 1188-packet HTTPS flow.

### 1.3 — Feature extraction module (`features/`)

- [x] Write `features/extractor.py` — takes a completed flow and computes the following features:

  **Flow-level features (computed per bidirectional flow):**
  - [x] Flow duration (seconds — used seconds instead of microseconds for readability; trivially convertible if microsecond precision is ever needed)
  - [x] Total bytes forward / backward
  - [x] Total packets forward / backward
  - [x] Mean / max / min / std of packet length (forward and backward)
  - [x] Mean / max / min / std of inter-arrival time (IAT) between packets
  - [ ] Forward / backward header length (not yet added as a standalone feature — header size is currently only used internally to derive payload size; can add as explicit features later if the model needs it)
  - [x] Bytes per second, packets per second

  **Flag-based features (TCP only):**
  - [x] Count of SYN, ACK, FIN, RST, PSH, URG flags — note: counted across the whole flow rather than split forward/backward, since for scan/flood detection the *total* SYN ratio matters most; can split by direction later if evaluation shows it's needed
  - [x] SYN flag ratio (SYN count / total TCP packets) — verified: scored 1.0 on a simulated SYN scan vs 0.22 on a normal handshake

  **Port/protocol features:**
  - [x] Source port, destination port (kept as identity fields for logging/blocking — see note below)
  - [x] Protocol number (6=TCP, 17=UDP, 1=ICMP)
  - [x] Is destination a well-known port (< 1024)? (boolean)

  **Payload features:**
  - [x] Average payload size (total payload bytes / total packets)
  - [x] Ratio of packets with zero payload — verified: scored 1.0 on simulated SYN scan (no payload at all) vs 0.0 on normal HTTPS traffic

- [x] Output: a Python dict per flow (chosen over pandas row — zero overhead per call, trivially convertible to a DataFrame/array later only when the ML layer actually needs it)
- [ ] Write `features/normaliser.py` — `StandardScaler` wrapper (deferred to Phase 1.4, since normalisation is tightly coupled with the anomaly detector's training process — makes more sense to build alongside `detection/anomaly.py`)
- [x] Testing: verified via two synthetic flows (normal HTTPS handshake + simulated SYN scan) with hand-checked feature values, AND verified against real live traffic (ICMP ping, DNS, mDNS, SSDP) on real hardware. Formal `pytest` unit tests still deferred to Phase 1.6/5.5 alongside the sniffer tests.

**Design note:** `src_ip`/`dst_ip`/`src_port`/`dst_port` are included in the extracted dict as identity fields, but are explicitly NOT meant to be fed into the model as training features — the model should learn behavioural patterns (timing, ratios, sizes), not memorise specific addresses. This distinction will matter when we build the anomaly detector's input pipeline in 1.4 — identity fields get stripped out right before `.fit()`/`.predict()`, but stay in the dict for logging, alerting, and blocking decisions downstream.

**Verified on real hardware:** hand-checked synthetic test correctly distinguished a normal TCP handshake from a simulated SYN scan across every relevant feature (`syn_ratio`, `zero_payload_ratio`, `iat_std`, `packets_per_second`). Real traffic test (ICMP, UDP/DNS, mDNS, SSDP) produced sensible, hand-verifiable numbers — e.g. a 5-ping ICMP exchange correctly computed as 10 packets, ~4.03s duration, pps matching the ping command's own reported timing.

### 1.4 — Anomaly detection module (`detection/`) ✅ COMPLETE (verified on real attack traffic, real false-positive testing, and 9 passing pytest tests)

- [x] Write `detection/anomaly.py` — wraps `sklearn.ensemble.IsolationForest`
- [x] Implement `AnomalyDetector` class with methods:
  - `predict(x)` — returns a `DetectionResult` (verdict + raw score + original features) — chosen over a bare tuple so downstream code (display, logging) doesn't need to know about score internals
  - `save(path)` / `load(path)` — persists the model with `joblib`, verified with a real save/load round-trip test producing bit-identical scores
- [x] Cold-start strategy: collects `warmup_flows` (default 500, configurable) silently before flagging anything — verified both via pytest and live testing (correctly stayed `WARMING_UP` until exactly the threshold, then trained automatically)
- [x] Configurable contamination parameter in `config.yaml`
- [x] Write unit tests (`tests/test_anomaly.py`, 9 tests): warm-up lifecycle, normal-vs-attack scoring, save/load round-trip, flood-rate guard (see below)

**Design decision — model does NOT keep learning after warm-up:** deliberately fixed after training, not continuously retrained on live traffic, to prevent an attacker slowly "teaching" the model their pattern is normal. Formal retraining is deliberately deferred to Phase 5, with evaluation/versioning/rollback.

**Major real-world finding — constant-feature dilution (discovered and fixed during live testing):**
While verifying detection against a real, captured ICMP flood (2000 pings via `ping -A`, generated from a Docker container to guarantee real network-interface traffic rather than loopback/hairpin paths), the flood scored only weakly anomalous (`-0.0068`) despite being an extreme statistical outlier (z-score >1000 on rate features). Root-caused via direct experimentation: constant/zero-variance features (e.g. all TCP flag counts are 0 on ICMP-only warm-up data) were diluting Isolation Forest's effective sensitivity, since random per-tree feature splits were frequently "wasted" on uninformative columns. **Fix, confirmed via measured before/after evidence:** constant columns are now excluded from the vector before fitting (`MIN_FEATURE_VARIANCE`), and `n_estimators` was increased from sklearn's default of 100 to 500. This roughly doubled score separation in testing, and is documented in detail directly in `detection/anomaly.py`'s docstring and `config.yaml`'s threshold comments.

**Known, documented limitation — flood detection needed a second, explicit mechanism:** even after the fix above, the general-purpose Isolation Forest alone was not reliably catching flood-style traffic (very high, very uniform packet rate) without unacceptable false positives on normal bursty traffic. Rather than over-fit the general model to one attack pattern, a **dedicated, explicit flood-rate guard** (`FLOOD_PACKETS_PER_SECOND_THRESHOLD`, default 1000 pps) was added, running alongside the Isolation Forest — if a flow's rate exceeds this threshold, it's flagged `ATTACK` directly regardless of what the general model says. Verified: correctly flagged a real, captured 4000-packet flood, while NOT false-positiving on a simulated legitimate large file download at 500 pps.

**Verified on real attack traffic (not just synthetic data):**
- Port scan: `nmap -sS` from a Docker container (bridge network, to guarantee real-interface traffic — `127.0.0.1` and same-host-IP scans were found to hairpin and never reach the capture layer at all, a real Linux networking quirk documented for future reference) → correctly flagged `ATTACK` via the Isolation Forest itself.
- Flood: 2000-ping flood from the same Docker setup → correctly flagged `ATTACK` via the explicit rate guard.
- Normal traffic: real DNS/mDNS/SSDP/ICMP/HTTPS browsing traffic → correctly stayed `NORMAL` throughout every test session.

### 1.4b — DDoS detection module (`detection/ddos_tracker.py`) — NOT in original plan, added after recognizing a real architectural gap

**Why this exists:** while testing DoS (single-source flood) detection, it became clear that the per-flow architecture (Isolation Forest + flood-rate guard) can **structurally never detect a DDoS** — many distinct sources, each individually sending a low, unremarkable amount of traffic, only becomes alarming in aggregate. No single flow looks wrong on its own, so no per-flow mechanism, however well-tuned, can catch this pattern.

- [x] Write `detection/ddos_tracker.py` — `GlobalRateTracker` class tracking flow arrivals (NOT individual packets) across ALL sources in a sliding time window
- [x] Two-signal design: total flow rate AND distinct source count, both must exceed threshold together for `ATTACK` — this is what distinguishes a genuine multi-source DDoS from a single busy source (already handled by the per-flow flood guard) or a single organic burst of legitimate traffic
- [x] Wired into `capture/sniffer.py` and `capture/pcap_reader.py` via an optional `on_new_flow` callback hook (keeps the capture layer fully decoupled from detection internals — it has no idea what DDoS detection is, it just calls an optional function once per new flow)
- [x] Wired into `main.py` for both live capture and pcap replay
- [x] CLI display shows a prominent system-wide warning banner (not a per-row indicator, since DDoS is a property of the whole network's current state, not any one flow)
- [x] Write unit tests (`tests/test_ddos_tracker.py`, 7 tests) — the most important test directly proves the core design property: **identical total flow volume (600 flows) produces different verdicts depending on source diversity** (1 source → `SUSPICIOUS`, 30 sources → `ATTACK`)

**Config:** `config.yaml`'s new `ddos:` section — `window_seconds`, `attack_total_flows_threshold`, `attack_distinct_sources_threshold`, and matching `suspicious_*` thresholds.

### 1.5 — CLI output and logging (`main.py`) ✅ COMPLETE (verified end-to-end on real traffic)

- [x] Wire capture → features → detection → display → logging → DDoS check, all in `main.py`, for both live capture (`run_live_capture`) and offline pcap replay (`run_pcap`)
- [x] Use the `rich` library for a live-updating table (`detection/cli_display.py`):
  - Columns: time, protocol, source, destination, packet count, score, verdict
  - Color-coded: green=NORMAL, yellow=SUSPICIOUS, bold red=ATTACK, dim cyan=WARMING_UP
  - **Beyond original plan:** also shows a running summary caption (total flows, per-verdict counts, dropped-packet count if non-zero) and a system-wide DDoS warning banner in the table title when an aggregate attack is detected
- [x] Write flagged flows to `data/logs/detections.log` (JSON lines) via `detection/logger.py` — `SUSPICIOUS`/`ATTACK` logged by default, `NORMAL` optional via `log_normal` flag (logging every normal flow would be enormous, low-value noise)
- [ ] Print a periodic 60-second summary (not yet built — the live caption already shows running totals continuously, which covers most of the same need; a periodic snapshot/digest log is a reasonable Phase 5 addition if needed)

**Major real-world finding — packet capture throughput under load:** initial testing revealed that a fast burst (2000 pings in under a second) resulted in only ~5% of packets actually being captured — traced to kernel-level socket buffer overflow (Scapy's synchronous, single-threaded packet processing couldn't keep up with the burst, so the OS silently dropped packets before Python ever saw them). **Fixed via:** (1) decoupling capture from processing using a bounded queue + dedicated worker thread (`capture/sniffer.py`'s `FlowAssembler`/`PacketSniffer` split), so the capture callback does almost no work and the kernel socket gets drained as fast as possible; (2) increasing both the OS-level (`net.core.rmem_max`/`rmem_default` via `sysctl`) and Scapy-level (`conf.bufsize`) receive buffer sizes. Verified: went from capturing ~5% of a real flood's packets to **100%** (4000/4000, exact match) after the fix. Fully documented in `docs/performance.md`, including the exact sysctl commands needed on a fresh machine.

### 1.6 — Phase 1 wrap-up

- [x] `README.md` already covers install/run instructions, features, and project structure (written during scaffold phase, may benefit from a pass once Phase 1 screenshots/demo exist)
- [ ] Record a short demo (terminal recording showing a real detected attack — we have the real data now, e.g. the Docker-based SYN scan and flood tests; recording is just packaging this for presentation)
- [ ] Tag the repo: `git tag v1.0-anomaly-detection` (do this as part of the first push)
- [ ] Push to GitHub — this is **Portfolio Project 1** — ready now, pending the actual `git push`

**Refactor note (capture/sniffer.py):** core flow-assembly logic was extracted into a shared `FlowAssembler` base class, inherited by both `PacketSniffer` (live capture) and `PcapReader` (offline pcap replay) — added in 1.6 area but documented here since it touches both 1.2 and 1.6. This guarantees live and offline replay can never silently drift apart in how they interpret the same traffic, since they share the exact same code rather than two parallel implementations.

---

## Phase 2 — Intelligence

**Goal:** Add supervised classification (once you have labelled data), an LLM-powered log analyser that reasons about suspicious flows, and a self-labelling pipeline that turns anomaly scores into training labels automatically over time.

**Why this matters:** Moving from unsupervised to supervised learning is a huge step — it demonstrates that you understand the full ML lifecycle, not just running a model.

### 2.1 — Self-labelling pipeline (`pipeline/labeller.py`)

- [ ] Write `pipeline/labeller.py` — reads `detections.log` and auto-labels flows:
  - Anomaly score below threshold → label `BENIGN`
  - Anomaly score above threshold → send to LLM analyser for confirmation (see 2.2)
  - LLM says attack → label with attack type (e.g. `PORTSCAN`, `DOSATTEMPT`, `BRUTEFORCE`)
  - LLM unsure → label `UNKNOWN` (skip for training, review manually)
- [ ] Store labelled flows in SQLite database (`data/logs/flows.db`) with schema:
  ```
  flows table:
    id, timestamp, src_ip, dst_ip, dst_port, protocol,
    anomaly_score, label, label_source (auto/llm/manual),
    all 30+ feature columns
  ```
- [ ] Write a CLI command `python main.py --label` that runs the labelling pass on today's logs

### 2.2 — LLM log analyser (`detection/llm_analyser.py`)

- [ ] Write `detection/llm_analyser.py` — calls Claude API with a structured prompt
- [ ] For each suspicious flow, build a prompt that includes:
  - The raw feature values in human-readable form (e.g. "2000 SYN packets in 3 seconds from 192.168.1.50 to port 22")
  - Ask: is this a known attack pattern? If yes, what type? Confidence level? Why?
- [ ] Parse the response and extract: `attack_type`, `confidence` (high/medium/low), `reasoning` (one sentence)
- [ ] Store the reasoning in the database — this becomes a human-readable audit trail, which is genuinely impressive in a portfolio
- [ ] Rate-limit LLM calls: only call for flows with anomaly score above a higher secondary threshold — don't burn API tokens on borderline cases
- [ ] Write unit tests using mocked API responses

### 2.3 — Supervised classifier (`detection/classifier.py`)

- [ ] Write `detection/classifier.py` — wraps XGBoost and Random Forest (train both, pick the better one per evaluation)
- [ ] Implement `Classifier` class with:
  - `train(X, y)` — trains on labelled flow data from the SQLite database
  - `predict(x)` — returns predicted class label and probability scores for each class
  - `evaluate(X_test, y_test)` — prints confusion matrix, precision, recall, F1 per class
  - `save(path)` / `load(path)` — model persistence
- [ ] Minimum training threshold: only train if the database has at least 1000 labelled samples with at least 3 distinct labels — log a warning and fall back to anomaly detection if below threshold
- [ ] Once trained, run classifier in parallel with the anomaly detector. Final verdict logic:
  - Both agree → high confidence verdict
  - Disagree → flag as SUSPICIOUS, send to LLM analyser
  - Only anomaly detector firing, no classifier yet → use anomaly score only

### 2.4 — Attack simulation for self-generated labels

- [ ] Write `tests/attack_simulator.py` — generates synthetic attack traffic against localhost so you can populate your database with labelled examples fast:
  - Port scan simulation: rapid TCP SYN packets to many ports
  - Brute force simulation: many connection attempts to port 22 (SSH)
  - DoS simulation: high-volume UDP flood to a test port
  - Normal traffic simulation: mixed HTTP/DNS/random port traffic
- [ ] **Safety note in code and README:** these simulations run against localhost only — never point at external IPs

### 2.5 — Phase 2 wrap-up

- [ ] Update `README.md` with the new LLM + classifier features
- [ ] Add a `docs/` folder with a brief write-up of the labelling pipeline and why it's interesting
- [ ] Tag: `git tag v2.0-supervised-learning`
- [ ] Update GitHub repo description and topics (`python`, `machine-learning`, `cybersecurity`, `xgboost`, `network-security`)
- [ ] This is **Portfolio Project 1 — v2** milestone

---

## Phase 3 — Response

**Goal:** When an attack is confirmed, do something about it. Auto-block the attacker's IP, look up their location, and send an alert with all the details.

**Important:** All blocking code must include safety checks — never block localhost, the router gateway, or whitelisted IPs. One wrong iptables rule can lock you out of your own machine.

### 3.1 — IP blocking module (`response/blocker.py`)

- [ ] Write `response/blocker.py` — wraps iptables / nftables via Python `subprocess`
- [ ] Implement `IPBlocker` class with:
  - `block(ip, reason, duration_minutes=60)` — adds a DROP rule for the IP, logs the action
  - `unblock(ip)` — removes the rule manually
  - `auto_expire()` — runs every minute via a background thread, removes rules past their duration
  - `is_blocked(ip)` — checks current iptables rules
  - `list_blocked()` — returns all currently blocked IPs with reason and time remaining
- [ ] Safety checks (raise an exception, never block):
  - `127.0.0.0/8` (loopback)
  - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (private ranges) — configurable: can opt in to blocking LAN IPs
  - Any IP in `config.yaml` whitelist
  - Your own public IP (fetched once on startup from `api.ipify.org`)
- [ ] Dry-run mode (`config.yaml: dry_run: true`) — logs what would be blocked but does not execute `iptables` commands — essential for development and testing
- [ ] Write all block/unblock actions to `data/logs/blocks.log` (JSON lines)

### 3.2 — GeoIP lookup module (`response/geoip.py`)

- [ ] Write `response/geoip.py` — resolves an IP address to physical location and network info
- [ ] Primary method: `ip-api.com` REST API (free, no key, 45 req/min limit)
  - Returns: country, region, city, ISP, org, latitude, longitude, timezone
- [ ] Fallback method: MaxMind GeoLite2 offline database (download once, works offline, GDPR-friendly)
  - Use `geoip2` Python library
- [ ] Cache results in memory (LRU cache, 1000 entries) — don't re-query the same IP twice in a session
- [ ] Persist cache to SQLite so it survives restarts
- [ ] For private/reserved IPs: return `{"country": "Local Network", "city": "—", "lat": null, "lon": null}`

### 3.3 — Alerting module (`response/alerter.py`)

- [ ] Write `response/alerter.py` — sends notifications when an attack is confirmed and blocked
- [ ] Support three alert channels (all configurable in `config.yaml`, any can be disabled):
  - **Email** via SMTP (works with Gmail, Outlook — use app passwords, never hardcode credentials)
  - **Slack** via incoming webhook URL
  - **Webhook** — generic HTTP POST to any URL (useful for Discord, custom dashboards, etc.)
- [ ] Alert payload includes:
  - Timestamp
  - Attack type and confidence
  - Attacker IP address
  - GeoIP: city, country, ISP, coordinates
  - Destination port and protocol
  - Anomaly score and LLM reasoning (one sentence)
  - Action taken (blocked for X minutes / monitoring only)
- [ ] Rate limiting: max 1 alert per unique IP per 10 minutes — prevent alert storms if the same IP keeps probing
- [ ] Test mode: `config.yaml: alert_test: true` — sends a dummy alert on startup to confirm channels work

### 3.4 — Response coordinator (`response/coordinator.py`)

- [ ] Write `response/coordinator.py` — ties blocker + geoip + alerter together with decision logic
- [ ] Decision rules (all configurable thresholds):
  - Anomaly score > 0.8 AND classifier agrees → block + alert
  - Anomaly score 0.6–0.8 → log + alert (no block yet)
  - Anomaly score < 0.6 → log only
  - LLM says HIGH confidence attack → always block regardless of score
- [ ] Repeated offenders: if the same IP triggers 3 suspicion events in 1 hour → escalate to block even if individual scores are below threshold
- [ ] Write unit tests for each decision rule using mocked blocker/alerter

### 3.5 — Phase 3 wrap-up

- [ ] Update `README.md` with blocking and alerting setup instructions
- [ ] Add `docs/safety.md` — explains the IP whitelist, dry-run mode, and how to recover if a rule goes wrong (`iptables -F` to flush all rules)
- [ ] Tag: `git tag v3.0-active-response`
- [ ] This is the foundation of **Portfolio Project 2**

---

## Phase 4 — Dashboard

**Goal:** Replace the CLI table with a live web dashboard. Real-time attack feed, world map showing attacker origins, blocked IP management, model performance metrics — all in one place.

### 4.1 — Backend API (`dashboard/api.py`)

- [ ] Write a lightweight REST API using `FastAPI`:
  - `GET /api/flows/recent` — last 100 detected flows (JSON)
  - `GET /api/flows/attacks` — all confirmed attacks, paginated
  - `GET /api/blocks` — currently blocked IPs with geo data
  - `DELETE /api/blocks/{ip}` — manually unblock an IP
  - `GET /api/stats` — summary: total flows, attacks, blocks, uptime, model accuracy
  - `GET /api/geo/attacks` — all attack source IPs with lat/lon for map display
  - `WebSocket /ws/live` — pushes new detections in real time as they happen
- [ ] All endpoints read from the SQLite database — no direct coupling to the capture pipeline
- [ ] Add basic API key authentication (single key in `config.yaml`) — good security practice and impressive in a portfolio

### 4.2 — Dashboard frontend

- [ ] **Option A (faster):** Streamlit dashboard (`dashboard/streamlit_app.py`) — good for getting something working quickly
- [ ] **Option B (more impressive):** React frontend (`dashboard/frontend/`) — better for the portfolio but takes longer
- [ ] Whichever you choose, implement these panels:

  **Live attack feed panel:**
  - Auto-refreshing table (every 2 seconds via WebSocket or polling)
  - Columns: time, src IP, flag (country emoji), city, attack type, confidence, action taken
  - Colour-coded rows by severity

  **World map panel:**
  - Uses `Leaflet.js` (Streamlit) or `react-leaflet` (React)
  - Each attack origin = a red pin on the map
  - Click a pin → popup with IP, city, ISP, attack count, last seen
  - Heatmap overlay option for high-attack regions

  **Blocked IPs panel:**
  - Table of currently blocked IPs with: IP, country, reason, blocked at, expires at
  - Unblock button per row (calls `DELETE /api/blocks/{ip}`)
  - Manual block input: enter an IP to block manually with reason

  **Stats panel:**
  - Live counters: total flows today, attacks detected, IPs blocked, alerts sent
  - Traffic volume chart (line chart, last 60 minutes, flows/minute)
  - Model confidence histogram (distribution of anomaly scores)
  - Top 10 attacking countries (bar chart)
  - Top 10 targeted ports (bar chart)

  **Model panel:**
  - Current model version, trained at timestamp, training sample count
  - Precision / recall / F1 per attack class (from last evaluation)
  - Confusion matrix heatmap
  - Button to trigger manual retraining

### 4.3 — Phase 4 wrap-up

- [ ] Take clean screenshots of every dashboard panel for the README and CV
- [ ] Record a screen recording of a simulated attack being detected, blocked, and appearing on the map
- [ ] Tag: `git tag v4.0-dashboard`
- [ ] Update GitHub with screenshots in the README — visual projects get far more attention than text-only repos
- [ ] This is **Portfolio Project 2 — v2**

---

## Phase 5 — Production

**Goal:** Make the system robust enough to run unattended for days. Auto-retraining when enough new data arrives, model versioning so you can roll back a bad model, performance optimisation, and security hardening of the system itself.

### 5.1 — Auto-retraining pipeline (`pipeline/trainer.py`)

- [ ] Write `pipeline/trainer.py` — end-to-end retraining script:
  1. Query SQLite for all flows labelled in the last 30 days
  2. Check minimum sample count (configurable, default 2000 samples, 3+ classes)
  3. Split: 80% train, 20% test (stratified by label)
  4. Train XGBoost + Random Forest, evaluate both
  5. Pick the better model by F1-score on the test set
  6. If new model is better than current deployed model → promote it
  7. If worse → keep old model, log the comparison results
- [ ] Write `pipeline/scheduler.py` — runs retraining automatically:
  - Nightly at 2am via `APScheduler`
  - Also triggers if the database accumulates 500 new labelled samples since last training
- [ ] Log every training run to `data/logs/training_history.log`: timestamp, sample count, model type, F1 scores, whether it was promoted

### 5.2 — Model versioning (`data/models/`)

- [ ] Save every trained model with a version filename: `classifier_v{N}_{timestamp}.joblib`
- [ ] Keep a `model_registry.json` that tracks:
  ```json
  {
    "current": "classifier_v7_20250601.joblib",
    "history": [
      {"version": 7, "f1": 0.94, "trained_at": "...", "promoted": true},
      {"version": 6, "f1": 0.91, "trained_at": "...", "promoted": true}
    ]
  }
  ```
- [ ] Implement rollback: `python main.py --rollback` loads the previous model version
- [ ] Keep last 5 versions, delete older ones automatically

### 5.3 — Performance optimisation

- [ ] Profile the capture → feature → detection pipeline using `cProfile` — identify the bottleneck
- [ ] Move feature extraction to a separate process using Python `multiprocessing` — the capture loop should never block on feature computation
- [ ] Use a thread-safe queue between the capture process and the detection process
- [ ] Benchmark: measure flows-per-second throughput. Target: handle at least 10,000 flows/minute on a standard laptop
- [ ] Database optimisation: add SQLite indexes on `timestamp`, `src_ip`, `label` columns — makes dashboard queries fast

### 5.4 — Security hardening

- [ ] Never log raw packet payloads — only flow-level metadata. This is a privacy and legal requirement
- [ ] Store SMTP/Slack/API credentials only in environment variables or a `.env` file — never in `config.yaml` or committed to git. Add `.env` to `.gitignore`
- [ ] Add input validation to all FastAPI endpoints — reject malformed IP addresses, SQL injection attempts
- [ ] Rate limit the FastAPI endpoints (use `slowapi`)
- [ ] Write a `docs/threat-model.md` — what the system protects against, what it does not protect against, known limitations. This document alone impresses senior engineers in interviews

### 5.5 — Testing and CI

- [ ] Achieve at least 70% test coverage across all modules
- [ ] Set up GitHub Actions workflow (`.github/workflows/test.yml`) that runs all tests on every push
- [ ] Add a `Dockerfile` so the system can run in a container — important for deployment to a VPS
- [ ] Write `docs/deployment.md` — step-by-step guide to deploying on a fresh Ubuntu VPS

### 5.6 — Phase 5 wrap-up

- [ ] Final `README.md` polish: architecture diagram (link to this phases doc), badges (Python version, tests passing, license), quick-start in under 5 commands
- [ ] Write a technical blog post (can be a `docs/writeup.md` or published on Medium / Dev.to):
  - Problem: why does real-time NIDS matter?
  - Approach: self-labelling pipeline (this is the novel part)
  - Results: what attack types does it detect? What's the F1 score on your self-collected data?
  - Lessons learned
- [ ] Tag: `git tag v5.0-production`
- [ ] This is **Portfolio Project 3**

---

## Phase 6 — Ideas backlog

> Add ideas here as they come to you during development. Move them into a phase above when you decide to implement them.

- [ ] **Environment notes (for future reference / README "Troubleshooting" section):**
  - Arch + Python 3.14: `pandas`/`numpy` must come from `pacman` (`python-pandas`, `python-numpy`), not `pip` — pip tries to build from source against the newest GCC and fails on Cython's `[[maybe_unused]]` attribute placement. Everything else in `requirements.txt` uses loose `>=` version pins specifically to avoid this same class of failure.
  - Packet capture needs raw socket access. Instead of running everything via `sudo` (which causes a separate root vs. user `pip` package path mismatch), grant the capability directly to the Python binary once: `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python))`. After that, run Sentinel as a normal user, no `sudo` needed.
  - `pip install --break-system-packages` is required and expected on Arch when installing without a venv.
- [ ] **Decoy / honeypot port:** open a port that no real service listens on — any connection to it is automatically flagged as a scan
- [ ] **P2P threat sharing:** share blocked IP lists with other instances of the system (useful if you deploy it on multiple machines)
- [ ] **Browser extension:** show a warning badge when you visit an IP that your system has previously flagged
- [ ] **Mobile push notifications:** send alerts to your phone via Pushover or ntfy.sh (both free)
- [ ] **Packet payload analysis (optional, careful):** for unencrypted protocols, scan payload for known attack signatures (SQL injection strings, shell commands) — clearly document the privacy implications
- [ ] **VPN/Tor detection:** flag flows from known Tor exit nodes or VPN providers (use public IP lists)
- [ ] **Protocol anomaly detection:** flag HTTP requests with unusual methods, oversized headers, or malformed structure
- [ ] **MITRE ATT&CK mapping:** tag each detected attack type with its MITRE ATT&CK technique ID (e.g. T1046 for port scanning) — adds serious credibility to the project
- [ ] **Export report:** generate a PDF summary of the week's attack activity — useful for the portfolio and for showing to a potential employer

---

## Development rules (follow throughout all phases)

- **One feature per branch, one branch per PR.** Keep commit history clean — future employers will look at it.
- **Every module gets a unit test before it's considered done.** No exceptions.
- **All credentials go in `.env`, never in code or config files.**
- **Dry-run mode must always work.** Never require a live network or root access just to run the tests.
- **Comments explain *why*, not *what*.** The code shows what — the comment explains the reasoning.
- **Update this file** as you complete tasks (check the boxes) and as new ideas come in (add to Phase 6).