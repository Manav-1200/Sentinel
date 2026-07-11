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
| 2 | Intelligence | Supervised ML + LLM log analysis + self-labelling pipeline + port-scan detection | Project 1 v2 | ✅ Complete — 99 passing tests, 72%+ coverage (verified end-to-end on real nmap scans, real floods, real DDoS traffic) — tagged `v2.0-supervised-learning` |
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
- [x] Write `capture/pcap_reader.py` — reads `.pcap` files for offline testing, using the exact same flow-assembly rules as live capture (shared `FlowAssembler` base class)
- [x] Implement graceful shutdown on `Ctrl+C` — flushes all remaining active flows (not just the current window) before exiting, verified working in a real terminal. **Known exception — see Phase 2's "Known issues" note:** this clean shutdown does not reliably trigger when stdout is redirected to a non-terminal (e.g. piped to a log file in a script).
- [x] Write formal `pytest` unit tests in `tests/` — `tests/test_sniffer.py` (11 tests covering flow key symmetry, bidirectional assembly, TCP FIN/RST closing, UDP/ICMP grouping, flow-limit eviction). Verified passing on real hardware (Arch Linux, Python 3.14.6, pytest 9.1.1).

**Extra hardening added beyond the original plan:**
- [x] `_enforce_flow_limit()` — evicts the oldest flow when `max_active_flows` is hit, protecting against memory exhaustion during a flood-style attack
- [x] Per-interface capture failures (e.g. WiFi disconnects mid-capture) are caught and logged without crashing the other interfaces' threads
- [x] No packet payloads are ever stored — only metadata (size, timing, TCP flags) — per the privacy commitment in `docs/safety.md`
- [x] **(Added in Phase 2)** A second callback, `on_new_flow_with_port(src_ip, dst_ip, dst_port, timestamp)`, added alongside the original `on_new_flow(src_ip, timestamp)` — same cadence (once per new flow, not per packet), but also passes destination port. This is what `PortScanTracker` (2.1c) needs and `GlobalRateTracker` deliberately doesn't use. Wired through both `capture/sniffer.py` and `capture/pcap_reader.py`.

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
- [x] Testing: verified via two synthetic flows (normal HTTPS handshake + simulated SYN scan) with hand-checked feature values, AND verified against real live traffic (ICMP ping, DNS, mDNS, SSDP) on real hardware.

**Design note:** `src_ip`/`dst_ip`/`src_port`/`dst_port` are included in the extracted dict as identity fields, but are explicitly NOT meant to be fed into the model as training features — the model should learn behavioural patterns (timing, ratios, sizes), not memorise specific addresses. This distinction became directly relevant in Phase 2.3 — see the `TRAINING_LABEL_SOURCES` feature-schema bug below for what happens when a downstream module doesn't respect this boundary consistently.

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

### 1.4b — DDoS detection module (`detection/ddos_tracker.py`) ✅ COMPLETE (NOT in original plan, added after recognizing a real architectural gap — verified via 7 passing pytest tests)

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

- [x] `README.md` already covers install/run instructions, features, and project structure
- [ ] Record a short demo (terminal recording showing a real detected attack)
- [x] Tag the repo: `git tag v1.0-anomaly-detection`
- [x] Push to GitHub — **Portfolio Project 1** — complete

**Refactor note (capture/sniffer.py):** core flow-assembly logic was extracted into a shared `FlowAssembler` base class, inherited by both `PacketSniffer` (live capture) and `PcapReader` (offline pcap replay) — added in 1.6 area but documented here since it touches both 1.2 and 1.6. This guarantees live and offline replay can never silently drift apart in how they interpret the same traffic, since they share the exact same code rather than two parallel implementations.

---

## Phase 2 — Intelligence ✅ COMPLETE — tagged `v2.0-supervised-learning`

**Goal:** Add supervised classification (once you have labelled data), an LLM-powered log analyser that reasons about suspicious flows, a self-labelling pipeline that turns anomaly scores into training labels automatically over time, and dedicated detection for the one attack pattern Phase 1's architecture structurally couldn't see: port scans.

**Why this matters:** Moving from unsupervised to supervised learning is a huge step — it demonstrates that you understand the full ML lifecycle, not just running a model.

### 2.1 — Self-labelling pipeline (`pipeline/labeller.py`) ✅ COMPLETE (verified on real traffic, real attack traffic, and multiple real bugs found + fixed)

- [x] Write `pipeline/labeller.py` — reads live detection results and auto-labels flows:
  - Anomaly score below `llm.min_score_for_analysis` → stored directly, `label_source="auto"`, no LLM call (saves LLM usage for flows that need it most)
  - Anomaly score above threshold, OR detector already said ATTACK → sent to the LLM analyser (see 2.2)
  - LLM confirms a real attack type with high/medium confidence → stored with that label, `label_source="llm"` — **and promotes the stored verdict to ATTACK** if the flow only arrived as SUSPICIOUS (see verdict-conflation fix below)
  - LLM says `benign`/`unknown`, or low confidence → stored as-is, never promotes a verdict
  - LLM call fails for any reason → stored with `label="unknown"`, `label_source="llm_failed"` — never silently dropped
- [x] Store labelled flows in SQLite (`data/logs/sentinel.db`, `labelled_flows` table) — schema includes indexed columns (`src_ip`, `dst_port`, `total_packets`, etc.) plus a full `all_features` JSON column for everything else
- [x] `count_by_label()` / `count_by_label_source()` / `fetch_all()` query helpers for classifier training and manual inspection
- [x] `python main.py --label` prints a read-only summary of accumulated samples (total, by label, by source, with a warning if usable-sample percentage is low)
- [x] Aggregate DDoS detections (see 1.4b) are stored as real training samples too via `Labeller.process_ddos_attack()`, `label_source="ddos_tracker"`, no LLM confirmation needed (already deterministic evidence)

**Real bug found and fixed — LLM never actually called on flood-guard ATTACK flows:**
- Problem: `process()`'s original gate only checked `should_analyse(result.score)` (a pure score threshold).
- Flood-guard-triggered ATTACK verdicts can carry a perfectly ordinary Isolation Forest score (the guard overrides on packet rate, not score) — so these flows silently skipped the LLM entirely and piled up as `label_source="auto"`.
- Fix: the gate now also fires whenever `result.verdict == Verdict.ATTACK`, independent of score.

**Major real-world finding — verdict conflation caused frequent false ATTACK flags on ordinary traffic:**
- Problem: Isolation Forest's raw score was originally allowed to produce `ATTACK` directly (not just `SUSPICIOUS`) once negative enough.
- Because `contamination` forces the model to always flag ~contamination% of flows as outliers *by construction*, completely ordinary traffic (a single DNS lookup, an mDNS broadcast) was regularly labelled `ATTACK` with no actual malicious behaviour behind it — confirmed via repeated live testing.
- This matters beyond cosmetics: in a deployment where verdicts drive alerting or blocking, false ATTACK labels cause real alert fatigue and risk disrupting legitimate traffic.
- Fix: `detection/anomaly.py`'s Isolation Forest path can now only ever produce `SUSPICIOUS` on its own. A stored `ATTACK` verdict requires either the deterministic flood-rate guard, or the LLM independently confirming a real attack pattern (`_REAL_ATTACK_TYPES`, medium+ confidence) — see `pipeline/labeller.py`'s verdict-promotion logic.
- Known gap: this promotion updates what's *stored* for classifier training, but doesn't retroactively repaint the live terminal row already rendered before the LLM responds — see Phase 6 backlog.

**Real bug found and fixed — flood guard itself false-positived on tiny flows:**
- Problem: a 2-packet flow with ~1ms between packets computes `packets_per_second` into the thousands purely from dividing by a near-zero duration, despite being completely ordinary traffic (e.g. a fast request/response pair). Confirmed live: a genuine 2-packet HTTPS flow was flagged `ATTACK` this way.
- Fix: added `FLOOD_MIN_PACKETS` (20) — the flood-rate guard is now only evaluated once a flow has enough packets for a rate calculation to be meaningful.

**Real bug found and fixed — aggregate DDoS detections originally never reached the labelling pipeline at all:**
- Problem: `detection/ddos_tracker.py`'s `GlobalRateTracker` has no single underlying flow to hand to `labeller.process()`. A real, deterministic aggregate ATTACK finding (both flow-rate and distinct-source thresholds crossed together) was previously only ever shown as a display banner, never stored as training data.
- Fix: added `Labeller.process_ddos_attack()`, called from `main.py` on the transition into an aggregate ATTACK verdict — stores it directly with `label="ddos"`, `label_source="ddos_tracker"`, no LLM confirmation needed (the aggregate rule is already deterministic evidence, same philosophy as the flood guard).

### 2.1b — Port-scan tracker (`detection/port_scan_tracker.py`) ✅ COMPLETE (moved out of Phase 6 backlog — real gap identified, closed, and verified against a live nmap scan)

**Why this exists:** confirmed directly during Phase 2 testing (see 2.1's originally-documented gap): a real `nmap -sT` scan produced zero SUSPICIOUS/ATTACK verdicts and zero labelled samples. Per-flow Isolation Forest sees only unremarkable individual short connections; `GlobalRateTracker` tracks distinct *source* IPs (for DDoS), not distinct *destination ports from one source* (a scan's actual signature). This is the mirror-image gap to DDoS — architecturally a sibling to `GlobalRateTracker`, not a tweak to it.

- [x] Write `detection/port_scan_tracker.py` — `PortScanTracker` class, per-source sliding window of `(timestamp, dst_ip, dst_port)` tuples, verdict based on count of *distinct* destination ports touched within the window (`suspicious_distinct_ports_threshold` default 8, `attack_distinct_ports_threshold` default 20, `window_seconds` default 10)
- [x] New `port_scan:` section added to `config.yaml` matching the above thresholds
- [x] `on_new_flow_with_port(src_ip, dst_ip, dst_port, timestamp)` callback added to `FlowAssembler`/`PacketSniffer`/`PcapReader` (additive — existing `on_new_flow` untouched) — see 1.2's update
- [x] `Labeller.process_port_scan_attack()` added, same deterministic-evidence pattern as `process_ddos_attack()` — no LLM confirmation needed, since the distinct-port threshold crossing is itself deterministic evidence
- [x] Wired into `main.py` for both `run_live_capture` and `run_pcap` — per-source verdict tracking via `last_port_scan_verdict_by_source: dict[str, PortScanVerdict]` (a dict, unlike DDoS's single scalar `last_ddos_verdict`, since port-scan verdicts are per source IP, not global), calling `process_port_scan_attack()` only on the transition into `ATTACK` for a given source

**Verified end-to-end against real traffic:** `nmap -sT -p 1-50` run from a Docker container (`nicolaka/netshoot`, default bridge network) against the host's real LAN IP. Confirmed via `python main.py --label`: `label: port_scan`, `label_source: port_scan_tracker` correctly appear. Generated 17 independent samples total via a scripted restart-and-scan loop (`generate_port_scan_samples.sh`) to reach a meaningful count for classifier-gating purposes (though see 2.3's note — these ultimately don't feed the classifier at all).

**Dedicated automated test coverage added (`tests/test_port_scan_tracker.py`, 15 tests):** threshold crossing (both SUSPICIOUS and ATTACK, and the boundary between them), per-source isolation (the core design property — one source's scan must never affect another source's verdict, mirroring `test_ddos_tracker.py`'s equivalent proof for the opposite-shaped DDoS case), distinct-ports vs. distinct-targets as independently meaningful signals, sliding-window eviction on both the write path (`record_new_flow`) and read path (`check`), an unseen/unknown source, and config defaults/fallback when `config.yaml`'s `port_scan:` section is missing entirely. Added specifically to close the 0%-coverage gap this module carried through initial CI runs — see the coverage-threshold incident noted in Phase 6.

**Real bug found and fixed along the way — LLM analyser could hang the entire capture loop indefinitely:**
- Problem: while testing the restart-and-scan loop, `main.py` failed to shut down cleanly (`SIGINT`) after processing a real ATTACK-verdict flow, hanging for 20-30+ minutes before being manually killed. Root-caused to `detection/llm_analyser.py`: passing `timeout=...` to the OpenAI/Anthropic client constructor sets an HTTP-level timeout, but both SDKs also retry failed/timed-out requests by default (`max_retries=2`), silently multiplying one configured timeout into 2-4x that duration — or worse, in edge cases (a stalled proxy, a DNS hang) that neither timeout nor retry logic cleanly resolves.
- Fix, two independent layers: (1) both clients now constructed with `max_retries=0`, so the SDK's own retry/backoff can never multiply the timeout; (2) the actual network call now runs in a worker thread with a hard external deadline enforced from the calling thread (`future.result(timeout=timeout_seconds + 2.0)`) — a genuine backstop that doesn't trust the SDK's own timeout handling at all, guaranteeing the main capture loop can never block longer than `timeout_seconds + 2s`, regardless of what the underlying HTTP client does.
- Verified: re-ran the same live-attack scenario that previously hung — clean `"Shutting down..."` shutdown within seconds after Ctrl+C.

**Known, unresolved issue found during this same testing (see Phase 6 backlog for tracking):** even after the LLM-hang fix above, `SIGINT` sent to a backgrounded `main.py` process (stdout redirected to a file, as in the sample-generation script) still does not reliably produce a clean shutdown — the process has to be force-killed (`SIGKILL`). This did NOT reproduce with a direct, interactive Ctrl+C in a real foreground terminal. Root cause not yet identified (suspected Rich `Live`-display interaction with non-tty stdout). The sample-generation script was hardened with a bounded grace period + `SIGKILL` escalation as a practical workaround, but the underlying shutdown bug itself is still open.

**Automated test coverage added shortly after initial verification:** `PortScanTracker` shipped without dedicated `pytest` coverage initially (tracked as an open gap in Phase 6). This became concrete rather than theoretical once GitHub Actions' CI started failing outright — `Coverage failure: total of 68 is less than fail-under=70` — directly because `port_scan_tracker.py` sat at 0% coverage. `tests/test_port_scan_tracker.py` was added (15 tests, mirroring `test_ddos_tracker.py`'s existing sliding-window/per-source-isolation structure), bringing this module to 98% coverage and total project coverage to 72.33%, clearing the CI gate. `Labeller`'s port-scan/DDoS methods and `LLMAnalyser`'s hard-timeout backstop remain untested by dedicated unit tests — see Phase 6.

### 2.2 — LLM log analyser (`detection/llm_analyser.py`) ✅ COMPLETE (verified on real traffic, real attack traffic, provider outage handled, two real prompt bugs found + fixed, one real hang bug found + fixed)

- [x] Write `detection/llm_analyser.py` — provider-agnostic (`nim` / `anthropic`), single `analyse()` call shape regardless of backend
- [x] For each SUSPICIOUS/ATTACK flow, builds a plain-language prompt from the raw features (packet counts, rates, TCP flags, ports) rather than dumping raw JSON
- [x] Parses response into `attack_type` (fixed vocabulary — `KNOWN_ATTACK_TYPES`), `confidence`, `reasoning`; malformed/unparseable responses become `available=False`, never a fabricated label
- [x] Rate-limited (`_RateLimiter`, sliding 60s window) — protects free-tier quota from being exhausted during a real attack burst
- [x] Every failure mode (timeout, auth error, malformed response, provider outage, hard-backstop timeout) degrades to `AnalysisResult(available=False, ...)` — never crashes the live capture loop

**Real incident — NVIDIA NIM's 70B model hung indefinitely:**
- `meta/llama-3.3-70b-instruct` (the originally configured model) stopped responding entirely — connections established, requests sent, zero bytes ever received back, confirmed via `curl -v` (TLS handshake fine, then nothing, even past a 2m43s manual timeout).
- The smaller `meta/llama-3.1-8b-instruct` responded normally (~40ms) on the same account/key, confirming this was model-specific, not a key/network/account issue.
- Mitigation: switched default `config.yaml` model to the 8B variant to unblock testing; 70B remains available to switch back to once confirmed recovered on NVIDIA's side.
- This is an external provider issue, not a Sentinel bug — documented here for anyone hitting the same thing.

**Major real-world finding #1 — prompt structure biased the LLM toward rubber-stamping the detector's verdict:**
- Problem: the original prompt stated the detector's verdict ("This flow was flagged 'ATTACK'...") as fact, immediately before asking for a classification.
- Confirmed via live testing: this measurably biased the (especially smaller, 8B) model toward confirming whatever the detector said, rather than reasoning independently — ordinary 2-4 packet DNS/mDNS/HTTPS flows were being labelled `port_scan`/`ddos`/`syn_flood` with **high confidence**, purely because the prompt handed the model a pre-formed conclusion to agree with.
- Fix: rewrote `_build_prompt()` to present the detector's verdict *after* the raw features, explicitly framed as an unreliable, purely-statistical signal that "frequently misfires on ordinary traffic" — plus explicit skepticism guidance (a small number of packets to a standard service port is "virtually always benign, regardless of what the detector's verdict says").
- Verified: the same borderline flows that previously came back `port_scan`/`ddos` now correctly come back `benign` with sound, feature-grounded reasoning.

**Major real-world finding #2 — the fix above over-corrected, causing the LLM to under-call genuine, obvious floods:**
- Problem: after the skepticism fix above, a REAL 35,716-packet, ~3,745 pkts/sec, fully one-directional UDP flood (generated deliberately — see 2.4) came back `unknown`, **low confidence**, with reasoning literally stating "the packet rate ... [is] not extreme" — despite being an unambiguous flood by any reasonable numeric standard.
- Root cause: the 8B model had no concrete numeric anchor for what "extreme" means in packets/second, so it was guessing at scale rather than reasoning from a threshold — the same underlying issue as finding #1 (small models need explicit numeric anchors, not just qualitative language), just manifesting in the opposite direction.
- Fix: added an explicit quantitative guidance paragraph to the prompt — sustained traffic over ~500-1000 pps for more than a couple of seconds, especially combined with all-forward/zero-backward traffic, is called out as a strong flood/DoS indicator on its own.
- Verified: re-running the identical flood scenario afterward produced `ATTACK`, `ddos`, **high confidence**, with reasoning correctly citing the specific packet rate and one-directional pattern. This is the first fully-correct, high-confidence non-benign classification produced by the pipeline.

**Real bug found and fixed — SDK auto-retry could silently multiply the configured timeout, causing the pipeline to hang (see full writeup under 2.1b, since it was discovered during port-scan testing):** `max_retries=0` set on both provider clients, plus a hard external timeout backstop (`_run_with_hard_timeout`, a worker thread + `future.result(timeout=...)`) that guarantees `analyse()` can never block the calling thread longer than `timeout_seconds + 2s`, regardless of what the underlying SDK does internally.

### 2.3 — Supervised classifier (`detection/classifier.py`) ✅ COMPLETE (two real bugs found + fixed, verified training end-to-end on real multi-class data)

- [x] Write `detection/classifier.py` — trains both RandomForest and XGBoost on `label_source in TRAINING_LABEL_SOURCES` samples from the labeller's database, picks the winner by macro F1 (not accuracy — see module docstring for why)
- [x] `try_train_classifier()` in `main.py` attempts training once at startup; falls back to anomaly-detector-only behaviour if there isn't enough usable data yet
- [x] `MIN_DISTINCT_CLASSES` and `MIN_SAMPLES_PER_CLASS` gate training with clear, specific error messages rather than a confusing crash or a silently unreliable model
- [x] Formal `evaluate()` output — `EvaluationReport` includes macro F1, full `classification_report`, and confusion matrix per candidate model, both winner and loser kept visible (not thrown away)
- [x] Classifier predictions are strictly additive, never authoritative — `main.py` only asks the classifier for a predicted label on a flow the anomaly detector/rule-based mechanisms already flagged SUSPICIOUS/ATTACK, and the classifier's output is displayed alongside the verdict, never used to promote or demote it. Deliberate design decision (see below), not an oversight.

**Real bug found and fixed — stratified train/test split crashed on small, multi-class sample counts:**
- Problem: a fixed `test_size=0.2` split works fine at scale, but with e.g. 10 usable samples across 3 classes, a 20% test split is only 2 samples — not enough slots for scikit-learn's stratified split to guarantee at least one example of every class in the test set, which raises a hard error (`test_size should be greater or equal to the number of classes`) rather than proceeding unsafely.
- Fix: the test-set size is now computed dynamically — large enough to guarantee at least one test example per class, capped so training still keeps at least one example of every class too. Classes with fewer than `MIN_SAMPLES_PER_CLASS` (2) examples are excluded from training entirely (with a clear message naming which classes and why) rather than attempting a meaningless split.
- Verified: confirmed the exact original crash reproduced cleanly before the fix, and confirmed clean training (no crash, no silent misbehaviour) after it, across several real runs with growing/shifting class counts.

**Real bug found and fixed — `TRAINING_LABEL_SOURCES` included label sources with an incompatible feature schema (found during Phase 2.5 verification, before tagging v2.0):**
- Problem: `ddos_tracker` and `port_scan_tracker` samples (see 2.1/2.1b) store a small SYNTHETIC feature dict describing the aggregate pattern itself (`window_seconds`, `distinct_ports_in_window`, `distinct_sources_in_window`, etc.) — nothing like the ~30 real per-flow features (`syn_ratio`, `packets_per_second`, `iat_mean`, etc.) that every `"llm"`-sourced sample carries, and that `predict()` is always called with from `main.py`'s live pipeline.
- `TRAINING_LABEL_SOURCES` had included `"ddos_tracker"` for some time already (and was, briefly, about to be expanded to also include `"port_scan_tracker"`) without this incompatibility being noticed. `_get_feature_order()` picks its feature schema from whichever sample happens to be first in `fetch_all()`'s unordered result, then indexes every OTHER sample by that same key list — meaning the outcome depends on non-deterministic row order: either a silent, undocumented reduction in effective training data (if the mismatched samples happened to be excluded some other way) or a hard `KeyError` (if they weren't).
- Confirmed via direct diagnostic: with `TRAINING_LABEL_SOURCES = {"llm", "ddos_tracker"}`, `train()` reported `total_samples_used` matching the `llm`-only count almost exactly, despite 19 `ddos_tracker` samples being present and technically eligible — meaning they were being silently excluded from training somehow, not safely incorporated.
- Fix: `TRAINING_LABEL_SOURCES` reverted/restricted to `{"llm"}` only. `ddos_tracker` and `port_scan_tracker` samples remain fully stored in the database for record-keeping, audit, and any FUTURE dedicated aggregate-pattern model — they are simply excluded from feeding THIS classifier, which is trained and queried exclusively on real per-flow features.
- Verified: re-ran the same diagnostic with the fix applied — `TRAINING_LABEL_SOURCES: {'llm'}`, `total_samples_used` matching the llm count exactly, full `pytest` suite (84 tests) still green.

**Verified end-to-end on real, non-simulated multi-class data:** after generating a genuine sustained UDP flood via `tests/attack_simulator.py` (see 2.4) that the LLM correctly classified as `ddos` with high confidence, the classifier successfully trained: `RandomForest (F1=1.000) on 22 labelled samples` (2 `ddos`, 20 `benign`). The F1=1.000 is expected and not yet meaningful as a generalisation metric — it reflects a small, heavily imbalanced dataset that's trivially separable (a sustained ~3,700 pps flood vs. everything else), not genuine model quality. As of the `TRAINING_LABEL_SOURCES` fix above, the classifier now trains on 262 real `llm`-sourced samples (`RandomForest, F1=0.764`) — a more representative, if still modest, number.

**Data quality note:**
- The `labelled_flows` table was wiped clean (`DELETE FROM labelled_flows`, backup kept as `.pre-cleanup-backup`) partway through Phase 2 testing.
- This removed ~1400+ pre-fix rows (mostly `auto`/`unknown`, plus a handful of confidently-wrong `port_scan`/`ddos` labels from before the prompt fix above) that would otherwise have poisoned classifier training data.
- All classifier F1 numbers going forward should be read as "trained on post-fix data only."

### 2.4 — Attack simulation for self-generated labels (`tests/attack_simulator.py`) ✅ COMPLETE (real flood traffic generated and successfully labelled end-to-end)

- [x] Write `tests/attack_simulator.py` — generates real, controlled attack traffic:
  - `--mode flood` — a real UDP flood (single socket, sustained `sendto()` calls, no pipe-buffering distortion) against either `--target localhost` or `--target lan`
  - `--mode normal` — delegates to the existing `warmup_traffic.sh` for benign traffic variety
- [x] **Safety enforced in code, not just documented:** `_validate_target()` refuses to send anything outside `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, or `192.168.0.0/16` — a hard check before any traffic is sent, not just a comment.

**Real, repeated finding — same-host traffic hairpins regardless of which "safe" address is used:**
- The original assumption was that only literal `127.0.0.1` hairpins (per Phase 1's finding). Testing found this is broader: sending flood traffic from Azazel to Azazel's own real LAN IP (`192.168.10.67`) *also* hairpins at the kernel level and never reaches Scapy's capture layer — the kernel recognises "this destination belongs to me" regardless of which of the host's own addresses is used.
- Multiple attempts to work around this from the host itself failed for different reasons before the real fix was found:
  - A pure Python `socket.sendto()` loop from the host → hairpinned (same-host destination).
  - `nc -u` piped through a shell loop from inside the `sentinel-attacker` Docker container → traffic reached the host correctly, but each loop iteration spawned a new `nc` process with a new ephemeral source port, splitting the flood into hundreds of tiny 2-6-packet flows instead of one sustained one — neither the flood guard nor the DDoS tracker could fire on this shape.
  - `seq | nc -u` (single process, piped input) from the same container → `nc` buffers piped input into very few, large datagrams rather than one packet per line, defeating packet-*count*-based detection even though the same socket/source port was used throughout.
- **Actual fix:** a real Python `socket.sendto()` loop, run *inside* the Docker container (a genuinely separate network namespace) rather than on the host, targeting the host's real LAN IP. This produces one sustained flow, one real source port, hundreds of thousands of individual `sendto()` calls at true per-packet granularity — this is what finally produced a flow the flood guard correctly recognised (`ATTACK`, tens of thousands of packets, 3,000+ pkts/sec sustained). This exact finding also directly informed how port-scan testing (2.1b) and the sample-generation script were designed — a Docker container on the bridge network, never the loopback/same-host path.
- `--target localhost` in the script is kept for testing the simulator's own traffic-generation logic in isolation, but is explicitly documented as NOT producing capturable/labellable data — `--target lan`, run from a genuinely separate network namespace (e.g. a Docker container), is the only path that actually reaches Sentinel's capture layer.

**End-to-end result:** the real flood generated this way was correctly flagged `ATTACK` by the flood guard, correctly classified `ddos` with `high` confidence and sound reasoning by the LLM (after the 2.2 prompt fix), correctly stored as a genuine second training class, and successfully used to train the classifier (see 2.3). This proved the full Phase 2 pipeline — detection → LLM labelling → classifier training — working end-to-end on real, non-benign, non-corrected-false-positive data, and the same overall pattern (real traffic from a genuinely separate network namespace) was reused to prove out port-scan detection in 2.1b.

### 2.5 — Phase 2 wrap-up ✅ COMPLETE

- [x] Update `README.md` with the new LLM + classifier + port-scan features, an accurate (not carried-over) test count, and a "Known issues" section
- [x] Add a `docs/` cross-reference note on the classifier/anomaly combination design decision (classifier is label-only, never touches verdicts — see 2.3)
- [x] Fixed `tests/test_labeller.py::test_should_analyse_false_skips_llm_entirely` — this test used `Verdict.ATTACK`, which meant it was actually exercising (and accidentally passing on) the "ATTACK always analyses regardless of should_analyse()" OR-branch rather than testing what its name claimed. Renamed and corrected to use `Verdict.SUSPICIOUS`; added a new, separate test (`test_attack_verdict_always_analysed_even_if_should_analyse_false`) to give the OR-branch its own real, intentional coverage rather than accidental coverage via a mislabelled test.
- [x] Full suite verified green: **84 passed**, 0 failed, after all Phase 2 fixes (port-scan tracker, LLM hang fix, `TRAINING_LABEL_SOURCES` fix, test correction).
- [x] Tag: `git tag v2.0-supervised-learning`
- [ ] Update GitHub repo description and topics (`python`, `machine-learning`, `cybersecurity`, `xgboost`, `network-security`)
- [x] This is **Portfolio Project 1 — v2** milestone

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

- [ ] Achieve at least 70% test coverage across all modules — reached 72.33% shortly after Phase 2's close, once `tests/test_port_scan_tracker.py` (15 tests, mirroring `test_ddos_tracker.py`'s sliding-window/per-source-isolation pattern) was added; this pushed `detection/port_scan_tracker.py` from 0% to 98% and unblocked CI's `--cov-fail-under=70` gate, which had started failing once `port_scan_tracker.py` shipped with no tests. `Labeller`'s port-scan/DDoS methods and `LLMAnalyser`'s hard-timeout backstop are still verified manually/functionally only, not via dedicated automated tests — real, tracked follow-up work, not assumed already done
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

- [ ] **Fix `main.py`'s unreliable clean shutdown when stdout is redirected to a non-terminal:** found during Phase 2.1b's port-scan sample-generation testing. `SIGINT` reliably produces a clean `"Shutting down..."` exit in a real, interactive foreground terminal, but has repeatedly failed to do so when `main.py`'s output is piped to a log file in a script (backgrounded process). Root cause not yet identified — leading suspicion is an interaction between Rich's `Live` display and non-tty stdout, but this hasn't been confirmed. Currently worked around at the script level (bounded grace period + `SIGKILL` escalation in `generate_port_scan_samples.sh`), not fixed at the source. A forced `SIGKILL` means any flow mid-processing at that moment is lost rather than flushed — worth fixing properly before Phase 3 adds auto-blocking, where losing state mid-shutdown has higher stakes.
- [ ] **Live display doesn't reflect LLM-corrected verdicts:** a flow's on-screen ATTACK/SUSPICIOUS verdict is rendered before the LLM's analysis completes, so a later SUSPICIOUS→ATTACK promotion (or ATTACK→benign correction) is only visible in the stored database, not retroactively in the terminal table. Re-rendering or annotating the row after the fact is a reasonable Phase 3-ish polish item.
- [x] ~~**Dedicated automated test coverage for `PortScanTracker`**~~ — DONE: `tests/test_port_scan_tracker.py` added (15 tests: threshold crossing at both boundaries, per-source isolation, distinct-ports-vs-distinct-targets, sliding-window eviction on both the record and check paths, unknown-source handling, config defaults/fallback). Coverage went from 0% to 98% for this module, and total project coverage crossed back over the CI's 70% gate (72.33%) as a direct result — this was the actual, confirmed cause of a real CI failure (`Coverage failure: total of 68 is less than fail-under=70`), not a hypothetical gap.
- [ ] **Dedicated automated test coverage still missing for `Labeller.process_port_scan_attack()`/`process_ddos_attack()` and `LLMAnalyser`'s hard-timeout backstop (`_run_with_hard_timeout`):** both are verified manually/functionally (real nmap scans, a real hung-LLM reproduction and fix) but don't yet have dedicated `pytest` coverage the way `PortScanTracker` now does. Tracked here explicitly rather than left implicit — see Phase 5.5.
- [ ] **A dedicated aggregate-pattern classifier for `ddos_tracker`/`port_scan_tracker` samples:** these are currently excluded from `AttackClassifier` training (see Phase 2.3's `TRAINING_LABEL_SOURCES` fix) because their synthetic, aggregate-level feature schema is fundamentally incompatible with the real per-flow features the main classifier uses. The samples themselves are still stored and are real, deterministic, confidently-labelled data — a small, separate model trained specifically on the aggregate-pattern schema (window size, distinct port/source counts) could be a worthwhile future addition, rather than just leaving this data permanently unused.
- [ ] **Environment notes (for future reference / README "Troubleshooting" section):**
  - Arch + Python 3.14: `pandas`/`numpy` must come from `pacman` (`python-pandas`, `python-numpy`), not `pip` — pip tries to build from source against the newest GCC and fails on Cython's `[[maybe_unused]]` attribute placement. Everything else in `requirements.txt` uses loose `>=` version pins specifically to avoid this same class of failure.
  - Packet capture needs raw socket access. Instead of running everything via `sudo` (which causes a separate root vs. user `pip`/`python` package path mismatch — confirmed directly when `sudo python main.py` failed with `ModuleNotFoundError: No module named 'yaml'` despite the package being installed for the normal user), grant the capability directly to the Python binary once: `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python))`. After that, run Sentinel as a normal user, no `sudo` needed. This capability resets whenever the system package manager updates Python (e.g. `pacman -Syu`) and must be reapplied.
  - `pip install --break-system-packages` is required and expected on Arch when installing without a venv.
  - Docker Alpine containers: use the `dl-4.alpinelinux.org` mirror explicitly in `/etc/apk/repositories` — the default mirror routing is unreliable from some ISPs (confirmed on Manav's connection), causing `apk update`/`apk add` to hang or fail.
  - **Same-host traffic hairpins regardless of address used** — not just `127.0.0.1`. Sending traffic from a machine to its OWN real LAN IP also gets short-circuited by the kernel before reaching Scapy's capture layer. Any attack simulation, including port-scan testing, must originate from a genuinely separate network namespace (a Docker container is sufficient) to be captured at all.
  - When generating high-packet-rate test traffic, use a single persistent socket with real per-packet `sendto()`/`send()` calls in a loop — piping input through `nc` (`seq | nc -u`) buffers into a small number of large datagrams, and spawning a new process per packet (`for i in ...; do nc ...; done`) creates a new ephemeral source port each time, splitting one intended flood into hundreds of tiny separate flows. Neither produces traffic that per-flow or aggregate detectors can correctly recognise.
  - **LLM SDK clients retry by default:** both the OpenAI-compatible (NVIDIA NIM) and Anthropic Python SDKs retry failed/timed-out requests automatically (`max_retries=2` typically) unless told not to. A configured `timeout=` alone does not prevent this from silently multiplying total call duration — pass `max_retries=0` explicitly if a hard, predictable timeout matters (as it does here, since `analyse()` is called synchronously from the main capture loop).
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
- **Every module gets a unit test before it's considered done.** No exceptions. (Phase 2 note: this rule was not fully followed at first for `PortScanTracker`, the labeller's port-scan/DDoS methods, or the LLM analyser's hard-timeout backstop — real functional verification existed, but not dedicated `pytest` coverage. `PortScanTracker`'s gap was closed shortly after — see Phase 6 — once a real CI coverage failure made the gap concrete rather than theoretical. The labeller and LLM-analyser gaps are still open, tracked explicitly rather than silently dropped.)
- **All credentials go in `.env`, never in code or config files.**
- **Dry-run mode must always work.** Never require a live network or root access just to run the tests.
- **Comments explain *why*, not *what*.** The code shows what — the comment explains the reasoning.
- **Update this file** as you complete tasks (check the boxes) and as new ideas come in (add to Phase 6).
- **Verify before trusting a "success" message** — Phase 2's most valuable lesson: a script or function reporting success (e.g. classifier training completing without error) does not by itself confirm it did what was intended. The `TRAINING_LABEL_SOURCES` bug (2.3) trained "successfully" for weeks while silently excluding data it was supposed to include. When a claim matters, check it directly (e.g. via a diagnostic script comparing expected vs. actual sample counts) rather than trusting the absence of an error.