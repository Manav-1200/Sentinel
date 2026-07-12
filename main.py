"""
Sentinel — Real-time Network Threat Detection and Response
==========================================================

Main entry point. Parses CLI arguments and launches the
appropriate mode: live capture, pcap replay, or labelling pass.

Usage:
    sudo python main.py                  # Live capture on interface in config.yaml
    sudo python main.py --interface eth0 # Override the interface
    python main.py --pcap path/to.pcap   # Replay a pcap file (no root needed)
    python main.py --label               # Run the labelling pass on today's logs (Phase 2)
    python main.py --train               # Manually trigger retraining (Phase 5)
    python main.py --rollback            # Roll back to the previous model version (Phase 5)
    python main.py --dry-run             # Override config: enable dry-run mode (no iptables)
"""

import argparse
import sys
import os

import yaml
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel

# Load environment variables from .env (credentials, API keys).
# This must happen before any module that reads os.environ.
load_dotenv()

console = Console()


def load_config(path: str = "config.yaml") -> dict:
    """
    Load and return the YAML config file as a Python dict.
    Raises a clear error if the file is missing or malformed.
    """
    if not os.path.exists(path):
        console.print(f"[red]Error:[/red] Config file not found at '{path}'.")
        console.print("Make sure you are running Sentinel from the project root directory.")
        sys.exit(1)

    with open(path, "r") as f:
        try:
            return yaml.safe_load(f)
        except yaml.YAMLError as e:
            console.print(f"[red]Error:[/red] Could not parse config.yaml:\n{e}")
            sys.exit(1)


def print_banner(config: dict, mode: str) -> None:
    """Print the Sentinel startup banner with current settings."""
    from capture.sniffer import resolve_interfaces

    dry_run = config["response"]["dry_run"]
    interfaces = resolve_interfaces(config["capture"]["interfaces"])
    window = config["capture"]["window_seconds"]

    dry_run_notice = " [yellow](DRY RUN — no blocks will be applied)[/yellow]" if dry_run else ""

    console.print(Panel.fit(
        f"[bold cyan]Sentinel[/bold cyan] — Real-time Network Threat Detection & Response\n"
        f"Mode      : [green]{mode}[/green]{dry_run_notice}\n"
        f"Interfaces: [green]{', '.join(interfaces)}[/green]   "
        f"Window: [green]{window}s[/green]   "
        f"Contamination: [green]{config['detection']['contamination']}[/green]",
        border_style="cyan"
    ))


def try_train_classifier(config: dict):
    """
    Attempt to train the supervised classifier (detection/classifier.py)
    from whatever LLM-labelled samples currently exist in the database.

    Returns a trained AttackClassifier, or None if there isn't enough
    labelled data yet (the caller is expected to fall back to
    anomaly-detector-only behaviour in that case — this is the
    expected, normal state for a while after Sentinel's first run).

    Deliberately called ONCE at startup, not retrained mid-session —
    formal, evaluated, versioned retraining is Phase 5's job. This is
    just "is there enough data to bother training right now."
    """
    from detection.classifier import AttackClassifier
    from pipeline.labeller import Labeller

    labeller = Labeller(config, llm_analyser=None)  # No LLM needed — just reading existing samples
    samples = labeller.fetch_all()

    classifier = AttackClassifier(config)
    try:
        result = classifier.train(samples)
    except ValueError as e:
        console.print(f"[dim]Classifier not trained yet: {e}[/dim]\n")
        return None

    console.print(
        f"[green]Classifier trained:[/green] {result.winning_model_name} "
        f"(F1={result.winning_report.f1_macro:.3f}) on {result.total_samples_used} labelled samples.\n"
    )
    return classifier


def build_response_stack(config: dict):
    """
    Construct the three Phase 3 response components as a single shared
    set of instances, so callers (run_live_capture/run_pcap) get one
    line of setup instead of repeating this wiring twice.

    Returns (geoip, alert_manager, blocker). All three are cheap to
    construct and safe to build even if their respective features are
    fully disabled in config.yaml (e.g. every alerting channel off,
    response.dry_run true) — they simply become no-ops in that case,
    never errors.
    """
    from detection.geoip_lookup import GeoIPLookup
    from response.alerting import AlertManager
    from response.blocker import IPBlocker

    geoip = GeoIPLookup(config)
    alert_manager = AlertManager(config, geoip=geoip)
    blocker = IPBlocker(config)
    return geoip, alert_manager, blocker


def handle_attack_response(alert_manager, blocker, attack_type: str, src_ip: str,
                            reasoning: str = None, extra: dict = None) -> None:
    """
    Single shared call site for "an ATTACK-level verdict was just
    confirmed, from whichever detector" — used identically for
    per-flow ATTACK (flood-guard / LLM-promoted), aggregate DDoS
    ATTACK, and per-source port-scan ATTACK. Keeping this as one
    function (rather than inlining alert+block calls at all three
    transition points) means the alert-then-block ordering and
    exception isolation only need to be gotten right once.

    Alerting is attempted before blocking (not that the order matters
    much — both are independently exception-safe — but conceptually
    "notify" then "act" mirrors how a human analyst would work). A
    failure in either is caught and logged here so a response-stack
    problem (bad SMTP creds, missing nft binary) never interrupts the
    live detection pipeline that called this.
    """
    from response.alerting import AlertEvent

    event = AlertEvent(
        attack_type=attack_type,
        src_ip=src_ip,
        verdict="ATTACK",
        reasoning=reasoning,
        extra=extra or {},
    )

    try:
        alert_manager.send_alert(event)
    except Exception as e:
        console.print(f"[yellow]Warning:[/yellow] alerting failed for {src_ip}: {e}")

    try:
        blocker.block(src_ip, reason=f"{attack_type}: {reasoning or 'no additional detail'}")
    except Exception as e:
        console.print(f"[yellow]Warning:[/yellow] blocking failed for {src_ip}: {e}")


class _NoOpBlocker:
    """
    Passed to handle_attack_response() for the DDoS case, where there
    is deliberately no single IP to block (see the comment at that
    call site). Satisfies the same .block() interface as IPBlocker
    without ever touching the firewall or bookkeeping — a true no-op,
    kept as a tiny singleton so it never needs constructing per-call.
    """
    def block(self, ip: str, reason: str = "") -> None:
        pass


_NoOpBlocker.instance = _NoOpBlocker()


def run_live_capture(config: dict) -> None:
    """
    Start the live packet capture pipeline.

    Imports are deferred here so that --help and --label work
    without needing root or all heavy dependencies installed.
    """
    # These modules are built out in Phase 1.2 onwards.
    # They are imported here (not at the top of the file) so that
    # running `python main.py --label` does not require Scapy.
    from capture.sniffer import PacketSniffer
    from features.extractor import FeatureExtractor
    from detection.anomaly import AnomalyDetector
    from detection.cli_display import LiveDetectionDisplay
    from detection.logger import DetectionLogger
    from detection.ddos_tracker import GlobalRateTracker, DDoSVerdict
    from detection.port_scan_tracker import PortScanTracker, PortScanVerdict
    from detection.llm_analyser import LLMAnalyser
    from pipeline.labeller import Labeller

    print_banner(config, mode="live capture")

    ddos_tracker = GlobalRateTracker(config)
    port_scan_tracker = PortScanTracker(config)
    sniffer = PacketSniffer(
        config,
        on_new_flow=ddos_tracker.record_new_flow,
        on_new_flow_with_port=port_scan_tracker.record_new_flow,
    )
    extractor = FeatureExtractor(config)
    detector = AnomalyDetector(config)
    logger = DetectionLogger(config)
    llm_analyser = LLMAnalyser(config)
    labeller = Labeller(config, llm_analyser=llm_analyser)

    # Phase 3: GeoIP enrichment, alerting, and auto-blocking — one
    # shared stack for the whole pipeline. See build_response_stack().
    geoip, alert_manager, blocker = build_response_stack(config)

    # Attempt to train the supervised classifier from whatever labelled
    # data already exists. classifier will be None if there isn't
    # enough yet — completely normal for a while, the pipeline just
    # falls back to anomaly-detector-only verdicts in that case.
    classifier = try_train_classifier(config)

    console.print(f"[cyan]Warming up:[/cyan] collecting {config['detection']['warmup_flows']} "
                  f"flows before flagging anomalies...\n")

    # The live table takes over the terminal display once it starts.
    # Everything printed above this point (the banner, the warm-up
    # notice) stays visible in the scroll history above the table.
    display = LiveDetectionDisplay(max_rows=20)

    # Tracks whether we've already printed a DDoS warning for the
    # CURRENT elevated period, so we don't spam the console once per
    # flow while an attack is ongoing — only on verdict transitions.
    # Also gates process_ddos_attack() below for the same reason: a
    # single aggregate ATTACK period should produce ONE stored
    # training sample, not one per flow processed while it persists.
    last_ddos_verdict = DDoSVerdict.NORMAL

    # Per-source equivalent for port-scan verdicts. Unlike the DDoS
    # tracker (one global verdict for the whole pipeline),
    # PortScanTracker.check() returns a verdict PER SOURCE IP, so a
    # single scalar isn't enough here — we need to remember the last
    # verdict seen for each source individually, otherwise an ongoing
    # scanner would re-trigger process_port_scan_attack() on every
    # single flow it generates while ATTACK persists, instead of once
    # on the transition into ATTACK.
    last_port_scan_verdict_by_source: dict[str, PortScanVerdict] = {}

    try:
        with display:
            for flow in sniffer.stream_flows():
                features = extractor.extract(flow)
                if features is None:
                    # Flow was too short to extract meaningful features — skip it
                    continue
                result = detector.predict(features)
                display.dropped_packet_count = sniffer.dropped_packet_count

                # If a trained classifier is available AND the anomaly
                # detector already flagged this flow, ask the classifier
                # for a specific attack-type prediction to show alongside
                # the bare verdict. The classifier never overrides the
                # anomaly detector's verdict — it only adds detail on
                # top of an already-flagged flow (see main.py module
                # docstring discussion / PHASES.md for why detection and
                # classification stay as separate, composable layers).
                predicted_label = None
                if classifier is not None and result.verdict.value in ("SUSPICIOUS", "ATTACK"):
                    try:
                        predicted_label, _ = classifier.predict(features)
                    except Exception:
                        # A prediction failure (e.g. a feature the
                        # classifier wasn't trained on) must never
                        # interrupt the live pipeline — just skip
                        # showing a predicted label for this flow.
                        predicted_label = None

                display.add(result, predicted_label=predicted_label)
                logger.log(result)

                # Self-labelling: only acts on SUSPICIOUS/ATTACK verdicts
                # (see pipeline/labeller.py) — calls the LLM analyser
                # (rate-limited, gracefully degrades on failure) and
                # stores the result as a training sample for the
                # future Phase 2 classifier. Runs after display/logging
                # so a slow or failed LLM call never delays what the
                # operator sees on screen.
                labeller.process(result)

                # Phase 3: a per-flow ATTACK verdict here is always
                # either the deterministic flood-guard or an
                # LLM-confirmed promotion from SUSPICIOUS (see
                # pipeline/labeller.py's promotion logic) — in both
                # cases it's confirmed evidence, not a raw anomaly
                # score alone, so it's safe to alert/block on directly.
                if result.verdict.value == "ATTACK":
                    src_ip = features.get("src_ip")
                    if src_ip:
                        handle_attack_response(
                            alert_manager, blocker,
                            attack_type=predicted_label or "anomaly_flood",
                            src_ip=src_ip,
                            reasoning=f"Per-flow ATTACK verdict (score={result.score}).",
                            extra={"dst_ip": features.get("dst_ip"), "dst_port": features.get("dst_port")},
                        )

                # Aggregate, cross-source DDoS check — runs independently
                # of the per-flow verdict above. See detection/ddos_tracker.py
                # for why this needs to be a separate mechanism entirely.
                # A per-flow detector fundamentally cannot see this
                # pattern (many distinct sources, each individually
                # unremarkable) — so, unlike per-flow verdicts, a
                # genuine aggregate ATTACK here is stored directly as
                # its own training sample (no LLM confirmation needed
                # — both of GlobalRateTracker's thresholds already had
                # to be crossed together, which is itself deterministic
                # evidence). Only done on the transition INTO ATTACK,
                # not on every flow processed while it persists.
                ddos_result = ddos_tracker.check(flow.last_seen)
                if ddos_result.verdict != last_ddos_verdict:
                    display.set_ddos_status(ddos_result)
                    if ddos_result.verdict == DDoSVerdict.ATTACK:
                        labeller.process_ddos_attack(ddos_result)
                        # DDoS is many-sources-one-target by definition
                        # (see ddos_tracker.py) — there is no single
                        # attacker IP to block. Alert only; blocking
                        # every distinct source seen in the window
                        # would be both impractical and likely to
                        # sweep up innocent hosts. Operators should
                        # respond to a confirmed DDoS alert with
                        # upstream/ISP-level mitigation, not a
                        # per-source Sentinel block.
                        handle_attack_response(
                            alert_manager, blocker=_NoOpBlocker.instance,
                            attack_type="ddos",
                            src_ip="multiple-sources",
                            reasoning=(
                                f"{ddos_result.total_flows_in_window} flows from "
                                f"{ddos_result.distinct_sources_in_window} distinct sources "
                                f"in {ddos_result.window_seconds:.0f}s."
                            ),
                            extra={
                                "total_flows_in_window": ddos_result.total_flows_in_window,
                                "distinct_sources_in_window": ddos_result.distinct_sources_in_window,
                            },
                        )
                    last_ddos_verdict = ddos_result.verdict

                # Per-source port-scan check — same structural reason as
                # the DDoS check above (a per-flow detector can't see
                # "one source touching many distinct ports"), but keyed
                # per source_ip rather than global. See
                # detection/port_scan_tracker.py for the detection
                # logic. Checked for the source IP of THIS flow, since
                # that's the only source we have fresh information for
                # right now.
                port_scan_result = port_scan_tracker.check(flow.src_ip, flow.last_seen)
                previous_verdict = last_port_scan_verdict_by_source.get(
                    flow.src_ip, PortScanVerdict.NORMAL
                )
                if port_scan_result.verdict != previous_verdict:
                    if port_scan_result.verdict == PortScanVerdict.ATTACK:
                        labeller.process_port_scan_attack(port_scan_result)
                        handle_attack_response(
                            alert_manager, blocker,
                            attack_type="port_scan",
                            src_ip=port_scan_result.src_ip,
                            reasoning=(
                                f"Touched {port_scan_result.distinct_ports_in_window} distinct ports "
                                f"across {port_scan_result.distinct_targets_in_window} targets "
                                f"in {port_scan_result.window_seconds:.0f}s."
                            ),
                            extra={
                                "distinct_ports_in_window": port_scan_result.distinct_ports_in_window,
                                "distinct_targets_in_window": port_scan_result.distinct_targets_in_window,
                            },
                        )
                    last_port_scan_verdict_by_source[flow.src_ip] = port_scan_result.verdict
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutting down...[/yellow] Flushing current window.")
        sniffer.stop()
        blocker.shutdown()
        console.print("[green]Done.[/green] Goodbye.")


def run_pcap(config: dict, pcap_path: str) -> None:
    """Replay a .pcap file through the full pipeline (no live interface needed)."""
    from capture.pcap_reader import PcapReader
    from features.extractor import FeatureExtractor
    from detection.anomaly import AnomalyDetector
    from detection.cli_display import LiveDetectionDisplay
    from detection.logger import DetectionLogger
    from detection.ddos_tracker import GlobalRateTracker, DDoSVerdict
    from detection.port_scan_tracker import PortScanTracker, PortScanVerdict
    from detection.llm_analyser import LLMAnalyser
    from pipeline.labeller import Labeller

    print_banner(config, mode=f"pcap replay — {pcap_path}")

    if not os.path.exists(pcap_path):
        console.print(f"[red]Error:[/red] pcap file not found: '{pcap_path}'")
        sys.exit(1)

    ddos_tracker = GlobalRateTracker(config)
    port_scan_tracker = PortScanTracker(config)
    reader = PcapReader(
        config,
        pcap_path,
        on_new_flow=ddos_tracker.record_new_flow,
        on_new_flow_with_port=port_scan_tracker.record_new_flow,
    )
    extractor = FeatureExtractor(config)
    detector = AnomalyDetector(config)
    logger = DetectionLogger(config)
    llm_analyser = LLMAnalyser(config)
    labeller = Labeller(config, llm_analyser=llm_analyser)
    classifier = try_train_classifier(config)
    display = LiveDetectionDisplay(max_rows=20)

    # Phase 3 response stack — same wiring as run_live_capture. Replay
    # runs through the exact same alert/block logic as live capture,
    # which is deliberate: it's the fastest way to validate config.yaml
    # alerting/blocking settings (including against a captured real
    # attack) without needing a live interface or root/setcap at all.
    geoip, alert_manager, blocker = build_response_stack(config)

    last_ddos_verdict = DDoSVerdict.NORMAL
    last_port_scan_verdict_by_source: dict[str, PortScanVerdict] = {}

    try:
        with display:
            for flow in reader.stream_flows():
                features = extractor.extract(flow)
                if features is None:
                    continue
                result = detector.predict(features)

                predicted_label = None
                if classifier is not None and result.verdict.value in ("SUSPICIOUS", "ATTACK"):
                    try:
                        predicted_label, _ = classifier.predict(features)
                    except Exception:
                        predicted_label = None

                display.add(result, predicted_label=predicted_label)
                logger.log(result)
                labeller.process(result)

                if result.verdict.value == "ATTACK":
                    src_ip = features.get("src_ip")
                    if src_ip:
                        handle_attack_response(
                            alert_manager, blocker,
                            attack_type=predicted_label or "anomaly_flood",
                            src_ip=src_ip,
                            reasoning=f"Per-flow ATTACK verdict (score={result.score}).",
                            extra={"dst_ip": features.get("dst_ip"), "dst_port": features.get("dst_port")},
                        )

                ddos_result = ddos_tracker.check(flow.last_seen)
                if ddos_result.verdict != last_ddos_verdict:
                    display.set_ddos_status(ddos_result)
                    if ddos_result.verdict == DDoSVerdict.ATTACK:
                        labeller.process_ddos_attack(ddos_result)
                        handle_attack_response(
                            alert_manager, blocker=_NoOpBlocker.instance,
                            attack_type="ddos",
                            src_ip="multiple-sources",
                            reasoning=(
                                f"{ddos_result.total_flows_in_window} flows from "
                                f"{ddos_result.distinct_sources_in_window} distinct sources "
                                f"in {ddos_result.window_seconds:.0f}s."
                            ),
                            extra={
                                "total_flows_in_window": ddos_result.total_flows_in_window,
                                "distinct_sources_in_window": ddos_result.distinct_sources_in_window,
                            },
                        )
                    last_ddos_verdict = ddos_result.verdict

                port_scan_result = port_scan_tracker.check(flow.src_ip, flow.last_seen)
                previous_verdict = last_port_scan_verdict_by_source.get(
                    flow.src_ip, PortScanVerdict.NORMAL
                )
                if port_scan_result.verdict != previous_verdict:
                    if port_scan_result.verdict == PortScanVerdict.ATTACK:
                        labeller.process_port_scan_attack(port_scan_result)
                        handle_attack_response(
                            alert_manager, blocker,
                            attack_type="port_scan",
                            src_ip=port_scan_result.src_ip,
                            reasoning=(
                                f"Touched {port_scan_result.distinct_ports_in_window} distinct ports "
                                f"across {port_scan_result.distinct_targets_in_window} targets "
                                f"in {port_scan_result.window_seconds:.0f}s."
                            ),
                            extra={
                                "distinct_ports_in_window": port_scan_result.distinct_ports_in_window,
                                "distinct_targets_in_window": port_scan_result.distinct_targets_in_window,
                            },
                        )
                    last_port_scan_verdict_by_source[flow.src_ip] = port_scan_result.verdict
    finally:
        blocker.shutdown()

    console.print("[green]Pcap replay complete.[/green]")


def run_label(config: dict) -> None:
    """
    Prints a summary of labelled samples accumulated so far in the
    SQLite database — useful for checking progress toward having
    enough training data for the Phase 2 classifier.

    Note: this does NOT run a separate labelling pass over old logs.
    Labelling now happens automatically, live, during normal capture
    (see run_live_capture/run_pcap) — every SUSPICIOUS/ATTACK flow is
    labelled as it's detected, via pipeline/labeller.py. This command
    is just a read-only summary of what's accumulated so far.
    """
    from pipeline.labeller import Labeller

    print_banner(config, mode="label summary")

    labeller = Labeller(config, llm_analyser=None)  # No LLM needed — read-only summary
    counts = labeller.count_by_label()
    source_counts = labeller.count_by_label_source()

    if not counts:
        console.print("[yellow]No labelled samples yet.[/yellow] "
                       "Run live capture or pcap replay to start accumulating labelled data.")
        return

    total = sum(counts.values())
    usable = source_counts.get("llm", 0)

    console.print(f"[cyan]Total stored samples:[/cyan] {total}")
    console.print(
        f"[cyan]Usable for classifier training (label_source='llm'):[/cyan] {usable} "
        f"({usable / total * 100:.1f}% of total)\n"
    )
    console.print(
        "[dim]Note: 'ddos_tracker' and 'port_scan_tracker' samples are stored for record-keeping "
        "and audit purposes, but are NOT used to train the classifier — they carry a small, "
        "synthetic feature set (window size, distinct port/source counts) that doesn't match "
        "the ~30 real per-flow features the classifier is trained and queried on. See "
        "detection/classifier.py's TRAINING_LABEL_SOURCES.[/dim]\n"
    )

    console.print("[bold]By label:[/bold]")
    for label, count in sorted(counts.items(), key=lambda x: -x[1]):
        console.print(f"  {label:<20} {count}")

    console.print()
    console.print("[bold]By label source:[/bold]")
    source_descriptions = {
        "llm": "a real LLM judgment — usable for classifier training",
        "ddos_tracker": "a deterministic aggregate DDoS finding — stored for audit, NOT used for classifier training",
        "port_scan_tracker": "a deterministic port-scan finding — stored for audit, NOT used for classifier training",
        "auto": "score didn't meet llm.min_score_for_analysis — never sent to the LLM",
        "llm_failed": "LLM call attempted but failed (timeout/rate limit/error)",
    }
    for source, count in sorted(source_counts.items(), key=lambda x: -x[1]):
        description = source_descriptions.get(source, "")
        console.print(f"  {source:<18} {count:<8} [dim]{description}[/dim]")

    if usable < total * 0.1:
        console.print(
            "\n[yellow]Note:[/yellow] Less than 10% of stored samples have a real, usable "
            "label. This usually means most flows aren't crossing "
            "llm.min_score_for_analysis — check detection/anomaly.py scoring is "
            "behaving as expected (see the constant-column-filter safety floor added "
            "June 2026), or consider lowering llm.min_score_for_analysis in config.yaml."
        )


def run_train(config: dict) -> None:
    """Phase 5: Manually trigger a retraining run."""
    from pipeline.trainer import Trainer  # noqa: F401  (built in Phase 5)

    print_banner(config, mode="manual retraining")
    console.print("[yellow]Retraining pipeline not yet implemented — coming in Phase 5.[/yellow]")


def run_rollback(config: dict) -> None:
    """Phase 5: Roll back to the previous model version."""
    print_banner(config, mode="model rollback")
    console.print("[yellow]Model rollback not yet implemented — coming in Phase 5.[/yellow]")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel — Real-time network threat detection and response."
    )
    parser.add_argument(
        "--interface", "-i",
        type=str,
        help="Network interface(s) to capture on, comma-separated "
             "(e.g. 'wlo1' or 'wlo1,enp2s0'). Overrides config.yaml. "
             "Use 'auto' to auto-detect all active interfaces."
    )
    parser.add_argument(
        "--pcap",
        type=str,
        metavar="FILE",
        help="Path to a .pcap file to replay instead of live capture."
    )
    parser.add_argument(
        "--label",
        action="store_true",
        help="Run the labelling pass on today's detection logs (Phase 2)."
    )
    parser.add_argument(
        "--train",
        action="store_true",
        help="Manually trigger a model retraining run (Phase 5)."
    )
    parser.add_argument(
        "--rollback",
        action="store_true",
        help="Roll back to the previous model version (Phase 5)."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Enable dry-run mode: log what would be blocked but do not apply iptables rules."
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config.yaml",
        help="Path to the config file (default: config.yaml)."
    )

    args = parser.parse_args()

    # Load config first — everything else depends on it
    config = load_config(args.config)

    # CLI flags override config.yaml values
    if args.dry_run:
        config["response"]["dry_run"] = True

    if args.interface:
        if args.interface.strip().lower() == "auto":
            config["capture"]["interfaces"] = "auto"
        else:
            config["capture"]["interfaces"] = [
                name.strip() for name in args.interface.split(",") if name.strip()
            ]

    # Route to the correct mode
    if args.label:
        run_label(config)
    elif args.train:
        run_train(config)
    elif args.rollback:
        run_rollback(config)
    elif args.pcap:
        run_pcap(config, args.pcap)
    else:
        run_live_capture(config)


if __name__ == "__main__":
    main()