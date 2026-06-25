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

    print_banner(config, mode="live capture")

    ddos_tracker = GlobalRateTracker(config)
    sniffer = PacketSniffer(config, on_new_flow=ddos_tracker.record_new_flow)
    extractor = FeatureExtractor(config)
    detector = AnomalyDetector(config)
    logger = DetectionLogger(config)

    console.print(f"[cyan]Warming up:[/cyan] collecting {config['detection']['warmup_flows']} "
                  f"flows before flagging anomalies...\n")

    # The live table takes over the terminal display once it starts.
    # Everything printed above this point (the banner, the warm-up
    # notice) stays visible in the scroll history above the table.
    display = LiveDetectionDisplay(max_rows=20)

    # Tracks whether we've already printed a DDoS warning for the
    # CURRENT elevated period, so we don't spam the console once per
    # flow while an attack is ongoing — only on verdict transitions.
    last_ddos_verdict = DDoSVerdict.NORMAL

    try:
        with display:
            for flow in sniffer.stream_flows():
                features = extractor.extract(flow)
                if features is None:
                    # Flow was too short to extract meaningful features — skip it
                    continue
                result = detector.predict(features)
                display.dropped_packet_count = sniffer.dropped_packet_count
                display.add(result)
                logger.log(result)

                # Aggregate, cross-source DDoS check — runs independently
                # of the per-flow verdict above. See detection/ddos_tracker.py
                # for why this needs to be a separate mechanism entirely.
                ddos_result = ddos_tracker.check(flow.last_seen)
                if ddos_result.verdict != last_ddos_verdict:
                    display.set_ddos_status(ddos_result)
                    last_ddos_verdict = ddos_result.verdict

    except KeyboardInterrupt:
        console.print("\n[yellow]Shutting down...[/yellow] Flushing current window.")
        sniffer.stop()
        console.print("[green]Done.[/green] Goodbye.")


def run_pcap(config: dict, pcap_path: str) -> None:
    """Replay a .pcap file through the full pipeline (no live interface needed)."""
    from capture.pcap_reader import PcapReader
    from features.extractor import FeatureExtractor
    from detection.anomaly import AnomalyDetector
    from detection.cli_display import LiveDetectionDisplay
    from detection.logger import DetectionLogger
    from detection.ddos_tracker import GlobalRateTracker, DDoSVerdict

    print_banner(config, mode=f"pcap replay — {pcap_path}")

    if not os.path.exists(pcap_path):
        console.print(f"[red]Error:[/red] pcap file not found: '{pcap_path}'")
        sys.exit(1)

    ddos_tracker = GlobalRateTracker(config)
    reader = PcapReader(config, pcap_path, on_new_flow=ddos_tracker.record_new_flow)
    extractor = FeatureExtractor(config)
    detector = AnomalyDetector(config)
    logger = DetectionLogger(config)
    display = LiveDetectionDisplay(max_rows=20)

    last_ddos_verdict = DDoSVerdict.NORMAL

    with display:
        for flow in reader.stream_flows():
            features = extractor.extract(flow)
            if features is None:
                continue
            result = detector.predict(features)
            display.add(result)
            logger.log(result)

            ddos_result = ddos_tracker.check(flow.last_seen)
            if ddos_result.verdict != last_ddos_verdict:
                display.set_ddos_status(ddos_result)
                last_ddos_verdict = ddos_result.verdict

    console.print("[green]Pcap replay complete.[/green]")


def run_label(config: dict) -> None:
    """
    Phase 2: Run the labelling pass on today's detection logs.
    Reads detections.log, calls the LLM analyser on suspicious flows,
    and writes labelled samples to the SQLite database.
    """
    # Imported here — this module does not exist until Phase 2.
    from pipeline.labeller import Labeller  # noqa: F401  (built in Phase 2)
    print_banner(config, mode="labelling pass")
    console.print("[yellow]Labelling pipeline not yet implemented — coming in Phase 2.[/yellow]")


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