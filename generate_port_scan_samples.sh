#!/usr/bin/env bash
#
# generate_port_scan_samples.sh
# ===============================
# Repeatedly starts Sentinel, waits for it to warm up, runs an nmap
# port scan against the host from a Docker container, then stops
# Sentinel cleanly (SIGINT, same as Ctrl+C, so flows are flushed).
#
# Why this is necessary rather than just re-running nmap in a loop
# against one long-running Sentinel process: main.py's
# last_port_scan_verdict_by_source dict only stores ONE
# process_port_scan_attack() call per transition into ATTACK for a
# given source IP. Once a source is already at ATTACK, subsequent
# scans from that SAME source within the same run won't produce new
# stored samples. Restarting Sentinel resets that in-memory dict,
# so each restart + scan cycle produces one fresh, independent
# training sample.
#
# Usage:
#   chmod +x generate_port_scan_samples.sh
#   ./generate_port_scan_samples.sh [num_runs] [target_ip]
#
# Defaults: 10 runs, target 192.168.10.67 (adjust if your host IP
# changes — check with `ip addr show wlo1`).
#
# Must be run from the Sentinel project root (same place you'd
# normally run `python main.py`).

set -euo pipefail

NUM_RUNS="${1:-10}"
TARGET_IP="${2:-192.168.10.67}"

# How long to wait after starting main.py before assuming warm-up
# has cleared and real traffic is flowing. detection.warmup_flows is
# 30 in config.yaml — on a normal desktop this clears within a few
# seconds from background DNS/mDNS/broadcast traffic alone, but we
# pad generously since flakiness here would silently produce fewer
# samples than requested, not an obvious error.
WARMUP_WAIT_SECONDS=8

# How long to let the scan + a bit of buffer run before stopping
# Sentinel. nmap -sT -p 1-50 typically finishes in well under a
# second locally, but we give the flow-assembly and finish/timeout
# logic a little room to actually process and store the result
# before we send SIGINT.
POST_SCAN_WAIT_SECONDS=5

echo "Generating ${NUM_RUNS} independent port_scan training samples against ${TARGET_IP}"
echo "----------------------------------------------------------------------"

for i in $(seq 1 "$NUM_RUNS"); do
    echo
    echo "[run ${i}/${NUM_RUNS}] Starting Sentinel..."

    # Run main.py in the background, redirecting its output to a
    # per-run log file rather than letting rich's live table clobber
    # this script's own stdout.
    LOG_FILE="/tmp/sentinel_portscan_run_${i}.log"
    python main.py > "$LOG_FILE" 2>&1 &
    SENTINEL_PID=$!

    echo "[run ${i}/${NUM_RUNS}] Sentinel PID=${SENTINEL_PID}, waiting ${WARMUP_WAIT_SECONDS}s for warm-up..."
    sleep "$WARMUP_WAIT_SECONDS"

    # Make sure Sentinel is actually still running before we bother
    # scanning — if it crashed on startup (e.g. a config error), fail
    # loudly here rather than silently scanning into nothing.
    if ! kill -0 "$SENTINEL_PID" 2>/dev/null; then
        echo "[run ${i}/${NUM_RUNS}] ERROR: Sentinel process died before scan. Check ${LOG_FILE}:"
        tail -n 30 "$LOG_FILE"
        exit 1
    fi

    echo "[run ${i}/${NUM_RUNS}] Running nmap scan from Docker container..."
    docker run --rm nicolaka/netshoot nmap -sT -p 1-50 "$TARGET_IP" > "/tmp/nmap_run_${i}.log" 2>&1 || {
        echo "[run ${i}/${NUM_RUNS}] WARNING: docker/nmap command failed — check /tmp/nmap_run_${i}.log"
    }

    echo "[run ${i}/${NUM_RUNS}] Scan finished, waiting ${POST_SCAN_WAIT_SECONDS}s for Sentinel to process/store..."
    sleep "$POST_SCAN_WAIT_SECONDS"

    echo "[run ${i}/${NUM_RUNS}] Stopping Sentinel (SIGINT)..."
    kill -INT "$SENTINEL_PID"

    # Wait for it to exit gracefully, but only for a bounded amount
    # of time — SIGINT has been observed to occasionally not produce
    # a clean exit when main.py's output is redirected to a file
    # (suspected Rich Live-display interaction with non-tty stdout,
    # not yet root-caused). Rather than risk another 20-30+ minute
    # hang per run, poll for exit and escalate to SIGKILL if the
    # process is still alive after SIGINT_GRACE_SECONDS.
    SIGINT_GRACE_SECONDS=10
    waited=0
    while kill -0 "$SENTINEL_PID" 2>/dev/null; do
        if [ "$waited" -ge "$SIGINT_GRACE_SECONDS" ]; then
            echo "[run ${i}/${NUM_RUNS}] WARNING: Sentinel did not exit within ${SIGINT_GRACE_SECONDS}s of SIGINT — sending SIGKILL."
            kill -9 "$SENTINEL_PID" 2>/dev/null || true
            break
        fi
        sleep 1
        waited=$((waited + 1))
    done

    # Reap the process so it doesn't linger as a zombie, regardless
    # of whether it exited cleanly or was just SIGKILLed above.
    wait "$SENTINEL_PID" 2>/dev/null || true

    echo "[run ${i}/${NUM_RUNS}] Done. Log: ${LOG_FILE}"
done

echo
echo "----------------------------------------------------------------------"
echo "All ${NUM_RUNS} runs complete. Checking results..."
echo
python main.py --label