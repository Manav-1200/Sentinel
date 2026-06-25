"""
detection/logger.py
=====================
Writes detection results to a JSON-lines log file — one JSON object
per line, easy to parse later (Phase 2's labelling pipeline reads
this same file).

Kept separate from cli_display.py: the terminal display is for a
human watching live; this log is the durable record that the rest
of the pipeline (labelling, training, dashboards) will read from.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from detection.anomaly import DetectionResult, Verdict


class DetectionLogger:
    """
    Appends one JSON line per detection result to a log file.

    By default, only SUSPICIOUS and ATTACK verdicts are logged —
    logging every single NORMAL flow would create a huge amount of
    low-value data very quickly. This is configurable via
    `log_normal` if you want full visibility for debugging.
    """

    def __init__(self, config: dict, log_normal: bool = False):
        self.path: str = config["storage"]["detections_log"]
        self.log_normal: bool = log_normal
        os.makedirs(os.path.dirname(self.path), exist_ok=True)

    def log(self, result: DetectionResult) -> None:
        """
        Append a detection result to the log file, unless it's a
        NORMAL verdict and log_normal is False, or a WARMING_UP
        result (nothing meaningful to log yet).
        """
        if result.verdict == Verdict.WARMING_UP:
            return
        if result.verdict == Verdict.NORMAL and not self.log_normal:
            return

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "verdict": result.verdict.value,
            "score": result.score,
            "features": result.features,
        }

        with open(self.path, "a") as f:
            f.write(json.dumps(entry) + "\n")