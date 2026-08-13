"""
detection/anomaly.py
======================
Unsupervised anomaly detection using Isolation Forest.

Lifecycle: WARM-UP (buffer first `warmup_flows` flows, no verdicts)
-> FIT (train IsolationForest + StandardScaler once) -> PREDICT
(score every flow after that against configured thresholds).

Key design decisions (see docs/performance.md for the incidents/data
behind each):
- Model does NOT retrain on live traffic after warm-up — avoids an
  attacker slowly poisoning "normal" via patient probing. Formal
  retraining is Phase 5's separate, versioned pipeline.
- Constant (zero-variance) warm-up features are dropped before
  fitting, and n_estimators=500 (up from sklearn's default 100).
  Without this, flood traffic scored only weakly anomalous — wasted
  splits on uninformative constant columns compressed the whole score
  range. MIN_SURVIVING_COLUMNS is a fallback floor for when warm-up
  traffic is too uniform for strict filtering to leave enough signal.
- Isolation Forest's score alone can never produce ATTACK, only
  SUSPICIOUS — raw IF scores caused frequent false alarms on ordinary
  traffic (contamination> 0 always flags some fraction as outliers).
  ATTACK only comes from the flood-rate guard below (deterministic)
  or downstream LLM confirmation (pipeline/labeller.py).
  self.attack_threshold is kept for config/schema compatibility and
  as a reference value, but is intentionally not a branch condition.
- Flood-rate guard requires FLOOD_MIN_PACKETS before evaluating rate
  — rate over very few packets is noise (e.g. 2 packets 1ms apart
  computes to ~2000 pkts/sec despite being ordinary traffic).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from typing import Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


# Fields in the feature dict that identify WHO a flow belongs to,
# rather than describing HOW the flow behaves. These must be excluded
# before fitting or predicting — the model should learn behavioural
# patterns (timing, ratios, sizes), not memorise specific addresses.
# Other modules (logging, alerting, blocking) still read these directly
# from the original feature dict — they are never deleted, only
# excluded from the numeric vector handed to the model.
IDENTITY_FIELDS = {"src_ip", "dst_ip", "src_port", "dst_port"}

# Number of trees in the Isolation Forest, increased from sklearn's
# default of 100. Confirmed via direct testing (Phase 1, June 2026,
# see docs/performance.md) that more estimators meaningfully improves
# separation between normal traffic and genuine outliers (floods),
# at an acceptable per-prediction cost (tens of milliseconds, well
# within budget for a multi-second flow window).
N_ESTIMATORS = 500

# Minimum variance (on the scaled, warm-up training data) for a
# feature to be included in the vector handed to IsolationForest.
# Features with variance at or below this threshold are constant (or
# effectively constant) across the warm-up period — e.g. all TCP flag
# counts during an ICMP-only warm-up — and carry no information, only
# diluting the model's effective sensitivity to genuinely informative
# features. See the module docstring for the full explanation and
# evidence behind this fix.
MIN_FEATURE_VARIANCE = 1e-9

# Safety floor for the constant-column filter above: even if MOST
# columns are constant during warm-up (a real, observed failure mode
# — narrow/uniform warm-up traffic, e.g. mostly similar DNS lookups,
# can leave very few or even zero columns with real variance), the
# model must always be trained on at least this many features. Below
# this, _fit_from_warmup_buffer() falls back to keeping the
# highest-variance columns instead of strictly filtering — see that
# method's docstring for the full incident writeup. This number is a
# practical floor, not a precisely-tuned value: low enough to almost
# never trigger with genuinely varied traffic, high enough that the
# model isn't trained on essentially nothing.
MIN_SURVIVING_COLUMNS = 8

# Dedicated, explicit flood-rate guard — runs ALONGSIDE the Isolation
# Forest, not as a replacement for it. The Isolation Forest is a
# general-purpose anomaly detector that, per real testing (see module
# docstring above), only weakly separates flood-style traffic (very
# high packet rate, very uniform timing) from normal traffic noise.
# Rather than over-fit the general model to one specific attack
# pattern, a simple, explicit, easy-to-reason-about rate threshold
# catches floods directly and reliably, while the Isolation Forest
# continues to handle everything else (port scans, unusual port/flag
# combinations, etc.) where it already performs very well.
#
# This value is intentionally generous (well above ordinary bursty
# traffic, e.g. a page load with many parallel connections) to avoid
# false positives — tune based on your own network's real traffic
# patterns if needed. A flow exceeding this rate (AND meeting
# FLOOD_MIN_PACKETS below) is flagged ATTACK directly — this is the
# ONLY deterministic, rule-based path to an ATTACK verdict at the
# detector level (see module docstring's "Isolation Forest alone can
# never produce ATTACK" section).
FLOOD_PACKETS_PER_SECOND_THRESHOLD = 1000.0

# Minimum total packets a flow must have before the flood-rate guard
# above is even evaluated. See the module docstring ("minimum packet
# floor on the flood-rate guard") for the full incident writeup: rate
# = packets / duration is a noisy, near-meaningless measurement for
# very short, low-packet-count flows — e.g. 2 packets arriving ~1ms
# apart computes to ~2000 pkts/sec despite being completely ordinary
# traffic. This floor is deliberately well below any real flood's
# packet count (a genuine flood accumulates far more than this within
# one flow window) while comfortably ruling out the 1-3 packet noise
# case that was confirmed to cause false alarms.
FLOOD_MIN_PACKETS = 20


class Verdict(str, Enum):
    """Possible outcomes of anomaly detection for a single flow."""
    WARMING_UP = "WARMING_UP"   # Not enough data yet to judge
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    ATTACK = "ATTACK"


@dataclass
class DetectionResult:
    """
    The result of running detection on a single flow's features.
    Bundles the raw score together with the human-readable verdict
    so downstream modules (logging, response) don't need to know
    about threshold values themselves.

    Converted to a @dataclass (was a plain __init__-based class) to
    fix a real bug: detection/evidence.py's _serialise() - used to
    JSON-encode Evidence.payload for DB storage - only knows how to
    recurse through @dataclass instances, Enums, dicts, and lists. A
    plain class instance falls through every check in _serialise and
    comes back out unchanged, which then blows up json.dumps() with
    "Object of type DetectionResult is not JSON serializable" - this
    crashed pcap replay (main.py --pcap) on the very first anomaly
    evidence, confirmed on the unmodified repo before this fix. Every
    other detector's result type (DDoSCheckResult,
    PortScanCheckResult, BruteForceResult) was already a dataclass -
    this was the one exception.
    """
    verdict: Verdict
    score: Optional[float]   # Raw Isolation Forest score, or None during warm-up
    features: dict           # The original feature dict (includes identity fields)

    def __repr__(self) -> str:
        score_str = f"{self.score:.4f}" if self.score is not None else "N/A"
        return f"DetectionResult(verdict={self.verdict.value}, score={score_str})"


def _vectorise(features: dict, feature_order: list[str]) -> np.ndarray:
    """
    Convert a feature dict into a numpy array in a fixed, consistent
    column order, excluding identity fields.

    `feature_order` is established once (from the first warm-up batch)
    and reused for every subsequent flow, so the model always sees
    columns in the same order it was trained on.
    """
    return np.array([[features[key] for key in feature_order]])


class AnomalyDetector:
    """
    Wraps IsolationForest + StandardScaler with a warm-up period.

    Usage:
        detector = AnomalyDetector(config)
        for flow_features in stream_of_feature_dicts:
            result = detector.predict(flow_features)
            if result.verdict == Verdict.ATTACK:
                ...
    """

    def __init__(self, config: dict):
        detection_config = config["detection"]

        self.warmup_target: int = int(detection_config["warmup_flows"])
        self.contamination: float = float(detection_config["contamination"])
        self.suspicious_threshold: float = float(detection_config["thresholds"]["suspicious"])
        self.attack_threshold: float = float(detection_config["thresholds"]["attack"])

        # Buffer of feature dicts collected during warm-up. Cleared
        # after fit() runs — we don't need to keep them around once
        # the model has learned from them.
        self._warmup_buffer: list[dict] = []

        # Fixed column order for the numeric feature vector, set once
        # the first time we vectorise data (see _get_feature_order).
        self._feature_order: Optional[list[str]] = None

        # Indices (into _feature_order) of columns that had non-zero
        # variance in the warm-up training data, and are therefore
        # actually used when fitting/predicting. Constant columns are
        # excluded — see MIN_FEATURE_VARIANCE and the module docstring
        # for why this matters. Set once during _fit_from_warmup_buffer,
        # then reused identically for every subsequent predict() call.
        self._active_column_indices: Optional[list[int]] = None

        self.scaler: Optional[StandardScaler] = None
        self.model: Optional[IsolationForest] = None
        self.is_trained: bool = False

    # ------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------

    def predict(self, features: dict) -> DetectionResult:
        """
        Process one flow's feature dict and return a DetectionResult.

        During warm-up, this silently buffers the flow and returns a
        WARMING_UP verdict with no score. Once enough flows have been
        collected, it automatically fits the model on the buffered
        data, then starts returning real verdicts from that point on.
        """
        if not self.is_trained:
            self._warmup_buffer.append(features)

            if len(self._warmup_buffer) < self.warmup_target:
                return DetectionResult(Verdict.WARMING_UP, None, features)

            # Warm-up target reached — fit the model now.
            self._fit_from_warmup_buffer()

        return self._score_flow(features)

    def save(self, path: str) -> None:
        """
        Persist the trained model and scaler to disk so the detector
        doesn't need to re-warm-up after every restart.

        Raises RuntimeError if called before the model is trained —
        there's nothing meaningful to save during warm-up.
        """
        if not self.is_trained:
            raise RuntimeError("Cannot save an untrained AnomalyDetector (still in warm-up).")

        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump({
            "model": self.model,
            "scaler": self.scaler,
            "feature_order": self._feature_order,
            "active_column_indices": self._active_column_indices,
            "contamination": self.contamination,
            "suspicious_threshold": self.suspicious_threshold,
            "attack_threshold": self.attack_threshold,
        }, path)

    def load(self, path: str) -> None:
        """
        Load a previously saved model and scaler from disk, skipping
        the warm-up phase entirely — useful for restarting Sentinel
        without losing the learned baseline.
        """
        bundle = joblib.load(path)
        self.model = bundle["model"]
        self.scaler = bundle["scaler"]
        self._feature_order = bundle["feature_order"]
        # .get() with a fallback, not bundle["..."], so a model file
        # saved before this filtering feature existed can still be
        # loaded — it just won't have any columns filtered (equivalent
        # to using every column, the original pre-fix behaviour).
        self._active_column_indices = bundle.get(
            "active_column_indices", list(range(len(self._feature_order)))
        )
        self.contamination = bundle["contamination"]
        self.suspicious_threshold = bundle["suspicious_threshold"]
        self.attack_threshold = bundle["attack_threshold"]
        self.is_trained = True
        self._warmup_buffer = []

    # ------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------

    def _get_feature_order(self, sample_features: dict) -> list[str]:
        """
        Establish the fixed column order for numeric features, based
        on a sample feature dict. Identity fields are excluded. The
        order is sorted alphabetically purely so it is deterministic
        and reproducible across runs (not dependent on dict insertion
        order, which is an implementation detail we don't want to
        rely on for something this important).
        """
        numeric_keys = [
            key for key in sample_features.keys()
            if key not in IDENTITY_FIELDS
        ]
        return sorted(numeric_keys)

    def _fit_from_warmup_buffer(self) -> None:
        """
        Train the StandardScaler and IsolationForest on the buffered
        warm-up flows. Called exactly once, automatically, the moment
        the warm-up buffer reaches its target size.

        Constant (zero-variance) columns in the warm-up data are
        excluded from the vector before fitting — see
        MIN_FEATURE_VARIANCE and the module docstring for why. The
        StandardScaler is still fit on ALL columns first (so its
        per-column statistics stay correct and reusable), and the
        column filtering is applied as a separate step afterward.

        Safety floor (added after a real incident, June 2026): if
        warm-up traffic happens to be narrow/uniform (e.g. mostly
        similar DNS lookups), strict variance filtering can remove
        MOST or even ALL columns, leaving the model trained on too
        little real signal — or, in the most extreme case, on zero
        columns at all, which crashes outright. If fewer than
        MIN_SURVIVING_COLUMNS pass the strict filter, we fall back to
        keeping the N columns with the HIGHEST variance instead
        (still better than nothing, never zero), and print a visible
        warning — this must never be a silent degradation, the same
        principle applied throughout this project to dropped packets
        and failed LLM calls.
        """
        self._feature_order = self._get_feature_order(self._warmup_buffer[0])

        X = np.array([
            [flow[key] for key in self._feature_order]
            for flow in self._warmup_buffer
        ])

        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        variances = X_scaled.var(axis=0)
        strict_indices = [
            i for i, v in enumerate(variances) if v > MIN_FEATURE_VARIANCE
        ]

        if len(strict_indices) >= MIN_SURVIVING_COLUMNS:
            self._active_column_indices = strict_indices
        else:
            # Fallback: keep the N highest-variance columns instead of
            # strictly thresholding. This is deliberately a LAST
            # RESORT, not the normal path — it means warm-up traffic
            # was unusually narrow and the detector's reliability for
            # this session may be reduced until more varied traffic
            # is seen. Surfaced as a warning, never silent.
            ranked_indices = np.argsort(variances)[::-1]  # highest variance first
            self._active_column_indices = sorted(
                ranked_indices[:MIN_SURVIVING_COLUMNS].tolist()
            )
            print(
                f"[sentinel] WARNING: warm-up traffic was too uniform — only "
                f"{len(strict_indices)} of {len(self._feature_order)} features had "
                f"meaningful variance (need {MIN_SURVIVING_COLUMNS}+). Falling back to "
                f"the {MIN_SURVIVING_COLUMNS} highest-variance features instead of the "
                f"strict filter. Detection reliability may be reduced this session — "
                f"consider running with more varied traffic (see warmup_traffic.sh) "
                f"or a longer warmup_flows setting."
            )

        X_filtered = X_scaled[:, self._active_column_indices]

        self.model = IsolationForest(
            n_estimators=N_ESTIMATORS,
            contamination=self.contamination,
            random_state=42,  # Fixed seed — reproducible behaviour run to run, important for debugging
        )
        self.model.fit(X_filtered)

        self.is_trained = True
        self._warmup_buffer = []  # Free the memory — we don't need these anymore

    def _score_flow(self, features: dict) -> DetectionResult:
        """
        Score a single flow against the already-trained model and
        return the corresponding verdict.

        Before consulting the Isolation Forest, this also checks an
        explicit flood-rate guard (see FLOOD_PACKETS_PER_SECOND_THRESHOLD,
        FLOOD_MIN_PACKETS, and the module docstring for why this exists
        separately from the general-purpose model). If a flow has
        accumulated enough packets (FLOOD_MIN_PACKETS) AND its packet
        rate exceeds FLOOD_PACKETS_PER_SECOND_THRESHOLD, it is flagged
        ATTACK directly — the Isolation Forest score is still computed
        and returned for visibility/logging, but does not override
        this explicit rule. Below FLOOD_MIN_PACKETS, rate is too noisy
        a measurement to trust on its own (see module docstring), so
        the guard is skipped entirely regardless of the computed rate.

        Isolation Forest's own score, no matter how negative, can only
        ever produce SUSPICIOUS here — never ATTACK on its own. See
        the module docstring ("Isolation Forest alone can never
        produce ATTACK") for why: the model is a purely statistical
        outlier detector with no understanding of what the traffic
        actually is, and treating its raw score as equivalent to a
        confirmed attack caused frequent false alarms on ordinary
        traffic. Promotion to a stored ATTACK verdict, when warranted,
        happens downstream in pipeline/labeller.py, only after the LLM
        analyser independently confirms a genuine attack pattern in
        the flow's actual features.
        """
        total_packets = features.get("total_packets", 0)
        packets_per_second = features.get("packets_per_second", 0.0)

        X = _vectorise(features, self._feature_order)
        X_scaled = self.scaler.transform(X)
        X_filtered = X_scaled[:, self._active_column_indices]

        # decision_function returns the raw anomaly score: more
        # negative = more anomalous.
        score = float(self.model.decision_function(X_filtered)[0])

        if (
            total_packets >= FLOOD_MIN_PACKETS
            and packets_per_second > FLOOD_PACKETS_PER_SECOND_THRESHOLD
        ):
            # Explicit flood guard overrides the general-purpose model
            # — see module docstring for why this exists. This is the
            # only rule-based, deterministic path to ATTACK here. The
            # packet-count floor guards against short, low-volume
            # flows where packets/duration is a noisy, meaningless
            # rate (e.g. 2 packets 1ms apart computing to ~2000/sec).
            verdict = Verdict.ATTACK
        elif score < self.suspicious_threshold:
            # attack_threshold is deliberately unused here — IF alone
            # never produces ATTACK (see module docstring).
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.NORMAL

        return DetectionResult(verdict, score, features)