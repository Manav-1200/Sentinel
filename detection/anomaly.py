"""
detection/anomaly.py
======================
Unsupervised anomaly detection using Isolation Forest.

This is the first real "AI" component in the pipeline. Everything
before this (capture, flow assembly, feature extraction) was pure
measurement — this module is what actually looks at the numbers and
decides whether a flow looks normal or suspicious.

How it works (high level):
----------------------------
Isolation Forest works by trying to "isolate" each data point with
random splits. Points that are easy to isolate (few splits needed)
are outliers — anomalies. Points that are hard to isolate (need many
splits, because they're surrounded by similar points) are normal.

This requires NO labelled attack data. It only needs to see enough
normal traffic to learn what "normal" looks like — anything that
doesn't fit that shape gets flagged.

Lifecycle:
-----------
1. WARM-UP: the first `warmup_flows` feature vectors are collected
   silently. No verdicts are given yet — we don't know what "normal"
   looks like until we've seen enough of it.
2. FIT: once warm-up completes, an IsolationForest is trained once on
   the warm-up data and a StandardScaler is fit alongside it.
3. PREDICT: every flow after that gets a verdict (NORMAL / SUSPICIOUS
   / ATTACK) based on its anomaly score against the configured
   thresholds.

Lifecycle:
-----------
1. WARM-UP: the first `warmup_flows` feature vectors are collected
   silently. No verdicts are given yet — we don't know what "normal"
   looks like until we've seen enough of it.
2. FIT: once warm-up completes, an IsolationForest is trained once on
   the warm-up data and a StandardScaler is fit alongside it.
3. PREDICT: every flow after that gets a verdict (NORMAL / SUSPICIOUS
   / ATTACK) based on its anomaly score against the configured
   thresholds.

Design decision — the model does NOT keep learning after warm-up:
--------------------------------------------------------------------
Once trained, this detector's "sense of normal" stays fixed. It is
NOT continuously retrained on live traffic. This is a deliberate
security choice: a detector that keeps adapting automatically could
be slowly poisoned by an attacker who probes persistently and
patiently, training the model to think their attack pattern is
normal. Formal retraining (with evaluation, versioning, and rollback)
is handled separately and deliberately in Phase 5's pipeline.

Design decision — removing constant (zero-variance) features per-fit:
--------------------------------------------------------------------
Real-world testing (Phase 1, June 2026) found that flood-style
attacks (very high packet rate, very uniform low inter-arrival time)
scored as only weakly anomalous despite being extreme outliers in raw
feature terms (z-scores over 1000 on rate-related features). Root
cause, confirmed by direct investigation: many features are constant
(zero variance) for a given protocol during warm-up — e.g. all TCP
flag counts are 0 for a pure-ICMP warm-up period. Isolation Forest
selects features to split on at random per tree; when a large
fraction of features carry no information, many splits get "wasted"
on useless features, lengthening average path lengths for ALL points
(including genuine outliers) and compressing the overall score range.

Fix (confirmed via direct testing, results in docs/performance.md):
constant features (zero variance in the warm-up data) are excluded
from the vector handed to IsolationForest entirely, and n_estimators
is increased from the sklearn default of 100 to 500. Together these
roughly doubled the score separation between normal traffic and a
genuine flood in testing, at an acceptable real-time cost (each
prediction still takes low tens of milliseconds, comfortably within
budget for a multi-second flow window).
"""

from __future__ import annotations

import os
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
# patterns if needed. A flow exceeding this rate is flagged ATTACK
# directly, regardless of what the Isolation Forest says about it.
FLOOD_PACKETS_PER_SECOND_THRESHOLD = 1000.0


class Verdict(str, Enum):
    """Possible outcomes of anomaly detection for a single flow."""
    WARMING_UP = "WARMING_UP"   # Not enough data yet to judge
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    ATTACK = "ATTACK"


class DetectionResult:
    """
    The result of running detection on a single flow's features.
    Bundles the raw score together with the human-readable verdict
    so downstream modules (logging, response) don't need to know
    about threshold values themselves.
    """

    def __init__(self, verdict: Verdict, score: Optional[float], features: dict):
        self.verdict = verdict
        self.score = score          # Raw Isolation Forest score, or None during warm-up
        self.features = features    # The original feature dict (includes identity fields)

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
        """
        self._feature_order = self._get_feature_order(self._warmup_buffer[0])

        X = np.array([
            [flow[key] for key in self._feature_order]
            for flow in self._warmup_buffer
        ])

        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        variances = X_scaled.var(axis=0)
        self._active_column_indices = [
            i for i, v in enumerate(variances) if v > MIN_FEATURE_VARIANCE
        ]
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
        explicit flood-rate guard (see FLOOD_PACKETS_PER_SECOND_THRESHOLD
        and the module docstring for why this exists separately from
        the general-purpose model). If a flow's packet rate exceeds
        that threshold, it is flagged ATTACK directly — the Isolation
        Forest score is still computed and returned for visibility/
        logging, but does not override this explicit rule.
        """
        packets_per_second = features.get("packets_per_second", 0.0)

        X = _vectorise(features, self._feature_order)
        X_scaled = self.scaler.transform(X)
        X_filtered = X_scaled[:, self._active_column_indices]

        # decision_function returns the raw anomaly score: more
        # negative = more anomalous. This is more informative than
        # predict()'s simple -1/1 output, since it lets us apply two
        # separate thresholds (SUSPICIOUS vs ATTACK) instead of just
        # a single binary cutoff.
        score = float(self.model.decision_function(X_filtered)[0])

        if packets_per_second > FLOOD_PACKETS_PER_SECOND_THRESHOLD:
            # Explicit flood guard overrides the general-purpose model
            # — see module docstring for why this exists.
            verdict = Verdict.ATTACK
        elif score < self.attack_threshold:
            verdict = Verdict.ATTACK
        elif score < self.suspicious_threshold:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.NORMAL

        return DetectionResult(verdict, score, features)