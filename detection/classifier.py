"""
detection/classifier.py
==========================
Supervised attack classifier — trained on the labelled samples that
pipeline/labeller.py has accumulated (specifically, samples where an
LLM gave a real, confident judgment — see TRAINING_LABEL_SOURCES).

This is deliberately separate from detection/anomaly.py. The anomaly
detector (Isolation Forest) answers "does this look unusual?" with
zero labelled data needed — it's what makes Sentinel useful from day
one. This classifier answers a different, harder question: "given
flows we've previously had an LLM judge, what specific attack type
does this new flow most resemble?" It needs real labelled examples to
exist before it can do anything at all.

Why train BOTH XGBoost and Random Forest:
--------------------------------------------
Neither algorithm is strictly better in general — it depends on the
specific data. Training both and keeping whichever scores higher on
a held-out test set (by F1, not accuracy — see _evaluate for why) is
standard, defensible practice: it's an actual comparison with
evidence, not a guess about which algorithm "should" work better.

Minimum sample gating:
-------------------------
Training on too few examples produces a classifier that's
overconfident and unreliable — worse than not having one at all,
since a confident wrong answer is more dangerous than an honest "not
enough data yet." `min_samples` (from config.yaml's
detection.min_classifier_samples) gates this: train() refuses to run
below that threshold, and the caller is expected to keep using the
anomaly detector alone until enough data accumulates.

Train/test split sizing (fixed after a real incident, July 2026):
--------------------------------------------------------------------
A fixed test_size=0.2 works fine once sample counts are reasonably
large, but breaks down early on: with e.g. 10 usable samples spread
across 3 classes, a 20% test split is only 2 samples — not enough
slots for scikit-learn's stratified split to guarantee at least one
example of every class in the test set, which raises a hard error
("test_size should be greater or equal to the number of classes")
rather than silently doing something unsafe. Rather than just
lowering min_classifier_samples (which doesn't fix the underlying
math — the same failure can recur any time class count grows faster
than sample count), the split size is now computed dynamically: large
enough to guarantee at least one test sample per class, but capped so
training still keeps at least one example of every class too. If
there isn't enough data for both sides of that requirement, or if any
class has fewer than MIN_SAMPLES_PER_CLASS examples at all, train()
raises a clear, specific ValueError rather than attempting an
unreliable split.

TRAINING_LABEL_SOURCES restricted to "llm" only (fixed July 2026):
--------------------------------------------------------------------
This set previously included "ddos_tracker" (and, briefly, was about
to be expanded to also include "port_scan_tracker"). Both were
reverted after Phase 2.5 verification surfaced a real, fundamental
incompatibility: process_ddos_attack() and process_port_scan_attack()
in pipeline/labeller.py store a small SYNTHETIC feature dict
describing the aggregate pattern itself (window_seconds,
distinct_ports_in_window, distinct_sources_in_window, etc.) — nothing
like the ~30 real per-flow features (syn_ratio, packets_per_second,
iat_mean, etc.) that every "llm"-sourced sample carries, and that
predict() is always called with from main.py's live pipeline. Mixing
these two incompatible schemas in one training set meant _get_feature_
order() would pick whichever schema happened to belong to the first
sample returned by fetch_all() (no deterministic ordering), and then
attempt to index every OTHER sample by that same key list — silently
producing a classifier trained on a fraction of the intended data (if
the mismatched samples happened to get excluded upstream) or a hard
KeyError (if they didn't). "ddos" and "port_scan" labelled samples are
still stored in the database in full — they remain valuable for
record-keeping, auditing, and any FUTURE dedicated aggregate-pattern
model — but they must never be fed to THIS classifier, which is
trained and queried exclusively on real per-flow features.
"""

from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass
from typing import Optional

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from detection.anomaly import IDENTITY_FIELDS


# Only samples labelled by an actual LLM judgment are used for
# training. This is deliberately narrower than "every deterministic,
# high-confidence label source" — see the module docstring's
# "TRAINING_LABEL_SOURCES restricted to 'llm' only" section for the
# real incompatibility this was reverted to fix. "auto" (no LLM call
# was made — score didn't meet the analysis threshold) and
# "llm_failed" (the call was attempted but failed) both result in
# label="unknown" by definition, which carries no real training
# signal. "ddos_tracker" and "port_scan_tracker" carry a real,
# confident, deterministic label — but a synthetic, aggregate-pattern
# feature schema that is fundamentally incompatible with the real
# per-flow features every other sample (and every live prediction
# call) uses.
TRAINING_LABEL_SOURCES = {"llm"}

# Minimum number of distinct classes required to train at all. A
# classifier trained on a single class can't learn to discriminate
# between anything — this isn't really a "minimum samples" question,
# it's a basic sanity check that there's something to classify.
MIN_DISTINCT_CLASSES = 2

# Minimum number of examples a single class must have before it can
# be included in training at all. Below this, a class can't have even
# one example in BOTH the train and test splits, which makes both
# training on it and evaluating it on it meaningless. See the module
# docstring ("Train/test split sizing") for the full incident writeup
# this constant was added to fix.
MIN_SAMPLES_PER_CLASS = 2


@dataclass
class EvaluationReport:
    """
    Holds the evaluation results for ONE trained model (either
    candidate), so train() can compare both fairly before picking a
    winner.
    """
    model_name: str
    f1_macro: float
    classification_report_text: str
    confusion_matrix: np.ndarray
    class_labels: list[str]

    def __repr__(self) -> str:
        return f"EvaluationReport(model={self.model_name}, f1_macro={self.f1_macro:.4f})"


@dataclass
class TrainingResult:
    """
    The outcome of a train() call — which model won, both models'
    evaluation reports (so the loser's numbers are visible too, not
    just thrown away), and how many samples were used.
    """
    winning_model_name: str
    winning_report: EvaluationReport
    losing_report: EvaluationReport
    total_samples_used: int


class AttackClassifier:
    """
    Wraps a StandardScaler + a chosen classifier (XGBoost or Random
    Forest, whichever wins evaluation). Call train() once enough
    labelled data exists, then predict() for new flows.
    """

    def __init__(self, config: dict):
        self.min_samples: int = int(config["detection"]["min_classifier_samples"])

        self.scaler: Optional[StandardScaler] = None
        self.model = None
        self.model_name: Optional[str] = None
        self.class_labels: Optional[list[str]] = None
        self._feature_order: Optional[list[str]] = None
        self.is_trained: bool = False

    def train(self, samples: list) -> TrainingResult:
        """
        Train on a list of LabelledSample objects (from
        pipeline/labeller.py's fetch_all()). Filters to only
        TRAINING_LABEL_SOURCES internally — callers don't need to
        pre-filter.

        Raises ValueError if there isn't enough usable data, if too
        few distinct classes exist, or if the class distribution
        can't support a safe stratified train/test split (see the
        module docstring's "Train/test split sizing" section) — these
        are deliberate hard stops, not silent skips, since a caller
        attempting to train should know immediately if it can't,
        rather than getting back a half-trained or default model.
        """
        usable = [s for s in samples if s.label_source in TRAINING_LABEL_SOURCES]

        if len(usable) < self.min_samples:
            raise ValueError(
                f"Not enough usable labelled samples to train: {len(usable)} available, "
                f"{self.min_samples} required (see config.yaml's "
                f"detection.min_classifier_samples). Keep running Sentinel to "
                f"accumulate more LLM-labelled data."
            )

        distinct_labels = {s.label for s in usable}
        if len(distinct_labels) < MIN_DISTINCT_CLASSES:
            raise ValueError(
                f"Only {len(distinct_labels)} distinct label(s) found "
                f"({sorted(distinct_labels)}) — need at least {MIN_DISTINCT_CLASSES} "
                f"different attack types to train a meaningful classifier."
            )

        # Drop classes with too few examples to meaningfully appear in
        # BOTH a train and a test split (see MIN_SAMPLES_PER_CLASS).
        # Re-check the distinct-class count afterward, since dropping
        # a rare class could bring us back below MIN_DISTINCT_CLASSES.
        label_counts = Counter(s.label for s in usable)
        sparse_labels = {
            label for label, count in label_counts.items() if count < MIN_SAMPLES_PER_CLASS
        }
        if sparse_labels:
            usable = [s for s in usable if s.label not in sparse_labels]
            distinct_labels = {s.label for s in usable}
            if len(distinct_labels) < MIN_DISTINCT_CLASSES:
                raise ValueError(
                    f"After excluding classes with fewer than {MIN_SAMPLES_PER_CLASS} "
                    f"examples ({sorted(sparse_labels)}), only {len(distinct_labels)} "
                    f"usable class(es) remain ({sorted(distinct_labels)}) — need at "
                    f"least {MIN_DISTINCT_CLASSES}. Keep running Sentinel to "
                    f"accumulate more examples of the rarer attack types."
                )

        self._feature_order = self._get_feature_order(usable[0].features)
        X = np.array([
            [sample.features[key] for key in self._feature_order]
            for sample in usable
        ])
        y = np.array([sample.label for sample in usable])

        # Dynamic test-set size (see module docstring for the full
        # incident this fixes): a fixed 20% split can produce a test
        # set smaller than the number of distinct classes, which
        # scikit-learn's stratified split refuses outright. Compute
        # the smallest test size that (a) guarantees at least one
        # example of every class in the test set, while (b) still
        # guaranteeing at least one example of every class remains in
        # the training set. If both can't be satisfied simultaneously
        # (too little data overall), raise a clear error rather than
        # attempting an unsafe or misleading split.
        n_samples = len(usable)
        n_classes = len(distinct_labels)
        default_test_count = round(0.2 * n_samples)
        test_count = max(n_classes, default_test_count)
        # Cap so training keeps at least one example per class too.
        max_test_count = n_samples - n_classes
        test_count = min(test_count, max_test_count)

        if test_count < n_classes:
            raise ValueError(
                f"Not enough samples ({n_samples}) across {n_classes} classes to "
                f"safely split into train and test sets with at least one example "
                f"of every class on both sides. Keep running Sentinel to "
                f"accumulate more labelled data."
            )

        # Stratified split: keeps the same proportion of each class in
        # both train and test sets, which matters a lot here since
        # attack-type classes are very unlikely to be balanced (e.g.
        # far more port_scan samples than data_exfiltration samples).
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_count, random_state=42, stratify=y
        )

        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)

        rf_model = RandomForestClassifier(n_estimators=200, random_state=42, class_weight="balanced")
        rf_model.fit(X_train_scaled, y_train)
        rf_report = self._evaluate(rf_model, "RandomForest", X_test_scaled, y_test)

        xgb_model = XGBClassifier(
            n_estimators=200, random_state=42, eval_metric="mlogloss",
        )
        # XGBoost needs numeric labels internally, not strings — encode
        # and decode around it so the public interface stays in terms
        # of real label strings throughout.
        label_to_int = {label: i for i, label in enumerate(sorted(distinct_labels))}
        int_to_label = {i: label for label, i in label_to_int.items()}
        y_train_int = np.array([label_to_int[label] for label in y_train])
        y_test_int = np.array([label_to_int[label] for label in y_test])

        xgb_model.fit(X_train_scaled, y_train_int)
        xgb_predictions_int = xgb_model.predict(X_test_scaled)
        xgb_predictions = np.array([int_to_label[i] for i in xgb_predictions_int])
        xgb_report = self._build_report("XGBoost", y_test, xgb_predictions)

        # Pick the winner by macro F1 — NOT accuracy. Accuracy is
        # misleading on imbalanced classes (a classifier that always
        # predicts the majority class can have high accuracy while
        # being useless on rarer attack types). Macro F1 weighs every
        # class equally regardless of how many samples it has.
        if rf_report.f1_macro >= xgb_report.f1_macro:
            winning_name, winning_model = "RandomForest", rf_model
            winning_report, losing_report = rf_report, xgb_report
        else:
            winning_name, winning_model = "XGBoost", xgb_model
            winning_report, losing_report = xgb_report, rf_report

        self.scaler = scaler
        self.model = winning_model
        self.model_name = winning_name
        self.class_labels = sorted(distinct_labels)
        self.is_trained = True

        # XGBoost needs the label encoding remembered for future
        # predict() calls — Random Forest works natively with string
        # labels, so this is only set when XGBoost wins.
        self._label_to_int = label_to_int if winning_name == "XGBoost" else None
        self._int_to_label = int_to_label if winning_name == "XGBoost" else None

        return TrainingResult(
            winning_model_name=winning_name,
            winning_report=winning_report,
            losing_report=losing_report,
            total_samples_used=len(usable),
        )

    def predict(self, features: dict) -> tuple[str, dict[str, float]]:
        """
        Predict the attack type for a new flow's features. Returns
        (predicted_label, {label: probability, ...}) so callers can
        see the full confidence distribution, not just the top pick.

        Raises RuntimeError if called before train() — there's no
        meaningful prediction to make without a trained model.
        """
        if not self.is_trained:
            raise RuntimeError("Cannot predict with an untrained AttackClassifier — call train() first.")

        X = np.array([[features[key] for key in self._feature_order]])
        X_scaled = self.scaler.transform(X)

        if self.model_name == "XGBoost":
            probabilities = self.model.predict_proba(X_scaled)[0]
            predicted_int = int(np.argmax(probabilities))
            predicted_label = self._int_to_label[predicted_int]
            prob_dict = {
                self._int_to_label[i]: float(p) for i, p in enumerate(probabilities)
            }
        else:
            probabilities = self.model.predict_proba(X_scaled)[0]
            predicted_label = self.model.classes_[np.argmax(probabilities)]
            prob_dict = {
                label: float(p) for label, p in zip(self.model.classes_, probabilities)
            }

        return predicted_label, prob_dict

    def save(self, path: str) -> None:
        if not self.is_trained:
            raise RuntimeError("Cannot save an untrained AttackClassifier.")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump({
            "model": self.model,
            "model_name": self.model_name,
            "scaler": self.scaler,
            "feature_order": self._feature_order,
            "class_labels": self.class_labels,
            "label_to_int": getattr(self, "_label_to_int", None),
            "int_to_label": getattr(self, "_int_to_label", None),
            "min_samples": self.min_samples,
        }, path)

    def load(self, path: str) -> None:
        bundle = joblib.load(path)
        self.model = bundle["model"]
        self.model_name = bundle["model_name"]
        self.scaler = bundle["scaler"]
        self._feature_order = bundle["feature_order"]
        self.class_labels = bundle["class_labels"]
        self._label_to_int = bundle["label_to_int"]
        self._int_to_label = bundle["int_to_label"]
        self.min_samples = bundle["min_samples"]
        self.is_trained = True

    # ------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------

    def _get_feature_order(self, sample_features: dict) -> list[str]:
        numeric_keys = [key for key in sample_features.keys() if key not in IDENTITY_FIELDS]
        return sorted(numeric_keys)

    def _evaluate(self, model, model_name: str, X_test, y_test) -> EvaluationReport:
        predictions = model.predict(X_test)
        return self._build_report(model_name, y_test, predictions)

    def _build_report(self, model_name: str, y_true, y_pred) -> EvaluationReport:
        labels = sorted(set(y_true) | set(y_pred))
        return EvaluationReport(
            model_name=model_name,
            f1_macro=f1_score(y_true, y_pred, average="macro", zero_division=0),
            classification_report_text=classification_report(y_true, y_pred, zero_division=0),
            confusion_matrix=confusion_matrix(y_true, y_pred, labels=labels),
            class_labels=labels,
        )