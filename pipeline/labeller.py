"""
pipeline/labeller.py
=======================
Self-labelling pipeline: takes a flow that's already been flagged
SUSPICIOUS/ATTACK by the anomaly detector, optionally asks the LLM
analyser to classify it, and stores the result in a SQLite database.

This is what turns Sentinel's live detections into a growing,
queryable training dataset — without ever needing a pre-existing
labelled dataset. Every confidently-labelled flow becomes a future
training example for the Phase 2 supervised classifier.

Labelling logic:
-------------------
  - A flow reaches this pipeline as either SUSPICIOUS or ATTACK from
    detection/anomaly.py. Critically, as of the verdict-promotion fix
    below, the anomaly detector's Isolation Forest score ALONE can
    only ever produce SUSPICIOUS — it has no understanding of what
    the traffic actually is, only that it looks statistically unusual
    relative to recent flows. ATTACK at the per-flow detector level is
    reserved for the deterministic flood-guard rule (see
    FLOOD_PACKETS_PER_SECOND_THRESHOLD in detection/anomaly.py).
  - Anomaly score below llm.min_score_for_analysis, OR the detector
    already said ATTACK (flood-guard) → ask the LLM.
  - LLM call succeeds with high/medium confidence → store with that
    label, source="llm".
  - LLM call succeeds but confidence is "low" → still stored, but
    flagged so the classifier (Phase 2, later) can choose to exclude
    low-confidence samples from training if desired.
  - LLM call fails for any reason (rate limit, network error,
    timeout) → flow is stored with label="unknown", source="llm_failed"
    rather than silently dropped — this keeps a complete record and
    makes failures visible/auditable, never silent data loss.
  - Anomaly score above the LLM threshold (SUSPICIOUS but not
    confidently anomalous enough) → stored directly with
    label="unknown", source="auto", no LLM call made at all — saves
    LLM usage for the cases that need it most.

Verdict promotion (SUSPICIOUS -> ATTACK):
-------------------------------------------
  A flow that reached this pipeline as SUSPICIOUS (i.e. flagged only
  by the Isolation Forest, not the flood guard) is promoted to a
  stored verdict of ATTACK if, and only if, the LLM independently
  identifies a genuine attack pattern (a label in _REAL_ATTACK_TYPES,
  i.e. anything other than "benign"/"unknown") with at least "medium"
  confidence. This is the deliberate fix for a real problem: treating
  a raw anomaly score as equivalent to a confirmed attack caused
  ordinary traffic (a single DNS lookup, an mDNS broadcast) to be
  labelled ATTACK purely because Isolation Forest is tuned to always
  flag ~contamination% of flows as outliers, whether or not anything
  malicious is actually happening. In a real deployment this kind of
  false alarm is not harmless — it causes alert fatigue and, if ever
  wired to automatic blocking, could disrupt legitimate traffic. The
  detector's statistical opinion and the LLM's confirmed judgment are
  now kept distinct: SUSPICIOUS means "worth a second look", ATTACK
  (as stored here) means either a deterministic rule fired (flood
  guard, aggregate DDoS tracker) or a second, independent check
  corroborated it.

  NOTE: this promotion affects what gets STORED in the database (and
  therefore what future classifier training and queries see) — it
  does not retroactively change what was already printed to the live
  terminal table for that flow, since the LLM's verdict arrives after
  the row has already been rendered. Reflecting the corrected verdict
  live (e.g. by re-rendering the row after LLM analysis completes) is
  a reasonable Phase 3 improvement but is out of scope here.

Aggregate DDoS samples (process_ddos_attack):
-------------------------------------------
  detection/ddos_tracker.py's GlobalRateTracker watches for a pattern
  no single flow can reveal on its own: many distinct sources
  simultaneously sending traffic, only alarming in aggregate. When it
  reports Verdict.ATTACK, both its total-flow-rate AND distinct-
  source-count thresholds have been crossed together (see that
  module's docstring for why requiring both matters) — this is
  already deterministic, rule-based evidence, exactly like the
  flood-rate guard in detection/anomaly.py. It is stored directly as
  a "ddos" sample with label_source="ddos_tracker", with no LLM call
  needed — asking the LLM to "confirm" an already-deterministic
  aggregate finding would add a point of failure without adding real
  certainty. This is called separately from process() (which handles
  only per-flow DetectionResults) since a DDoS finding has no single
  underlying flow — see main.py for where this is invoked, on the
  transition into an ATTACK-level DDoS verdict.

Per-source port-scan samples (process_port_scan_attack):
-------------------------------------------
  detection/port_scan_tracker.py's PortScanTracker watches for a
  different pattern no single flow can reveal on its own: one source
  touching many distinct destination ports. Like the DDoS tracker's
  finding, a reported ATTACK verdict here is already deterministic,
  rule-based evidence (the source's distinct-port count crossed
  attack_distinct_ports_threshold) — so, exactly like
  process_ddos_attack, no LLM confirmation is requested. Called
  separately from process() since a port-scan finding is aggregated
  per source IP across many flows, not tied to any single flow — see
  main.py for where this is invoked, on the transition into an
  ATTACK-level port-scan verdict for a given source IP.

  Reasoning text grammar fix (July 2026): the human-readable
  reasoning string previously always said "N targets", even when
  N was 1 (e.g. "touched 692 distinct ports across 1 targets"). This
  never affected detection or blocking — purely a cosmetic accuracy
  issue in text shown to a real operator — but Sentinel's stated goal
  is precise, non-confusing reporting, so the singular/plural form is
  now chosen correctly based on the actual count.
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from detection.anomaly import DetectionResult, Verdict
from detection.llm_analyser import LLMAnalyser, AnalysisResult, KNOWN_ATTACK_TYPES


# Fields from a flow's feature dict that get their own dedicated
# database column, for fast filtering/querying later (e.g.
# "show me all flows where syn_ratio > 0.8"). Every OTHER feature
# still gets preserved too, in the all_features JSON column — these
# specific columns are just a fast-access subset, not the only data
# kept.
_INDEXED_FEATURE_COLUMNS = [
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "total_packets", "packets_per_second", "syn_ratio", "zero_payload_ratio",
]

# Attack types that represent a genuinely confirmed threat. Everything
# else in KNOWN_ATTACK_TYPES ("benign", "unknown") is NOT treated as
# an attack, even though the LLM was asked to analyse the flow — the
# LLM concluding "benign" or "I can't tell" must never promote a
# flow's stored verdict to ATTACK.
_REAL_ATTACK_TYPES = frozenset(KNOWN_ATTACK_TYPES) - {"benign", "unknown"}

# Confidence levels the LLM must meet for its attack-type finding to
# promote a SUSPICIOUS flow to a stored ATTACK verdict. "low"
# confidence findings are still stored (with whatever label the LLM
# gave), but are not trusted enough on their own to promote a verdict.
_PROMOTION_CONFIDENCES = frozenset({"high", "medium"})


@dataclass
class LabelledSample:
    """One row of the labelled_flows table, as a Python object."""
    id: int
    timestamp: str
    label: str
    label_source: str  # "llm", "llm_failed", "auto", "ddos_tracker", or "port_scan_tracker"
    confidence: str
    anomaly_score: Optional[float]
    verdict: str
    reasoning: Optional[str]
    features: dict  # Full original feature dict, decoded from JSON


class Labeller:
    """
    Wires together anomaly detection results, the LLM analyser, and
    SQLite storage. Call `process(result)` once per flow that the
    anomaly detector has already scored, `process_ddos_attack()` on
    the transition into an aggregate DDoS ATTACK verdict, and
    `process_port_scan_attack()` on the transition into a per-source
    port-scan ATTACK verdict.
    """

    def __init__(self, config: dict, llm_analyser: Optional[LLMAnalyser] = None):
        """
        llm_analyser is accepted as an optional, already-constructed
        instance (rather than building one internally) so callers can
        share a single LLMAnalyser — and its rate limiter state —
        across the whole pipeline, and so tests can inject a fake
        analyser without needing real API credentials.
        """
        self.db_path: str = config["storage"]["db_path"]
        self.llm_analyser = llm_analyser
        self._ensure_schema()

    def process(self, result: DetectionResult) -> Optional[LabelledSample]:
        """
        Process one PER-FLOW detection result. Returns the
        LabelledSample that was stored, or None if this result didn't
        warrant storage at all (e.g. a NORMAL or WARMING_UP verdict —
        only SUSPICIOUS/ATTACK flows are ever labelled or stored
        here).

        For aggregate DDoS detections (no single underlying flow),
        see process_ddos_attack() instead. For per-source port-scan
        detections, see process_port_scan_attack() instead.
        """
        if result.verdict not in (Verdict.SUSPICIOUS, Verdict.ATTACK):
            return None

        # What actually gets stored as this flow's verdict. Starts as
        # whatever the detector said, and may be promoted below if the
        # LLM independently confirms a real attack pattern.
        effective_verdict = result.verdict

        if self.llm_analyser is not None and (
            result.verdict == Verdict.ATTACK or self.llm_analyser.should_analyse(result.score)
        ):
            analysis = self.llm_analyser.analyse(
                features=result.features,
                anomaly_score=result.score,
                verdict=result.verdict.value,
            )
            label, source, confidence, reasoning = self._interpret_analysis(analysis)

            # Promotion: a flow that arrived here as SUSPICIOUS (i.e.
            # flagged only by the Isolation Forest's statistical
            # score, not the deterministic flood guard) only becomes
            # a stored ATTACK if the LLM independently identifies a
            # genuine attack pattern with at least medium confidence.
            # Flood-guard-triggered ATTACK verdicts are already
            # deterministic rule-based evidence and are never
            # downgraded here, regardless of what the LLM says.
            if (
                result.verdict == Verdict.SUSPICIOUS
                and label in _REAL_ATTACK_TYPES
                and confidence in _PROMOTION_CONFIDENCES
            ):
                effective_verdict = Verdict.ATTACK
        else:
            # Either no LLM analyser configured at all, or this flow's
            # score didn't meet the (stricter) LLM analysis threshold —
            # store it anyway, just without an LLM-derived label.
            label, source, confidence, reasoning = "unknown", "auto", "unknown", None

        return self._store(result, effective_verdict, label, source, confidence, reasoning)

    def process_ddos_attack(self, ddos_result) -> LabelledSample:
        """
        Store a genuine aggregate DDoS detection (see
        detection/ddos_tracker.py's GlobalRateTracker) as a labelled
        training sample.

        Unlike per-flow SUSPICIOUS/ATTACK verdicts, an aggregate DDoS
        ATTACK verdict is already deterministic, rule-based evidence —
        both total flow rate and distinct source count crossed their
        configured thresholds together (see GlobalRateTracker's
        docstring for why requiring both matters). No LLM confirmation
        is requested here, the same way the flood-rate guard in
        detection/anomaly.py doesn't ask the LLM to confirm its own
        deterministic finding.

        Callers (see main.py) should call this ONCE per transition
        into an ATTACK-level DDoS verdict, not on every flow processed
        while the attack is ongoing — this method itself doesn't
        de-duplicate, since it has no visibility into prior calls.

        There is no single underlying flow for an aggregate detection,
        so a synthetic feature dict describing the aggregate pattern
        (window size, total flows, distinct sources) is stored instead
        of real per-flow features. anomaly_score is None, matching how
        WARMING_UP flows are stored — there is no Isolation Forest
        score for this kind of finding.
        """
        features = {
            "detection_type": "aggregate_ddos",
            "window_seconds": ddos_result.window_seconds,
            "total_flows_in_window": ddos_result.total_flows_in_window,
            "distinct_sources_in_window": ddos_result.distinct_sources_in_window,
        }
        synthetic_result = DetectionResult(Verdict.ATTACK, None, features)
        reasoning = (
            f"Aggregate rate tracker: {ddos_result.total_flows_in_window} flows "
            f"from {ddos_result.distinct_sources_in_window} distinct sources within "
            f"a {ddos_result.window_seconds:.0f}s window (both thresholds exceeded)."
        )
        return self._store(
            synthetic_result,
            effective_verdict=Verdict.ATTACK,
            label="ddos",
            source="ddos_tracker",
            confidence="high",
            reasoning=reasoning,
        )

    def process_port_scan_attack(self, port_scan_result) -> LabelledSample:
        """
        Store a genuine port-scan detection (see
        detection/port_scan_tracker.py's PortScanTracker) as a
        labelled training sample.

        Like process_ddos_attack, a port-scan ATTACK verdict is
        already deterministic, rule-based evidence — the source IP's
        distinct-destination-port count within the sliding window
        crossed attack_distinct_ports_threshold (see
        PortScanTracker.check() for the exact rule). No LLM
        confirmation is requested here, for the same reason
        process_ddos_attack skips it: asking the LLM to "confirm" an
        already-deterministic threshold crossing adds a point of
        failure without adding real certainty.

        Callers (see main.py) should call this ONCE per transition
        into an ATTACK-level port-scan verdict for a given source IP,
        not on every flow processed while the scan is ongoing — this
        method itself doesn't de-duplicate, since it has no visibility
        into prior calls (mirrors process_ddos_attack's contract).

        There is no single underlying flow for this aggregate,
        per-source pattern, so a synthetic feature dict describing the
        scan (source IP, window size, distinct ports/targets touched)
        is stored instead of real per-flow features. anomaly_score is
        None, matching how aggregate DDoS samples are stored — there
        is no Isolation Forest score for this kind of finding.

        Grammar note (July 2026): the reasoning text below correctly
        pluralises "target"/"targets" based on the actual count —
        see module docstring's "Reasoning text grammar fix" section.
        """
        features = {
            "detection_type": "port_scan",
            "src_ip": port_scan_result.src_ip,
            "window_seconds": port_scan_result.window_seconds,
            "distinct_ports_in_window": port_scan_result.distinct_ports_in_window,
            "distinct_targets_in_window": port_scan_result.distinct_targets_in_window,
        }
        synthetic_result = DetectionResult(Verdict.ATTACK, None, features)
        target_word = "target" if port_scan_result.distinct_targets_in_window == 1 else "targets"
        reasoning = (
            f"Port scan tracker: source {port_scan_result.src_ip} touched "
            f"{port_scan_result.distinct_ports_in_window} distinct destination ports "
            f"across {port_scan_result.distinct_targets_in_window} {target_word} within a "
            f"{port_scan_result.window_seconds:.0f}s window (threshold exceeded)."
        )
        return self._store(
            synthetic_result,
            effective_verdict=Verdict.ATTACK,
            label="port_scan",
            source="port_scan_tracker",
            confidence="high",
            reasoning=reasoning,
        )

    # ------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------

    def _interpret_analysis(self, analysis: AnalysisResult) -> tuple[str, str, str, Optional[str]]:
        if not analysis.available:
            # LLM call failed for any reason — record that fact
            # explicitly rather than silently dropping the sample.
            return "unknown", "llm_failed", "unknown", analysis.error
        return analysis.attack_type, "llm", analysis.confidence.value, analysis.reasoning

    def _store(self, result: DetectionResult, effective_verdict: Verdict, label: str, source: str,
               confidence: str, reasoning: Optional[str]) -> LabelledSample:
        timestamp = datetime.now(timezone.utc).isoformat()
        features = result.features

        row = {
            "timestamp": timestamp,
            "label": label,
            "label_source": source,
            "confidence": confidence,
            "anomaly_score": result.score,
            "verdict": effective_verdict.value,
            "reasoning": reasoning,
            "all_features": json.dumps(features),
        }
        for col in _INDEXED_FEATURE_COLUMNS:
            row[col] = features.get(col)

        conn = self._connect()
        try:
            columns = list(row.keys())
            placeholders = ", ".join("?" for _ in columns)
            column_list = ", ".join(columns)
            cursor = conn.execute(
                f"INSERT INTO labelled_flows ({column_list}) VALUES ({placeholders})",
                [row[col] for col in columns],
            )
            conn.commit()
            row_id = cursor.lastrowid
        finally:
            conn.close()

        return LabelledSample(
            id=row_id,
            timestamp=timestamp,
            label=label,
            label_source=source,
            confidence=confidence,
            anomaly_score=result.score,
            verdict=effective_verdict.value,
            reasoning=reasoning,
            features=features,
        )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _ensure_schema(self) -> None:
        """
        Create the labelled_flows table and its indexes if they don't
        already exist. Safe to call every time the Labeller is
        constructed — CREATE TABLE IF NOT EXISTS is a no-op on an
        already-initialised database.
        """
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = self._connect()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS labelled_flows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    label TEXT NOT NULL,
                    label_source TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    anomaly_score REAL,
                    verdict TEXT NOT NULL,
                    reasoning TEXT,
                    all_features TEXT NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol INTEGER,
                    total_packets INTEGER,
                    packets_per_second REAL,
                    syn_ratio REAL,
                    zero_payload_ratio REAL
                )
            """)
            # Indexes on the columns most likely to be filtered/grouped
            # on when the Phase 2 classifier pulls training data, or
            # when manually reviewing labelled samples.
            conn.execute("CREATE INDEX IF NOT EXISTS idx_label ON labelled_flows(label)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_label_source ON labelled_flows(label_source)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON labelled_flows(timestamp)")
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------
    # Query helpers — used by the classifier (Phase 2, next) and
    # useful for manual inspection in the meantime.
    # ------------------------------------------------------------

    def count_by_label(self) -> dict[str, int]:
        """Returns {label: count} for all stored samples — useful for
        checking whether there's enough labelled data yet to train a
        classifier, and whether classes are reasonably balanced."""
        conn = self._connect()
        try:
            cursor = conn.execute(
                "SELECT label, COUNT(*) FROM labelled_flows GROUP BY label"
            )
            return dict(cursor.fetchall())
        finally:
            conn.close()

    def count_by_label_source(self) -> dict[str, int]:
        """
        Returns {label_source: count} — i.e. how many samples came
        from a real LLM judgment ("llm") vs. never got analysed at
        all ("auto", score didn't meet llm.min_score_for_analysis) vs.
        an LLM call that was attempted but failed ("llm_failed") vs.
        a deterministic aggregate DDoS detection ("ddos_tracker") vs.
        a deterministic port-scan detection ("port_scan_tracker").

        This is the key diagnostic for understanding classifier
        training data quality: "llm", "ddos_tracker", and
        "port_scan_tracker" samples are used for training (see
        TRAINING_LABEL_SOURCES in detection/classifier.py) — a
        database dominated by "auto" means very little of the
        accumulated data is actually usable yet, which directly
        explains a classifier trained on far fewer real samples than
        the total row count might suggest.
        """
        conn = self._connect()
        try:
            cursor = conn.execute(
                "SELECT label_source, COUNT(*) FROM labelled_flows GROUP BY label_source"
            )
            return dict(cursor.fetchall())
        finally:
            conn.close()

    def fetch_all(self, min_confidence: Optional[str] = None) -> list[LabelledSample]:
        """
        Fetch all stored samples, optionally filtered to a minimum
        confidence level. Used by the Phase 2 classifier to build its
        training set.
        """
        conn = self._connect()
        try:
            query = "SELECT * FROM labelled_flows"
            params = []
            if min_confidence is not None:
                query += " WHERE confidence = ?"
                params.append(min_confidence)

            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()
        finally:
            conn.close()

        return [
            LabelledSample(
                id=row["id"],
                timestamp=row["timestamp"],
                label=row["label"],
                label_source=row["label_source"],
                confidence=row["confidence"],
                anomaly_score=row["anomaly_score"],
                verdict=row["verdict"],
                reasoning=row["reasoning"],
                features=json.loads(row["all_features"]),
            )
            for row in rows
        ]