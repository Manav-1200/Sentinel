"""
detection/llm_analyser.py
============================
LLM-assisted reasoning about suspicious/attack flows — the first step
toward self-labelling (Phase 2). Given a flow's features and the
anomaly detector's verdict, asks an LLM to reason about what kind of
attack (if any) this looks like, with a confidence level and a short
explanation.

This is NOT a replacement for the anomaly detector (detection/anomaly.py)
or the flood/DDoS guards — it's an additional reasoning layer, called
ONLY on flows that those mechanisms have already flagged as
SUSPICIOUS or ATTACK. The LLM's job is to go from "this looks unusual"
to "this looks like a port scan, here's why" — turning a bare anomaly
score into a labelled, explainable training example.

Provider abstraction:
-----------------------
Built against TWO interchangeable providers from day one:
  - NVIDIA NIM (default) — free tier, OpenAI-compatible API. Chosen
    as the default specifically because it requires no prepaid
    credit, unlike the Anthropic API.
  - Anthropic Claude — optional alternative, used if explicitly
    configured (requires prepaid API credit).

Both are accessed through a single `analyse()` function with the same
input/output shape, so the rest of the pipeline never needs to know
which provider is active. Switching providers is a one-line config
change (`llm.provider` in config.yaml), not a code change.

Failure handling:
-------------------
Network calls can fail in ways nothing else in this codebase has had
to handle yet: timeouts, malformed responses, rate limits, the
provider being temporarily down. Every failure mode here is designed
to degrade gracefully — if the LLM call fails for any reason, the
caller gets a clearly-marked "analysis unavailable" result rather than
an exception that could crash the whole detection pipeline. A flaky
LLM provider must never be able to take down live packet capture.

Hard timeout backstop (added July 2026, after a real hang):
--------------------------------------------------------------
Passing `timeout=...` to the OpenAI/Anthropic client constructor sets
an HTTP-level timeout, but BOTH SDKs also retry failed/timed-out
requests by default (typically max_retries=2, with backoff between
attempts) — so a single configured timeout of, say, 10 seconds can
silently become 30-40+ seconds in practice once retries are counted,
and in rare cases (a hung TCP connection that never cleanly times out
at the socket level, a proxy holding a connection open) could block
far longer than that. Since `analyse()` is called synchronously from
the main capture loop for every SUSPICIOUS/ATTACK flow, any hang here
blocks live packet capture entirely — exactly the failure mode this
module's docstring says must never happen.

Two independent fixes are applied:
  1. Both clients are constructed with max_retries=0, so the SDK's
     own retry/backoff behaviour can never multiply the configured
     timeout.
  2. The actual network call is additionally run in a worker thread
     with a hard `future.result(timeout=...)` from the main thread.
     This is a backstop that does not trust the SDK's own timeout
     handling at all — even if a future SDK version changes its
     retry defaults, or a connection hangs in a way neither timeout
     nor max_retries catches, the calling thread can never block
     longer than timeout_seconds + a small buffer. The worker thread
     itself may still be blocked on the underlying socket after this
     returns (Python cannot forcibly kill a thread) — but it's a
     daemon thread doing no shared-state mutation, so it is safe to
     simply abandon and let it die naturally when the network call
     eventually resolves or the process exits.
"""

from __future__ import annotations

import json
import os
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class AnalysisConfidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"  # Used when analysis failed or couldn't be parsed


# A small, fixed vocabulary of attack types the LLM can choose from.
# Keeping this fixed (rather than letting the LLM invent free-form
# labels) is important: these labels become training data for the
# Phase 2 supervised classifier, which needs a consistent, finite set
# of classes to learn from — free-form text labels would make that
# impossible.
KNOWN_ATTACK_TYPES = [
    "port_scan",
    "syn_flood",
    "ddos",
    "brute_force",
    "data_exfiltration",
    "benign",       # The LLM concluded this is actually normal, despite the anomaly score
    "unknown",      # The LLM genuinely couldn't determine a specific type
]


@dataclass
class AnalysisResult:
    """
    The result of asking an LLM to reason about one flow. `available`
    is False whenever the LLM call failed for any reason (timeout,
    network error, malformed response) — callers should treat this
    the same way they'd treat "no analysis was attempted", rather than
    as a confident "benign" or "unknown" verdict.
    """
    available: bool
    attack_type: Optional[str] = None
    confidence: AnalysisConfidence = AnalysisConfidence.UNKNOWN
    reasoning: Optional[str] = None
    error: Optional[str] = None

    def __repr__(self) -> str:
        if not self.available:
            return f"AnalysisResult(available=False, error={self.error!r})"
        return (
            f"AnalysisResult(attack_type={self.attack_type!r}, "
            f"confidence={self.confidence.value}, reasoning={self.reasoning!r})"
        )


# ----------------------------------------------------------------------
# Rate limiting
# ----------------------------------------------------------------------
class _RateLimiter:
    """
    A simple sliding-window rate limiter: tracks call timestamps in
    the last 60 seconds and refuses new calls once the limit is hit.

    This exists specifically to protect free-tier rate limits (NVIDIA
    NIM) from being exhausted during a real attack, when many flows
    could be flagged SUSPICIOUS/ATTACK in a short window — without
    this, a single busy minute could burn through an entire day's
    free-tier quota.
    """

    def __init__(self, max_calls_per_minute: int):
        self.max_calls_per_minute = max_calls_per_minute
        self._call_times: deque[float] = deque()

    def allow_call(self) -> bool:
        now = time.time()
        cutoff = now - 60.0
        while self._call_times and self._call_times[0] < cutoff:
            self._call_times.popleft()

        if len(self._call_times) >= self.max_calls_per_minute:
            return False

        self._call_times.append(now)
        return True


# ----------------------------------------------------------------------
# Prompt construction
# ----------------------------------------------------------------------
def _build_prompt(features: dict, anomaly_score: float, verdict: str) -> str:
    """
    Build a human-readable description of a flow's features for the
    LLM to reason about. Deliberately written in plain language
    ("2000 SYN packets in 0.5 seconds") rather than dumping raw JSON —
    LLMs reason more reliably about clearly-stated facts than about
    parsing a wall of numbers themselves.

    The detector's verdict is deliberately presented AFTER the raw
    features, and framed as an unreliable, purely-statistical signal
    rather than a stated fact — earlier versions of this prompt led
    with "this flow was flagged '{verdict}'" before showing any
    features, which measurably biased the model toward rubber-stamping
    the detector's call (especially smaller/faster models) rather than
    reasoning independently from the evidence. Ordinary low-volume
    traffic to standard ports (DNS, mDNS, HTTPS, SSDP) was being
    mislabelled as port_scan/ddos with high confidence as a result.

    A second, opposite failure mode was found after the fix above: the
    added skepticism guidance, while correctly stopping false
    positives on ordinary traffic, also caused the model to under-call
    genuine, obvious floods -- a real 35,716-packet, ~3,745 pkts/sec,
    fully one-directional UDP flood (confirmed via direct testing,
    July 2026) came back "unknown, low confidence" with reasoning that
    literally said "the packet rate ... [is] not extreme", despite
    being an unambiguous flood by any reasonable numeric standard. The
    8B model had no concrete anchor for what "extreme" means in
    packets/second, so it was guessing at scale rather than reasoning
    from a threshold. The quantitative guidance below gives it that
    anchor, so skepticism about the detector's verdict doesn't also
    mean skepticism about the actual numbers in front of it.
    """
    proto_names = {6: "TCP", 17: "UDP", 1: "ICMP"}
    protocol = proto_names.get(features.get("protocol"), str(features.get("protocol")))

    lines = [
        "Analyse this network traffic flow and determine if it represents an attack.",
        "",
        f"Protocol: {protocol}",
        f"Source: {features.get('src_ip')}:{features.get('src_port')}",
        f"Destination: {features.get('dst_ip')}:{features.get('dst_port')}",
        f"Duration: {features.get('duration_seconds', 0):.3f} seconds",
        f"Total packets: {features.get('total_packets', 0)} "
        f"({features.get('fwd_packets', 0)} forward, {features.get('bwd_packets', 0)} backward)",
        f"Packet rate: {features.get('packets_per_second', 0):.1f} packets/second",
        f"Byte rate: {features.get('bytes_per_second', 0):.1f} bytes/second",
    ]

    if protocol == "TCP":
        lines.append(
            f"TCP flags seen: SYN={features.get('syn_count', 0)}, "
            f"ACK={features.get('ack_count', 0)}, FIN={features.get('fin_count', 0)}, "
            f"RST={features.get('rst_count', 0)}"
        )
        lines.append(f"SYN ratio (SYN packets / total): {features.get('syn_ratio', 0):.2f}")

    lines.append(f"Zero-payload packet ratio: {features.get('zero_payload_ratio', 0):.2f}")
    lines.append(f"Inter-arrival time: mean={features.get('iat_mean', 0):.4f}s, "
                  f"std={features.get('iat_std', 0):.4f}s")
    lines.append("")
    lines.append(
        "An automated anomaly detector flagged this flow for review "
        f"(statistical verdict: '{verdict}', raw score={anomaly_score:.4f}, "
        "more negative = more statistically unusual relative to recent traffic). "
        "This detector has no understanding of what the traffic actually IS -- "
        "it only measures statistical deviation, and it frequently misfires on "
        "ordinary traffic (e.g. a single DNS lookup, an mDNS broadcast, or a "
        "brief HTTPS handshake can all look 'unusual' in a small sample window "
        "even though they are completely benign)."
    )
    lines.append("")
    lines.append(
        "Judge this flow primarily on the actual features above: packet counts, "
        "ports, protocol, rates, and flags. Only classify it as a specific attack "
        "type if the features themselves show clear evidence of that attack "
        "pattern (e.g. many distinct destination ports from one source for "
        "port_scan, a very high SYN ratio with few completions for syn_flood, "
        "extreme packet/byte rate for ddos). A small number of packets to a "
        "standard service port (53/DNS, 443/HTTPS, 5353/mDNS, 1900/SSDP) with "
        "no unusual flags is virtually always 'benign', regardless of what the "
        "detector's verdict says."
    )
    lines.append("")
    lines.append(
        "For scale: sustained traffic exceeding roughly 500-1000 packets per "
        "second for more than a couple of seconds is unusual for ordinary "
        "traffic and should be treated as a meaningful signal, not dismissed "
        "as 'not extreme' -- especially when combined with all-forward "
        "traffic (zero or near-zero packets in the reverse direction), which "
        "indicates the destination is not meaningfully responding. This "
        "pattern (high sustained one-directional packet rate) is a strong "
        "indicator of a flood/DoS-style attack (syn_flood for TCP with a high "
        "SYN ratio, ddos otherwise), even without other unusual features."
    )
    lines.append("")
    lines.append(
        "Respond with ONLY a JSON object (no other text, no markdown formatting) "
        "with exactly these fields:\n"
        '  "attack_type": one of ' + json.dumps(KNOWN_ATTACK_TYPES) + ",\n"
        '  "confidence": one of ["high", "medium", "low"],\n'
        '  "reasoning": a single short sentence explaining your classification, '
        'referencing the specific features that support it.'
    )

    return "\n".join(lines)


def _parse_llm_response(raw_text: str) -> AnalysisResult:
    """
    Parse the LLM's raw text response into an AnalysisResult.

    LLMs occasionally wrap JSON in markdown code fences or add stray
    text despite instructions — this strips common wrapping before
    parsing, but if parsing still fails, returns available=False
    rather than guessing at a result. A malformed response should
    never silently become a fabricated label.
    """
    text = raw_text.strip()

    # Strip markdown code fences if present (```json ... ``` or ``` ... ```)
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [line for line in lines if not line.strip().startswith("```")]
        text = "\n".join(lines).strip()

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as e:
        return AnalysisResult(available=False, error=f"Could not parse LLM response as JSON: {e}")

    attack_type = parsed.get("attack_type")
    confidence_str = parsed.get("confidence", "unknown")
    reasoning = parsed.get("reasoning")

    if attack_type not in KNOWN_ATTACK_TYPES:
        return AnalysisResult(
            available=False,
            error=f"LLM returned an unrecognised attack_type: {attack_type!r}",
        )

    try:
        confidence = AnalysisConfidence(confidence_str)
    except ValueError:
        confidence = AnalysisConfidence.UNKNOWN

    return AnalysisResult(
        available=True,
        attack_type=attack_type,
        confidence=confidence,
        reasoning=reasoning,
    )


# ----------------------------------------------------------------------
# Provider-specific call implementations
# ----------------------------------------------------------------------
def _call_nim(prompt: str, config: dict, timeout_seconds: float) -> str:
    """
    Call NVIDIA NIM's OpenAI-compatible API. Raises on any failure —
    callers are responsible for catching and converting to a graceful
    AnalysisResult(available=False, ...).

    max_retries=0: the OpenAI SDK retries failed/timed-out requests
    twice by default, which would silently turn one configured
    timeout into up to 3x that duration. Retries are disabled here
    because analyse() already treats any failure as "unavailable" and
    the calling pipeline moves on immediately — a fast, clean failure
    is far more valuable than a slow, hidden one for a live detection
    loop. See module docstring's "Hard timeout backstop" section.
    """
    from openai import OpenAI

    api_key = os.environ.get("NVIDIA_NIM_API_KEY")
    if not api_key:
        raise RuntimeError("NVIDIA_NIM_API_KEY is not set in the environment (.env)")

    nim_config = config["llm"]["nim"]
    client = OpenAI(
        base_url=nim_config["base_url"],
        api_key=api_key,
        timeout=timeout_seconds,
        max_retries=0,
    )

    response = client.chat.completions.create(
        model=nim_config["model"],
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,  # Low temperature — we want consistent, deterministic-ish classification, not creative variation
        max_tokens=300,
    )
    return response.choices[0].message.content


def _call_anthropic(prompt: str, config: dict, timeout_seconds: float) -> str:
    """
    Call the Anthropic Claude API. Raises on any failure — callers
    are responsible for catching and converting to a graceful
    AnalysisResult(available=False, ...).

    max_retries=0: same reasoning as _call_nim above — the Anthropic
    SDK also retries by default, which would multiply the configured
    timeout unpredictably. See module docstring's "Hard timeout
    backstop" section.
    """
    import anthropic

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY is not set in the environment (.env)")

    anthropic_config = config["llm"]["anthropic"]
    client = anthropic.Anthropic(
        api_key=api_key,
        timeout=timeout_seconds,
        max_retries=0,
    )

    response = client.messages.create(
        model=anthropic_config["model"],
        max_tokens=300,
        temperature=0.2,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text


# Single shared worker pool for the hard-timeout backstop below. One
# worker is enough: analyse() is already called synchronously, one
# flow at a time, from the main capture loop — this thread exists
# purely so the MAIN thread can enforce a real deadline on a call
# whose own internal timeout might not fire, not to add concurrency.
# A module-level pool (rather than one per LLMAnalyser instance) keeps
# this cheap even if multiple LLMAnalyser instances are constructed
# in the same process (e.g. try_train_classifier's Labeller vs. the
# live one in main.py).
_llm_call_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="llm-analyser-call")


def _run_with_hard_timeout(func, timeout_seconds: float, *args, **kwargs):
    """
    Run `func(*args, **kwargs)` in a worker thread and enforce a hard
    wall-clock deadline from the CALLING thread, regardless of
    whether func's own internal timeout/retry logic actually fires.

    This is the backstop described in the module docstring: even if
    the OpenAI/Anthropic client's own `timeout=` argument fails to
    cut off a hung connection (a stalled proxy, a DNS resolution that
    never completes, a future SDK version with different retry
    defaults), the calling thread is GUARANTEED to regain control
    after timeout_seconds + a small buffer.

    If the deadline is exceeded, the worker thread is simply abandoned
    (Python has no safe way to forcibly kill a thread) — this is fine
    here because the worker does no shared mutable state, only a
    single outbound network call and a return value that will simply
    be discarded if it arrives late.

    Raises TimeoutError (a plain builtin, not concurrent.futures'
    subclass) on deadline exceeded, or re-raises whatever exception
    func itself raised.
    """
    future = _llm_call_executor.submit(func, *args, **kwargs)
    try:
        # +2s buffer: the client's own timeout is enforced internally
        # by the SDK's HTTP layer; this outer deadline just needs to
        # be slightly more generous so a clean internal timeout has a
        # chance to return normally, while still guaranteeing this
        # call can never block indefinitely.
        return future.result(timeout=timeout_seconds + 2.0)
    except FutureTimeoutError:
        raise TimeoutError(
            f"LLM call did not return within {timeout_seconds + 2.0:.1f}s "
            "(hard backstop timeout — the SDK's own timeout/retry handling "
            "did not return control in time)."
        )


# ----------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------
class LLMAnalyser:
    """
    Provider-agnostic LLM flow analyser. Construct once, call
    analyse() for each SUSPICIOUS/ATTACK flow that meets the
    min_score_for_analysis threshold.
    """

    def __init__(self, config: dict):
        llm_config = config["llm"]
        self.provider: str = llm_config["provider"]
        self.min_score_for_analysis: float = float(llm_config["min_score_for_analysis"])
        self.timeout_seconds: float = float(llm_config["timeout_seconds"])
        self._config = config

        self._rate_limiter = _RateLimiter(int(llm_config["max_calls_per_minute"]))

        if self.provider not in ("nim", "anthropic"):
            raise ValueError(f"Unknown llm.provider: {self.provider!r}. Expected 'nim' or 'anthropic'.")

    def should_analyse(self, anomaly_score: float) -> bool:
        """
        Whether a flow with this anomaly score should be sent to the
        LLM at all. This is a SEPARATE, stricter check than the
        anomaly detector's own SUSPICIOUS/ATTACK thresholds — see
        config.yaml's llm.min_score_for_analysis comment for why.
        """
        return anomaly_score < self.min_score_for_analysis

    def analyse(self, features: dict, anomaly_score: float, verdict: str) -> AnalysisResult:
        """
        Ask the configured LLM provider to reason about a flow.
        Returns AnalysisResult(available=False, ...) gracefully for
        ANY failure — rate limit exceeded, network error, timeout,
        malformed response — rather than raising. This method must
        never crash the calling pipeline, and — as of the hard
        timeout backstop described in the module docstring — must
        never block it for longer than timeout_seconds + 2s either.
        """
        if not self._rate_limiter.allow_call():
            return AnalysisResult(
                available=False,
                error="Rate limit exceeded (max_calls_per_minute) — skipping LLM analysis for this flow.",
            )

        prompt = _build_prompt(features, anomaly_score, verdict)

        try:
            if self.provider == "nim":
                raw_response = _run_with_hard_timeout(
                    _call_nim, self.timeout_seconds, prompt, self._config, self.timeout_seconds
                )
            else:
                raw_response = _run_with_hard_timeout(
                    _call_anthropic, self.timeout_seconds, prompt, self._config, self.timeout_seconds
                )
        except Exception as e:
            # Deliberately broad: ANY failure here (network error,
            # auth error, timeout, provider outage, missing API key,
            # or the hard backstop TimeoutError above) must degrade
            # gracefully, not crash flow processing.
            return AnalysisResult(available=False, error=f"{type(e).__name__}: {e}")

        return _parse_llm_response(raw_response)