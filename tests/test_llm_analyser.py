"""
tests/test_llm_analyser.py
=============================
Unit tests for detection/llm_analyser.py. Deliberately makes NO real
network calls — tests prompt construction, response parsing, and
rate limiting in isolation. The real end-to-end API integration is
verified separately via test_llm_analyser_manual.py (a manual script,
not part of the automated suite, since it requires a real API key
and makes real network calls).
"""

import pytest

from detection.llm_analyser import (
    _build_prompt,
    _parse_llm_response,
    _RateLimiter,
    AnalysisConfidence,
    AnalysisResult,
    KNOWN_ATTACK_TYPES,
    LLMAnalyser,
)


SYN_SCAN_FEATURES = {
    "protocol": 6, "src_ip": "10.0.0.99", "src_port": 40000,
    "dst_ip": "192.168.1.50", "dst_port": 22,
    "duration_seconds": 0.02, "total_packets": 50,
    "fwd_packets": 50, "bwd_packets": 0,
    "packets_per_second": 2500.0, "bytes_per_second": 150000.0,
    "syn_count": 50, "ack_count": 0, "fin_count": 0, "rst_count": 0,
    "syn_ratio": 1.0, "zero_payload_ratio": 1.0,
    "iat_mean": 0.0004, "iat_std": 0.0001,
}


class TestPromptConstruction:

    def test_prompt_includes_protocol_name(self):
        prompt = _build_prompt(SYN_SCAN_FEATURES, -0.1156, "ATTACK")
        assert "TCP" in prompt

    def test_prompt_includes_key_ratios(self):
        prompt = _build_prompt(SYN_SCAN_FEATURES, -0.1156, "ATTACK")
        assert "1.00" in prompt  # syn_ratio formatted to 2 decimals

    def test_prompt_includes_verdict_and_score(self):
        prompt = _build_prompt(SYN_SCAN_FEATURES, -0.1156, "ATTACK")
        assert "ATTACK" in prompt
        assert "-0.1156" in prompt

    def test_prompt_requests_json_output(self):
        prompt = _build_prompt(SYN_SCAN_FEATURES, -0.1156, "ATTACK")
        assert "JSON" in prompt

    def test_prompt_lists_known_attack_types(self):
        prompt = _build_prompt(SYN_SCAN_FEATURES, -0.1156, "ATTACK")
        for attack_type in KNOWN_ATTACK_TYPES:
            assert attack_type in prompt

    def test_prompt_omits_tcp_flags_for_non_tcp(self):
        udp_features = dict(SYN_SCAN_FEATURES)
        udp_features["protocol"] = 17
        prompt = _build_prompt(udp_features, -0.05, "SUSPICIOUS")
        assert "TCP flags seen" not in prompt


class TestResponseParsing:

    def test_parses_well_formed_json(self):
        response = '{"attack_type": "port_scan", "confidence": "high", "reasoning": "High SYN ratio."}'
        result = _parse_llm_response(response)
        assert result.available is True
        assert result.attack_type == "port_scan"
        assert result.confidence == AnalysisConfidence.HIGH
        assert result.reasoning == "High SYN ratio."

    def test_strips_markdown_code_fence(self):
        response = '```json\n{"attack_type": "ddos", "confidence": "medium", "reasoning": "test"}\n```'
        result = _parse_llm_response(response)
        assert result.available is True
        assert result.attack_type == "ddos"

    def test_strips_plain_code_fence_without_json_tag(self):
        response = '```\n{"attack_type": "benign", "confidence": "low", "reasoning": "test"}\n```'
        result = _parse_llm_response(response)
        assert result.available is True
        assert result.attack_type == "benign"

    def test_malformed_json_returns_unavailable_not_a_crash(self):
        response = "I think this looks like a port scan based on the SYN ratio."
        result = _parse_llm_response(response)
        assert result.available is False
        assert result.error is not None

    def test_unrecognised_attack_type_is_rejected(self):
        """
        Critical: the LLM must not be able to introduce arbitrary,
        unvalidated labels into the training data. A made-up label
        that isn't in KNOWN_ATTACK_TYPES must be rejected, not
        silently accepted.
        """
        response = '{"attack_type": "something_the_llm_made_up", "confidence": "high", "reasoning": "test"}'
        result = _parse_llm_response(response)
        assert result.available is False

    def test_unrecognised_confidence_falls_back_to_unknown(self):
        # A bad/missing confidence value shouldn't fail the whole
        # parse — just falls back to UNKNOWN, since attack_type is
        # the more important field for training data.
        response = '{"attack_type": "port_scan", "confidence": "very sure!!", "reasoning": "test"}'
        result = _parse_llm_response(response)
        assert result.available is True
        assert result.confidence == AnalysisConfidence.UNKNOWN

    def test_missing_reasoning_field_does_not_crash(self):
        response = '{"attack_type": "port_scan", "confidence": "high"}'
        result = _parse_llm_response(response)
        assert result.available is True
        assert result.reasoning is None


class TestRateLimiter:

    def test_allows_calls_up_to_limit(self):
        limiter = _RateLimiter(max_calls_per_minute=3)
        results = [limiter.allow_call() for _ in range(3)]
        assert results == [True, True, True]

    def test_blocks_calls_beyond_limit(self):
        limiter = _RateLimiter(max_calls_per_minute=3)
        for _ in range(3):
            limiter.allow_call()
        assert limiter.allow_call() is False

    def test_window_slides_and_frees_up_capacity(self, monkeypatch):
        import detection.llm_analyser as llm_module

        fake_time = [1000.0]
        monkeypatch.setattr(llm_module.time, "time", lambda: fake_time[0])

        limiter = _RateLimiter(max_calls_per_minute=2)
        assert limiter.allow_call() is True
        assert limiter.allow_call() is True
        assert limiter.allow_call() is False

        # Advance time by 61 seconds — the old calls should be
        # outside the 60-second window now, freeing up capacity.
        fake_time[0] += 61.0
        assert limiter.allow_call() is True


class TestLLMAnalyserShouldAnalyse:
    """
    Tests the should_analyse() threshold check, which is a SEPARATE,
    stricter gate than the anomaly detector's own SUSPICIOUS/ATTACK
    thresholds — see config.yaml's llm.min_score_for_analysis comment.
    """

    @pytest.fixture
    def llm_config(self):
        return {
            "llm": {
                "provider": "nim",
                "nim": {"base_url": "https://example.com", "model": "test-model"},
                "anthropic": {"model": "test-model"},
                "min_score_for_analysis": -0.03,
                "max_calls_per_minute": 20,
                "timeout_seconds": 10,
            }
        }

    def test_score_below_threshold_should_analyse(self, llm_config):
        analyser = LLMAnalyser(llm_config)
        assert analyser.should_analyse(-0.05) is True

    def test_score_above_threshold_should_not_analyse(self, llm_config):
        analyser = LLMAnalyser(llm_config)
        assert analyser.should_analyse(-0.01) is False

    def test_invalid_provider_raises_at_construction(self, llm_config):
        llm_config["llm"]["provider"] = "not_a_real_provider"
        with pytest.raises(ValueError):
            LLMAnalyser(llm_config)