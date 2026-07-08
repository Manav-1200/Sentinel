"""
test_llm_analyser_manual.py
==============================
A throwaway manual test that calls the REAL NVIDIA NIM (or Anthropic)
API with a simulated attack flow, to verify detection/llm_analyser.py
actually works end-to-end against the live provider.

This is NOT a pytest unit test (those use no real network calls,
by design). This is the one place we genuinely need to hit the real
API to confirm the integration works.

Usage:
    python test_llm_analyser_manual.py
"""

import yaml
from dotenv import load_dotenv
from detection.llm_analyser import LLMAnalyser

# This MUST happen before LLMAnalyser is constructed — it reads .env
# and injects NVIDIA_NIM_API_KEY / ANTHROPIC_API_KEY into the process
# environment. main.py does this automatically at startup; this
# standalone script needs to do it explicitly itself.
load_dotenv()

with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

print(f"Provider: {config['llm']['provider']}")
print(f"Model: {config['llm'][config['llm']['provider']].get('model')}")
print()

analyser = LLMAnalyser(config)

# A simulated SYN-scan-shaped flow, same shape used throughout Phase 1
# testing — this should be a very unambiguous case for the LLM.
attack_features = {
    "src_ip": "10.0.0.99", "dst_ip": "192.168.1.50",
    "src_port": 40000, "dst_port": 22, "protocol": 6,
    "duration_seconds": 0.02, "total_packets": 50,
    "fwd_packets": 50, "bwd_packets": 0,
    "packets_per_second": 2500.0, "bytes_per_second": 150000.0,
    "syn_count": 50, "ack_count": 0, "fin_count": 0, "rst_count": 0,
    "syn_ratio": 1.0, "zero_payload_ratio": 1.0,
    "iat_mean": 0.0004, "iat_std": 0.0001,
}

print("Sending a simulated SYN-scan flow to the LLM for analysis...")
print("(This makes a REAL API call — should take a few seconds.)\n")

result = analyser.analyse(features=attack_features, anomaly_score=-0.1156, verdict="ATTACK")

print("=== Result ===")
print(result)

if result.available:
    print()
    print(f"Attack type: {result.attack_type}")
    print(f"Confidence:  {result.confidence.value}")
    print(f"Reasoning:   {result.reasoning}")
    print()
    print("SUCCESS — the LLM correctly analysed the flow." if result.attack_type in ("port_scan", "syn_flood")
          else "NOTE — got a response, but not the expected attack type. Worth reviewing the reasoning above.")
else:
    print()
    print(f"FAILED — analysis was not available. Error: {result.error}")
    print("Check: is your API key correctly set in .env? Is the provider/model name correct in config.yaml?")