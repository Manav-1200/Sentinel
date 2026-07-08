"""
test_classifier_manual.py
============================
A manual test that trains AttackClassifier on synthetic labelled
data, using the REAL xgboost and scikit-learn installed on this
machine (the sandbox used during development could not install
xgboost, so this is the first genuine end-to-end verification of
the XGBoost code path).

This is NOT a pytest unit test. Run it directly:
    python test_classifier_manual.py
"""

import random

from detection.classifier import AttackClassifier


class FakeSample:
    """Mimics pipeline.labeller.LabelledSample's shape — just the
    fields AttackClassifier.train() actually reads."""
    def __init__(self, label, label_source, features):
        self.label = label
        self.label_source = label_source
        self.features = features


rng = random.Random(42)


def make_port_scan_sample():
    return FakeSample("port_scan", "llm", {
        "total_packets": rng.randint(20, 100),
        "packets_per_second": rng.uniform(1000, 3000),
        "syn_ratio": rng.uniform(0.9, 1.0),
        "zero_payload_ratio": rng.uniform(0.9, 1.0),
        "iat_mean": rng.uniform(0.0001, 0.001),
        "bytes_per_second": rng.uniform(50000, 200000),
    })


def make_ddos_sample():
    return FakeSample("ddos", "llm", {
        "total_packets": rng.randint(500, 5000),
        "packets_per_second": rng.uniform(2000, 10000),
        "syn_ratio": rng.uniform(0.0, 0.2),
        "zero_payload_ratio": rng.uniform(0.0, 0.3),
        "iat_mean": rng.uniform(0.00001, 0.0005),
        "bytes_per_second": rng.uniform(100000, 500000),
    })


def make_benign_sample():
    return FakeSample("benign", "llm", {
        "total_packets": rng.randint(5, 30),
        "packets_per_second": rng.uniform(5, 50),
        "syn_ratio": rng.uniform(0.01, 0.15),
        "zero_payload_ratio": rng.uniform(0.0, 0.3),
        "iat_mean": rng.uniform(0.01, 0.5),
        "bytes_per_second": rng.uniform(500, 5000),
    })


print("Generating 150 synthetic labelled samples (50 each: port_scan, ddos, benign)...")
samples = (
    [make_port_scan_sample() for _ in range(50)]
    + [make_ddos_sample() for _ in range(50)]
    + [make_benign_sample() for _ in range(50)]
)

config = {"detection": {"min_classifier_samples": 100}}
classifier = AttackClassifier(config)

print("Training (this compares RandomForest vs XGBoost)...\n")
result = classifier.train(samples)

print(f"Winning model: {result.winning_model_name}")
print(f"Winning F1 (macro): {result.winning_report.f1_macro:.4f}")
print(f"Losing model: {result.losing_report.model_name}, F1 (macro): {result.losing_report.f1_macro:.4f}")
print(f"Total samples used: {result.total_samples_used}")
print()
print("=== Classification report (winning model) ===")
print(result.winning_report.classification_report_text)

print("=== Confusion matrix (winning model) ===")
print(f"Classes: {result.winning_report.class_labels}")
print(result.winning_report.confusion_matrix)

print()
print("Testing a fresh prediction...")
test_sample = make_port_scan_sample()
predicted_label, probabilities = classifier.predict(test_sample.features)
print(f"True label: port_scan | Predicted: {predicted_label}")
print(f"Probabilities: { {k: round(v, 3) for k, v in probabilities.items()} }")

print()
print("Testing save/load round-trip...")
classifier.save("/tmp/test_classifier.joblib")
fresh = AttackClassifier(config)
fresh.load("/tmp/test_classifier.joblib")
label2, probs2 = fresh.predict(test_sample.features)
assert label2 == predicted_label, "Save/load produced a different prediction!"
print("SUCCESS — save/load round-trip produced an identical prediction.")