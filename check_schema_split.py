"""Reports the real schema split in your labelled_flows.db so we know
whether the majority-vote bug in classifier.py's train() is actually
biting you right now, before touching any code.
"""
import yaml
from collections import Counter
from pipeline.labeller import Labeller
from detection.classifier import TRAINING_LABEL_SOURCES
from detection.anomaly import IDENTITY_FIELDS

with open("config.yaml") as f:
    config = yaml.safe_load(f)

labeller = Labeller(config, llm_analyser=None)
samples = labeller.fetch_all()

usable = [s for s in samples if s.label_source in TRAINING_LABEL_SOURCES]
print(f"Total stored samples: {len(samples)}")
print(f"Usable ('llm'-sourced) samples: {len(usable)}")

schema_counts = Counter(
    tuple(sorted(k for k in s.features.keys() if k not in IDENTITY_FIELDS))
    for s in usable
)

print(f"\nDistinct schemas found: {len(schema_counts)}")
for schema, count in schema_counts.most_common():
    has_new_features = all(k in schema for k in ("fwd_packet_share", "ack_ratio", "iat_cv"))
    tag = "CURRENT (has fwd_packet_share/ack_ratio/iat_cv)" if has_new_features else "STALE (pre-fix schema)"
    print(f"  count={count:4d}  [{tag}]  keys={len(schema)}")

canonical_schema, canonical_count = schema_counts.most_common(1)[0]
canonical_is_current = all(k in canonical_schema for k in ("fwd_packet_share", "ack_ratio", "iat_cv"))

print(f"\n>>> train()'s current majority-vote logic would pick the "
      f"{'CURRENT' if canonical_is_current else 'STALE'} schema as canonical.")
if not canonical_is_current:
    print(">>> This CONFIRMS the bug: train() is excluding your new-schema samples right now.")
else:
    print(">>> New-schema samples are already the majority — the existing fix happens to work for you.")
