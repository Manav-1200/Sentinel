# Database Retention & Rotation Policy

## Status

Design proposal — not yet implemented. Table/column names below are
inferred from `detection/evidence.py`'s docstrings and `api/app.py`'s
comments (which confirm at least an `evidence` table exists), not from
reading `pipeline/labeller.py` or the actual schema directly — that file
wasn't available this session. **Verify actual table/column names
against the real schema before implementing any of the deletion logic
below.**

## Why this is needed

Sentinel's SQLite DB accumulates data with no upper bound today:

- Every piece of `Evidence` any detector produces gets persisted (see
  `api/app.py`'s docstring: "the same one already going into the
  `evidence` DB table").
- Labelled flow samples accumulate for classifier training — this is
  the same data that was entirely lost in the Arch reinstall (706+
  samples gone), which is itself a hint that this DB currently has no
  backup/rotation story at all, just a single growing file.
- `observability/structured_logger.py` already has its own bounded
  rotation (`RotatingFileHandler`, max_bytes/backup_count) — but that
  only bounds the JSON-lines log file, explicitly NOT the SQLite DB
  (see that module's docstring: "it doesn't address the SQLite DB's
  unbounded growth, which is a separate, larger piece of work" — this
  doc is that separate piece of work).

Left alone, a long-running deployment's DB grows forever, disk usage
becomes unpredictable, and (relevant for the corroboration wiring)
old, low-value data ends up query-competing with recent, actionable
data — the operational cost of never deleting anything.

## What must NEVER be deleted by an automated policy

- **Anything a currently-open Incident still needs.** An incident stays
  OPEN indefinitely (`correlation_engine.py`'s explicit "incidents never
  auto-close" design) — if retention deleted the Evidence rows behind an
  open incident, `get_techniques_for_incident()`, `risk_engine.assess()`,
  and `timeline.render_timeline_text()` would all silently start
  returning incomplete results for a still-active case. Retention must
  check incident status before touching evidence rows, not just row age.
- **Training samples actively needed by the classifier.** Per your own
  recent decision, classifier data accumulates organically as the
  primary strategy — an aggressive retention policy that deletes
  "old" labelled samples would directly undermine the exact thing that
  decision was trying to protect. Training data retention should be
  treated as a distinct, much longer-lived tier from operational
  evidence (see tiers below).
- **Resolved incidents that fall inside any compliance/audit retention
  requirement** you may adopt later — this doc defines defaults, not a
  legal minimum; if Sentinel is ever deployed somewhere with a real
  compliance retention requirement (e.g. "keep 1 year of security
  incident records"), that requirement overrides these defaults, not
  the other way around.

## Proposed retention tiers

| Data | Default retention | Rationale |
|---|---|---|
| Raw `evidence` rows tied to a **resolved** incident | 90 days after resolution | Forensic value drops sharply once an incident is closed and any immediate follow-up window has passed; 90 days covers a realistic "someone asks about this a season later" case. |
| Raw `evidence` rows tied to an **open** incident | Never (until resolved, then the 90-day clock above starts) | See "must never be deleted" above. |
| `evidence` rows with `verdict=NORMAL` (if `log_normal`-style verbose logging is ever enabled for evidence, mirroring `detection/logger.py`'s existing `log_normal` flag for the detection log) | 7 days | Bulk, low-value-per-row data; short retention keeps it useful for near-term debugging without it dominating DB size. |
| Classifier training samples (labelled flows) | Indefinite by default, size-capped instead of time-capped (see below) | Matches the "organic accumulation as primary strategy" decision — deleting by AGE would work against training data that's already scarce for some classes. |
| Structured JSON-lines event log | Already handled — `structured_logger.py`'s own `RotatingFileHandler` | Out of scope for this doc; noted for completeness only. |

### Why training samples get a size cap, not a time cap

Time-based deletion assumes "older is less valuable," which is backwards
for training data — an old sample of a rare attack class (e.g. an early
brute-force sample from before the tracker existed) may be MORE valuable
than a recent one precisely because rare-class samples are still thin
(the documented classifier data-shortage problem). Recommend instead:
a configurable maximum row count per class
(`retention.max_training_samples_per_class`, e.g. 5,000), with the
OLDEST samples in an over-cap class pruned first, only once that class
has enough samples that losing the oldest ones stops mattering. This
needs the actual schema to implement correctly (is there a `label`/
`attack_type` column to group by? confirm against real
`pipeline/labeller.py` before writing this query).

## Rotation mechanism

Given SQLite (not a server-based DB with built-in partitioning), the
practical mechanism is:

1. A scheduled maintenance pass (`pipeline/retention.py`, new module) run
   periodically — either from a cron-style scheduler if one gets added
   later, or, simpler and requiring no new infrastructure, triggered
   from `main.py`'s own loop every N flows/minutes, the same "do
   periodic housekeeping inline" pattern `cli_display.py` already uses
   for its own summary-line cadence (`_SUMMARY_EVERY_N_FLOWS`).
2. `DELETE FROM evidence WHERE ...` in small batches (e.g. 500 rows at a
   time, looped), not one giant `DELETE` — a single huge delete on a
   live SQLite file can hold a lock long enough to visibly stall the
   main detection loop if it's writing to the same file concurrently,
   which it is (this is the same class of concern that makes SQLite a
   flagged scale limitation elsewhere in the enterprise-readiness
   discussion).
3. `VACUUM` after a deletion pass to actually reclaim disk space —
   SQLite doesn't shrink the file on `DELETE` alone. `VACUUM` rewrites
   the whole file, so it should run relatively rarely (e.g. once a day,
   not after every small batch), and never while the capture pipeline
   might be actively writing — needs a brief coordination point with
   `main.py` (e.g. only run it when the flow-processing loop is
   between flows, not mid-write).
4. All thresholds config-driven under a new `retention:` section in
   `config.yaml`, matching every other Sentinel subsystem's
   config-fallback convention (`resolved_incident_evidence_days`,
   `normal_evidence_days`, `max_training_samples_per_class`,
   `vacuum_interval_hours`).

## What this doc deliberately does NOT decide

- The exact SQL/schema-touching implementation — blocked on actually
  reading `pipeline/labeller.py`'s real table definitions first.
- Whether retention ever needs to run as a genuinely separate process
  instead of inline in `main.py` — inline is proposed as the simpler
  starting point; a separate process would only be justified once
  `VACUUM`'s brief exclusive-lock requirement becomes a real operational
  problem at higher flow volumes than currently tested.
- Backup strategy (a retention policy decides what to DELETE; it says
  nothing about whether deleted/aging data should be archived somewhere
  first — e.g. exported via `reporting/incident_report.py`'s CSV export
  before a resolved incident's evidence ages out). Worth deciding
  separately: should the 90-day resolved-incident window auto-export a
  CSV/Markdown report before deletion, so the DELETE isn't also the last
  time that data exists anywhere? Leaning yes, but flagging as a
  follow-up decision rather than assuming it here.

## Next step before implementation

Upload `pipeline/labeller.py` (and whatever module actually defines the
DB schema/creates the tables, if that's a separate file) so the batch
`DELETE` queries and the training-sample size-cap logic above can be
written against real column names instead of the inferred ones in this
doc.
