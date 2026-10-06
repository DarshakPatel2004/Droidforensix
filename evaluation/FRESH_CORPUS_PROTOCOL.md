# Fresh Corpus Acquisition and Validation Protocol

Status: **pilot manifest frozen; not approved as a formal thesis holdout** (25-Sep-2026).

This protocol defines the minimum evidence required before any new APK is used
as a current-model holdout or independent benign evaluation set.

## Manifest schema

Use `evaluation/FRESH_CORPUS_MANIFEST.csv` with these required columns:

| Column | Meaning |
|---|---|
| `sha256` | Lowercase SHA-256 computed from the APK bytes |
| `path` | Repository-relative path to the APK |
| `label` | `malware` or `benign` |
| `role` | `holdout` or `development` |
| `source` | Human-readable collection/source name |
| `source_url` | Reproducible upstream URL or archive identifier |
| `license` | Upstream license or redistribution permission |
| `collected_at` | ISO date/time of acquisition |
| `notes` | Selection, adjudication, or exclusion rationale |

`role=holdout` rows must not be used for profile mining, threshold selection,
or model tuning. They are scored only after the manifest and protocol are
frozen.

## Exclusion gate

Before freezing a manifest, exclude every SHA-256 present in:

- `evaluation/classifier_data/features.csv` (current binary training cache);
- `ground_truth_all_corrected.csv` (broad family/GT manifest);
- `evaluation/holdout_split_v1.csv` (sealed family holdout membership).

Also exclude duplicate APK hashes within the candidate set. Use computed file
hashes, never filename matching.

Run the validator:

```text
python scripts/validate_fresh_corpus.py \
  --manifest evaluation/FRESH_CORPUS_MANIFEST.csv \
  --exclude evaluation/classifier_data/features.csv \
  --exclude ground_truth_all_corrected.csv \
  --exclude evaluation/holdout_split_v1.csv
```

A final manifest must have no missing paths, hash mismatches, duplicate hashes,
excluded overlaps, or blank provenance fields. The validator reports aggregate
counts only; it does not score the samples.

## Current local candidates

The existing `benign_eval`, `engine_apps`, `fresh_mb`, uploads, and pendrive
pools are not fresh final holdouts. They have incomplete provenance, prior
observation, tuning overlap, or historical scoring. They may be used only for
development diagnostics after explicit labeling.

The formal target is specified in `evaluation/FRESH_CORPUS_TARGET.md`:
200 total samples, with the scored 20-row pilot excluded.

## Evaluation gate

After a manifest passes validation:

1. record the frozen manifest hash and evaluator command;
2. evaluate the current 15-feature binary bundle without retraining;
3. report aggregate results by label/source;
4. keep the family holdout separate and sealed;
5. do not add failures to profiles or thresholds after scoring.

The current 16-row manifest is a completed pilot only. It must not be used
for model tuning or reported as a powered holdout result.

Collection errors must be redacted before logging. If a provider credential
appears in transient error output, rotate it before retrying.
