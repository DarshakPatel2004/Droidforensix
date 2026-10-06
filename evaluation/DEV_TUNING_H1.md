# Dev Tuning Milestone H1 — Confidence-Bar Calibration

Status: **H1 accepted as an evaluator-only calibration** (24-Sep-2026).

## Scope

Use only the 264 rows marked `dev` in `evaluation/holdout_split_v1.csv`.
The target denominator is the 136 dev rows whose ground-truth family is
scorable under `analysis/labels.py::is_catch_all`. The offline scorer can only
use rows with the required gap-feature cache; any missing rows must be reported
rather than silently dropped.

Freeze all of the following for this milestone:

- `backend/family_id.py` signatures and thresholds;
- `analysis/family_knowledge_base.json`;
- class-count profiles;
- family profile contents;
- `FamilyConfidenceScorer` signal weights and score saturation.

Do not inspect, score, or tune against the 113-row holdout.

## Treatment

- **Baseline:** `FamilyConfidenceScorer.CONFIDENCE_BAR = 0.75`
- **H1:** `FamilyConfidenceScorer.CONFIDENCE_BAR = 0.60`

This is an evaluator/scorer calibration only. `FamilyConfidenceScorer` is not
currently wired into production `identify_family()`, so H1 must not be reported
as a production-path improvement.

## Metrics

Primary: alias-aware accuracy on the 136 scorable dev rows using
`analysis/labels.py::is_correct()`.

Also report:

- strict exact-match accuracy;
- answered coverage;
- precision among answered;
- per-source scorable accuracy;
- transitions from `unknown` to a concrete family.

## Acceptance rule

Accept H1 only if all conditions hold:

1. at least three net additional correct scorable dev rows over the 0.75
   baseline;
2. precision among answered does not decrease;
3. no source loses more than one currently-correct scorable row;
4. no new wrong-family cluster is concentrated in a previously abstained
   family.

If any condition fails, reject H1 without trying another confidence bar.

## Reproduce the evaluator comparison

```text
python evaluation/family_ensemble_eval.py \
  --split dev \
  --gt ground_truth_all.csv \
  --cache evaluation/validation_359/dev_scorer_cache.json \
  --include-missing-as-unknown \
  --bars 0.60,0.75 \
  --output-dir evaluation/validation_359/h1_metrics
```

## Denominator correction

The initial planning note counted 138 scorable dev rows. A recount using the
current canonical `analysis/labels.py::is_catch_all()` yields 136; the
two-row discrepancy is a data-definition correction, not a treatment choice.
The 0.60/0.75 comparison and acceptance rule remain unchanged.

## Complete dev run (accepted evaluator-only)

The complete run used all 136 canonical scorable dev rows. Fifteen rows without
usable scorer input were retained as `unknown`; they were not dropped. The
18 missing retained production predictions were also represented as unknown for
baseline accounting. The result is:

- Cached production baseline: 55.88% (76/136), with missing baseline rows
  counted as unknown.
- Cached scorer ranking at no bar: 69.85% (95/136).
- Scorer at 0.75: 1.47% (2/136), precision among answered 100%.
- Scorer at 0.60: 16.18% (22/136), precision among answered 100%.
- Net change: **+20 correct rows**; no newly answered wrong rows.
- The lower bar added correct answers in the profile-backed dev sources and
  did not remove any answer that was correct at 0.75.

All four acceptance conditions passed. H1 is accepted **only as an additive
FamilyConfidenceScorer calibration**. No production `identify_family()` code,
signature, profile, or knowledge-base artifact was changed; the holdout remains
unscored. The first 118-row partial run is superseded by this complete
136-row result.

## Provenance caveat

The repository's profile and knowledge-base artifacts were mined before the
split. A positive dev result is therefore subject to the existing corpus-level
knowledge caveat; it is not a fresh external validation result.
