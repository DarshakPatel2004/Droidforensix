# Dev/Holdout Split (v1) — tuning discipline for family validation

Status: **frozen 23-Sep-2026**, seed 42. Membership:
`evaluation/holdout_split_v1.csv` — 377 rows: **dev 264 / holdout 113**.

## Why this exists

The full-corpus run's per-row results are already observed and published in
`evaluation/VALIDATION_359.md`. Any engine change informed by those rows
(signature thresholds, family profiles, heuristics) risks test-set
contamination. This split freezes a holdout **before** the accuracy push.

## Rules

1. Engine tuning iterations run with `--split dev` and are judged on dev
   numbers only.
2. Holdout rows are scored only at declared milestones, and reported
   aggregate-only — no per-row holdout inspection during tuning (do not
   read its failures).
3. Each holdout evaluation is a "look": report it, then go back to dev.
   No per-change holdout peeking.
4. Honest caveat: corpus-level aggregates were observed pre-split
   (`VALIDATION_359.md`), so the split blocks per-row/per-family
   overfitting, not knowledge of corpus-level difficulty. A fresh external
   holdout remains the gold standard for any final thesis claim.

## Contaminated legacy artifact

`evaluation/clean_family_train.csv` and `evaluation/family_classifier_clean.pkl`
were generated before the split and are not dev-only: an aggregate membership
check finds 58 of the clean-training rows in the sealed holdout (138 in dev).
Do not use either artifact for split-safe tuning or report it as a clean
holdout result. Regenerate the training set and model from dev rows only before
any declared tuning milestone.

## Mechanics

- Regenerate (deterministic — seed 42, sorted shuffles, stratified by
  `source × is_catch_all`, the declared scorable cut in
  `analysis/labels.py`):

  ```
  python evaluation/make_holdout_split.py
  ```

- Run a side:

  ```
  python evaluation/run_validation_359.py --split dev -p 4 \
    --output-dir evaluation/validation_359_dev/
  python evaluation/run_validation_359.py --split holdout -p 4 \
    --output-dir evaluation/validation_359_holdout/
  ```

  Default `--split all` = historical full-corpus behavior. A missing split
  file fails loudly (no silent pass-through to full corpus).

## Counts (per source)

| source | dev | holdout |
|---|---|---|
| AndroZoo | 18 | 8 |
| abusech | 85 | 36 |
| androzoo_drebin | 104 | 45 |
| modern_eval | 44 | 19 |
| pendrive | 13 | 5 |
| **total** | **264** | **113** |

## Effective membership after the 6-Oct corpus offload

Membership above is frozen against the 23-Sep 377-row manifest. The 6-Oct
offload (`ff4b752`) moved 54 `modern_eval` rows to `_offload/` and rebuilt
`ground_truth_all.csv` to 323 rows, so 54 frozen rows no longer exist:
**effective dev = 228, holdout = 95** (36 dev + 18 holdout rows offloaded).

`filter_by_split` intersects membership with the manifest **silently**, so the
shrink is invisible at run time. `tests/evaluation/test_family_dev_split.py`
pins the effective counts and the 54-row drift so the next divergence fails
loudly; if the corpus moves again, update those pins and
`evaluation/DEV_BASELINE.md` together. Membership itself is deliberately **not**
re-rolled: regenerating with seed 42 would move previously-sealed rows between
sides, which is exactly what this split exists to prevent.
