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

## Mechanics

- Regenerate (deterministic — seed 42, sorted shuffles, stratified by
  `source × is_catch_all`, the declared scorable cut in
  `analysis/labels.py`):

  ```
  python evaluation/make_holdout_split.py
  ```

- Run a side:

  ```
  python evaluation/run_validation_359.py --split dev -p 4
  python evaluation/run_validation_359.py --split holdout -p 4
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
