# Family Validation — Dev Baseline

Status: **final dev-only run** (24-Sep-2026).

## Protocol

- Dataset: `ground_truth_all.csv`, filtered to the 264 rows marked `dev` in
  `evaluation/holdout_split_v1.csv`.
- Runner: `evaluation/run_validation_359.py`.
- Command:

  ```text
  python evaluation/run_validation_359.py --split dev -p 4 \
    --output-dir evaluation/validation_359/
  ```

- Ground-truth lookup was disabled; pipeline steps 1–9 were retained and steps
  10–18 were skipped.
- Isolated Ollama: `qwen2.5:7b-instruct`.
- The 113-row holdout was not run or inspected.

## Results

- Evaluated: **264/264**, errors: **0**.
- Raw accuracy across all dev labels: **35.98%** (95/264).
- Canonical scorable rows: **136**; catch-all rows: **128**.
- Scorable rows are the denominator for the H1 scorer experiment.

| Source | Rows | Correct | Raw accuracy |
|--------|-----:|--------:|--------------:|
| androzoo_drebin | 104 | 69 | 66.35% |
| abusech | 85 | 1 | 1.18% |
| modern_eval | 44 | 19 | 43.18% |
| AndroZoo | 18 | 6 | 33.33% |
| pendrive | 13 | 0 | 0.00% |

The low abuse.ch and pendrive figures are expected to reflect catch-all labels
and profile coverage gaps; they must not be presented as ordinary specific-
family accuracy without the scorable cut.

## Artifacts

- `evaluation/validation_359/predictions.json` — ignored dev predictions.
- `evaluation/validation_359/validation_report.json` — ignored aggregate report.
- `evaluation/DEV_TUNING_H1.md` — predeclared scorer calibration and result.
- `evaluation/DEV_FUSION_H2.md` — rejected production fallback experiment.
- `evaluation/DEV_PROFILE_H3.md` — profile-gap audit and next-step decision.
- `evaluation/FRESH_CORPUS_RESULT.md` — 16-row external pilot result.
- `evaluation/HOLDOUT_SPLIT.md` — split rules and contaminated-artifact warning.

This baseline is for dev tuning only. It is not a replacement for the
full-corpus historical results and does not authorize a holdout evaluation.
