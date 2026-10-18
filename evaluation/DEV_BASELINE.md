# Family Validation — Dev Baseline

## Current anchor (2026-10-18)

**This is the baseline every A/B delta is stated against.** It is dev-only, and it is
the only per-sample predictions set that matches the current `ground_truth_all.csv`
(323 rows).

| | |
|---|---|
| Dataset | `ground_truth_all.csv` filtered to the `dev` side of `evaluation/holdout_split_v1.csv` — **228 rows** (androzoo_drebin 104, abusech 85, AndroZoo 18, pendrive 13, modern_eval 8) |
| Command | `python evaluation/run_validation_359.py --split dev -p 4 --output-dir evaluation/validation_359_dev/` |
| Code revision | `6e426351` (working tree clean under `analysis/`, `backend/`, `packers/`) |
| Result | evaluated **227/228** (1 error), accuracy **0.3553**, macro-precision **0.2822**, macro-recall **0.2956** |
| Artifacts (gitignored) | `validation_359_dev/predictions.json` (per-sample — **this is the anchor**), `validation_359_dev/validation_report.json` (aggregate), `validation_359_dev/<sha256>/pipeline_result.json` (per sample, 227 of 228) |

| Source | Rows | Correct | Raw accuracy | vs the 24-Sep dev run |
|--------|-----:|--------:|-------------:|---|
| androzoo_drebin | 104 | 68 | 65.38% | 69 — one row drifted |
| abusech | 85 | 1 | 1.18% | unchanged |
| AndroZoo | 18 | 6 | 33.33% | unchanged |
| modern_eval | 8 | 6 | 75.00% | narrowed 44 → 8 |
| pendrive | 13 | 0 | 0.00% | unchanged |
| **total** | **228** | **81** | **35.53%** | |

**This is not comparable to 0.3598**, for two separate reasons:

- The dev row sets differ **only** in `modern_eval` (44 rows then, 8 now). The 36 rows
  the offload removed carried 13 correct predictions, so 0.3598 → 0.3553 is almost
  entirely attrition of a source that scored above the dev average — not a change in
  behaviour.
- `androzoo_drebin` still moved 69 → 68 correct on the *same* 104 rows. That is engine
  or LLM drift across three weeks of changes (packer framework, evidence merge,
  signature edits). The 24-Sep per-sample predictions are gone, so the row cannot be
  identified retroactively — which is exactly why this anchor exists from here on.

The one error row is `0ed420c4…` (pendrive, `FrontierSmartRAT_dropper`): Step 3
(encoding detection) timed out at 600s. Errors count as wrong in the raw cut, the same
convention the historical runs used. The 23-Sep run's other systematic error
(`1e727609…`) is no longer in the corpus.

`filter_by_split` intersects the split with the manifest **silently**, so the effective
dev set fell from 264 to 228 when the 6-Oct corpus offload (`ff4b752`) dropped 54
`modern_eval` rows. `tests/evaluation/test_family_dev_split.py` now pins the effective
counts and the 54-row drift, so the next divergence fails loudly instead of quietly
changing the denominator.

### What each baseline artifact actually is

Filenames do not say this, and two of them are easy to swap by accident:

| Artifact | What it really is | Rows | Accuracy | Per-sample predictions |
|---|---|---|---|---|
| `validation_359_dev/` | **current anchor** (18-Oct), dev side of the 323-row manifest | 228 | see above | yes |
| `validation_359/validation_report.json` | 24-Sep **dev-side** run over the old 377-row manifest (this is what the old "264 rows" figures below came from) | 264 | 0.3598 | no — overwritten |
| `validation_359/validation_report.partial.json` + `predictions.json` | 6-Oct **incomplete full-corpus** run, pre-offload; the anchor that phase 2's delta was computed against | 265 | 0.3547 | yes, but incomplete |
| `evaluation/VALIDATION_359.md` | 23-Sep **full-corpus** run | 377 | 0.3554 | no — overwritten |

## Historical dev-only run (24-Sep-2026, superseded)

Kept as the record of the H1/H2/H3 experiments that consumed it. It no longer matches
the manifest, and its per-sample predictions are gone.

### Protocol

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

### Results

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

### Artifacts

- `evaluation/validation_359/predictions.json` — **not** dev predictions: it is the
  incomplete 6-Oct full-corpus run (265 rows). See the anchor table above.
- `evaluation/validation_359/validation_report.json` — the 24-Sep dev aggregate.
- `evaluation/DEV_TUNING_H1.md` — predeclared scorer calibration and result.
- `evaluation/DEV_FUSION_H2.md` — rejected production fallback experiment.
- `evaluation/DEV_PROFILE_H3.md` — profile-gap audit and next-step decision.
- `evaluation/FRESH_CORPUS_RESULT.md` — 16-row external pilot result.
- `evaluation/HOLDOUT_SPLIT.md` — split rules and contaminated-artifact warning.

This baseline is for dev tuning only. It is not a replacement for the
full-corpus historical results and does not authorize a holdout evaluation.
