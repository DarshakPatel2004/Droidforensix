# Leakage-Free Family Validation — Final Results (`run_validation_359`)

Status: **final, 23-Sep-2026**. Every number below is verified directly against
`evaluation/validation_359/validation_report.json` + `predictions.json`
(gitignored artifacts; regenerate with the command at the bottom).

## Protocol

- Runner: `evaluation/run_validation_359.py`; dataset: `ground_truth_all.csv`
  (377 rows).
- Report field `evaluation_mode = accurate_family_identification_steps_1_9`;
  pipeline steps 10–18 skipped (`skipped_pipeline_steps = [10..18]`).
- Ground truth is never consulted during inference (GT lookup disabled in the
  runner); LLM verdicts come from an isolated Ollama instance
  `qwen2.5:7b-instruct` on `127.0.0.1:11435`, started and stopped by the
  runner; workers: `-p 4`.
- Checkpoint/resume: completed samples are recovered from `predictions.json`
  (atomic write); reruns re-execute only prior failures.
- Correctness matcher: `analysis/labels.py::is_correct` (alias/lineage-aware).
  Scorable cut: `analysis/labels.py::is_catch_all` on the ground-truth label —
  the declared single source of truth; no ad-hoc matching.
- Errors count as wrong in the raw cuts; evaluated-only cuts exclude them.

## Headline results

Alias-aware (`is_correct`) is the primary metric; strict exact-match
(`prediction == ground_truth`) is reported as the conservative floor.

| Cut | n (all / evaluated) | Alias-aware | Strict exact |
|---|---|---|---|
| All rows | 377 / 375 | **0.3554** | 0.3227 (ev) |
| **Scorable GT** (not catch-all) | 194 / 193 | **0.6237** | 0.5567 |
| Catch-all GT (`label_unresolvable`) | 183 / 182 | 0.0710 | 0.0710 |

- Macro precision **0.2868**, macro recall **0.2972** (report `overall`).
- 375 evaluated / 2 errors of 377; correct = 134 alias-aware, 121 exact.
- Alias-vs-exact gap (13 rows) lies entirely inside the scorable cut;
  catch-all scores are identical under both matchers (catch-all predictions
  are exact by construction).

## Per source

| Source | n | Correct | Accuracy |
|---|---|---|---|
| androzoo_drebin | 149 | 99 | **0.6644** |
| modern_eval | 63 | 27 | 0.4286 |
| AndroZoo | 26 | 7 | 0.2692 |
| abusech | 121 | 1 | 0.0083 |
| pendrive | 18 | 0 | 0.0000 (1 error) |

## Miss anatomy (evaluated wrongs: 241; report `failure_count` = 243 incl. 2 errors)

- **62 under_matched** — prediction stayed catch-all (mostly `unknown`)
  while GT was specific. `prediction_counts['unknown'] = 71`; many driven by
  E-coded typed verdicts (`method = e_coded` → `E-NATIVE-NO-RECOVERY` /
  `E-JAVA-RUNTIME-DELIVERY` → `unknown`), i.e. documented capability limits,
  not misclassifications.
- **179 wrong_family** — a specific family was emitted but not the GT one.
- Structural baseline: 183/377 rows carry catch-all GT labels
  (AndroidOS/GenericKD/Agent/Banker/…) that are unresolvable to a family by
  design — these cap any family-level score and are why the scorable cut
  (0.6237) is the honest headline, not the raw 0.3554.

## Pendrive finding (18 rows; paths fixed in `222038c`)

- GT = long-tail dropper/banker families: `FraudDropper`×9, `SMSStealer`×2,
  `TelegramBanker`, `TrojanWhatsAppMod`, `FakeBankApp`, `SpyNote_like`,
  `FakeStoreOps`, `BoithirtyeightBanker_dropper`,
  `FrontierSmartRAT_dropper`.
- Result: **0/17 correct** (1 row is a pipeline-timeout error). Predictions:
  `unknown`×9, Ermac×2, Hydra, MobileTx, ICICI, FakeInstaller.
- Interpretation: a **profile-coverage gap** — the engine has no static
  profile for these families, so it abstains or near-misses. All 18 samples
  ran cleanly (paths, workers, LLM all healthy), so this is a model-coverage
  result, not infrastructure flakiness.
- ⚠ **Leakage warning:** do not tune engine profiles against these answers on
  this same set. Any profile additions informed by `validation_359` ground
  truth require a dev/holdout split before re-evaluating, or the
  leakage-free claim is void.

## Remaining errors (2/377 — systematic, left documented)

1. `1e7276097313eb4ede32eba76886e42696ecd2de41a1a7aeac5536ce717319c0`
   (modern_eval): Step 7 Obfuscation timeout after 180s — **second
   consecutive strike** across runs; systematic for that APK.
2. `0ed420c4f23c50d2eeba330b01cdd72f05bd6f5658b42db1bfb55184a1d02d52`
   (pendrive): whole-pipeline timeout at 620s (limit 600s) — very large APK;
   it cleared path resolution, so `222038c` is proven for it anyway.

Both are capability/timeout limits (0.5% of rows). Raising
`STEP_TIMEOUTS`/`pipeline_timeout` for exactly these two samples would be
special-pleading; left as-is.

## History

- 22-Sep run completed with 20 errors: 18× pendrive `FileNotFoundError`
  (dead `/home/kali/DroidForensix/…` prefixes — corpus had been mirrored
  from the pendrive/Kali tree) + 2× timeouts.
- `222038c`: rewrote the 18 `apk_path`s to project-relative
  `PENDRIVE DATA/…`, verified 18/18 exist.
- 23-Sep rerun: recovered 357 from checkpoint, retried the 20 → 18 new
  successes (17 pendrive + `0a02bda8` timeout retry); 2 systematic errors
  remain (above). Errors 20 → 2.

## Reproduce

```
python evaluation/run_validation_359.py -p 4
```

Writes `predictions.json` (checkpoint) and `validation_report.json` under
`evaluation/validation_359/`; spawns/stops the isolated Ollama instance on
`127.0.0.1:11435`.
