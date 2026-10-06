# Fresh Corpus Pilot — Static Binary Evaluation

Status: **completed pilot; not a thesis headline** (25-Sep-2026).

## Frozen input

- Manifest: `evaluation/FRESH_CORPUS_MANIFEST.csv`
- Manifest SHA-256: `f47ae4da9bc2219ed0062769b2b003b5b58fa6ee2b3e48cee96ad1a8bc53dbac`
- Samples: **20** total — 10 F-Droid benign, 10 AndroZoo malware.
- Existing exclusion hashes: **527**; overlap: **0**.
- Collection date: 25-Sep-2026.
- Binaries remain under ignored `data/fresh_corpus/`.

## Protocol

- Model: `evaluation/classifier_data/malben_rf.pkl` (15 features).
- Pipeline: `classify_malware_fast`, steps 1–6, no LLM.
- No APK installation, execution, or emulation.
- All rows had `role=holdout` in the manifest and were not used for tuning.

## Aggregate result

| Metric | Result |
|--------|--------|
| Samples | 20 |
| Pipeline errors | 0 |
| Overall accuracy | 55.00% (11/20) |
| True positives | 6 |
| False negatives | 4 |
| True negatives | 5 |
| False positives | 5 |
| Malware recall | 60.00% (6/10) |
| Benign specificity | 50.00% (5/10) |
| Malware precision | 54.55% (6/11) |

The small pilot is intentionally not used to retune the model. The result is
an external smoke test, not a replacement for a powered holdout.

## Caveats

- Twenty samples, split evenly by source, are insufficient for a stable
  estimate.
- The AndroZoo collection required a retry after transient rate-limit/DNS
  failures; the successful samples are not a representative malware
  distribution. A provider credential appeared in transient request-error
  output; rotate it before any future retry.
- F-Droid provides provenance and licenses but not a malware-family ground
  truth.
- The environment emitted the existing scikit-learn pickle-version warning
  (model serialized with 1.8.x, environment 1.9.x). Treat the result as
  provisional until the pinned runtime is reconciled.
- No profile, threshold, signature, or model update is authorized by this
  pilot.

## Next gate

Expand the manifest with additional independently collected samples, rerun the
validator, and predeclare the target count before treating the result as a
formal external holdout. Do not inspect or tune against pilot failures.
