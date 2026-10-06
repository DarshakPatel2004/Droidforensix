# Formal Fresh-Corpus Target

Status: **predeclared for the next collection milestone** (25-Sep-2026).

## Target

- **200 total APKs**
- **100 benign** from provenance-documented F-Droid or equivalent sources
- **100 malware** from AndroZoo or an equivalent auditable archive
- All rows use `role=holdout`.

The already-scored 20-row pilot is **not** part of this formal target. Its 20
hashes are added to the exclusion set before new collection.

## Freeze rules

1. Collect without inspecting model predictions.
2. Exclude all hashes in the 527-row training/GT union and the 20-row pilot
   (547 total hashes at target start).
3. Require source URL, license/redistribution status, collection date, and role
   for every row.
4. Validate hashes, paths, duplicates, and exclusions.
5. Freeze the manifest and record its SHA-256.
6. Reconcile the scikit-learn runtime with the model pickle version before
   scoring.
7. Run the current 15-feature model once; do not tune from failures.

## Interpretation

The target is intended to estimate external generalization, not to replace the
90.6% cross-validation claim. Report confidence intervals and confusion matrix
by source and label. Any failure analysis must wait until the one-shot result
is recorded.
