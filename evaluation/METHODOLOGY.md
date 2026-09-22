# Evaluation Methodology — DroidForensix

Every number in this document is reproducible from files checked into the repo.
Commands to reproduce each reading are inline. Do **not** copy reading from this
doc into the thesis without re-running the command first (a few early "readings"
in chat logs were in-sample and are explicitly marked as such here).

> **Headline finding (§3):** C2 domain *quantity* is anti-correlated with malice
> in this corpus (corr −0.158; benign median 5 domains vs malware 3). The 11
> high-C2 false negatives are all packed droppers whose observable surface is
> benign-SDK-indistinguishable. Domain *alignment with family profiles*, not
> counts, is the discriminator.

-------------------------------------------------------------------------------

## 1. Ground Truth Sources & Measured Reliability

`ground_truth_all_corrected.csv` (459 rows). Sources: `AndroZoo`, `abusech`
(MalwareBazaar), `androzoo_drebin` (DREBIN), `F-Droid` (benign), `modern_eval`,
`pendrive`.

Reliability is **measured from the GT file itself** — no hand-set constants, no
VT API calls at eval time. Formula (`evaluation/source_aware_eval.py`,
`measured_reliability`), all three ratios in [0,1]:

```
reliability = 0.4 * specific_share        # non-catch-all family labels / total
            + 0.4 * external_confirmation # gt_reason starts vt_consensus|manual_analysis|mb_
            + 0.2 * high_confidence_share # GT confidence == 'high'
```

Reproduce:

```
python evaluation/source_aware_eval.py --gt ground_truth_all_corrected.csv \
    --predictions evaluation/metrics_v2/predictions.json \
    --features evaluation/classifier_data/features.csv
```

Measured (family-join subset, N = predictions matched to GT):

| source          | N  | family acc | spec% | ext% | high% | reliability |
|-----------------|----|-----------:|------:|-----:|------:|------------:|
| androzoo_drebin | 149 | 0.591     | 87.9  | 66.4 | 100.0 | 0.817       |
| abusech         | 120 | 0.058     | 21.7  | 90.8 | 92.5  | 0.635       |
| AndroZoo        |  25 | 0.400     | 40.0  | 72.0 | 72.0  | 0.592       |
| modern_eval     |  58 | 0.500     | 58.6  | 29.3 | 29.3  | 0.410       |

Notes:
- abusech's 0.058 family accuracy is a **label floor, not a model ranking
  failure**: 78.3% of its labels are catch-all categories (AndroidOS, GenericKD)
  with no identity to match, while 90.8% are externally confirmed *as malware*.
  The model's job on those is "unknown" (abstain).
- modern_eval has the **lowest label reliability** (0.410): only 29.3% of rows
  carry external confirmation. Use for diversity, not as a primary family-score
  source.
- Earlier chat figures (androzoo_drebin 0.921, abusech 0.58) used a different
  weighting and are deprecated. The table above is the canonical one.

Weighted family accuracy: raw 0.3807 -> reliability-weighted 0.3981 (+1.7pts).
Frame it as "our score is partly masked by un-verifiable labels", not as an
accuracy gain.

## 2. Family Classification Protocol

Inputs: `evaluation/metrics_v2/predictions.json` (352 repo-retained production
predictions) + `ground_truth_all_corrected.csv`. Matching semantics:
`is_correct` + `ALIASES` from `evaluation/run_validation_359.py`.

Reproduce:

```
python evaluation/family_ensemble_eval.py   # writes evaluation/metrics_family_ensemble/metrics.json
python evaluation/misclassification_analysis.py
python evaluation/metrics_recompute.py --gt ground_truth_all_corrected.csv \
    --predictions evaluation/metrics_v2/predictions.json
```

Canonical numbers:

| metric | value | definition |
|--------|-------|-----------|
| baseline specific accuracy (full repo set) | 0.597 | 120/201 GT-specific samples, production engine |
| baseline (same 192 head-to-head subset)  | 0.6042 | 116/192 |
| fusion ranking accuracy (argmax, no bar)  | **0.6823** | 131/192, +7.8pts vs baseline on the SAME subset |
| androzoo_drebin (n=130) baseline vs fusion | 0.6769 -> **0.8615** | largest source, +18.5pts |
| AndroZoo (n=10)                            | 0.8000 -> 0.8000 | |
| abusech (n=24)                             | 0.2917 -> 0.2083 | families lack static profiles -> abstain |
| modern_eval (n=28)                         | 0.4643 -> 0.2143 | same |

The 192-sample subset = GT-specific AND present in `analysis/gap_features_cache.json`.
All 192 have *specific* GT labels (a catch-all subset is excluded by construction),
so any statement like "on 102/192 specific samples ... 91.2%" is **not reproducible** —
do not write it. The reproducible regime is: ranking 68.2% on the scorable
subset; abstention precision monotone:

| bar  | accuracy | correct | abstained | answered | precision@answered |
|------|:--------:|:-------:|:---------:|:--------:|:------------------:|
| 0.55 | 0.2188   | 42      | 148       | 44       | 0.9545             |
| 0.60 | 0.1875   | 36      | 156       | 36       | 1.0000             |
| 0.65 | 0.1302   | 25      | 167       | 25       | 1.0000             |
| 0.70 | 0.0833   | 16      | 176       | 16       | 1.0000             |
| 0.75 | 0.0521   | 10      | 182       | 10       | 1.0000             |
| 0.80 | 0.0156   | 3       | 189       | 3        | 1.0000             |
| 0.85 | 0.0052   | 1       | 191       | 1        | 1.0000             |

Caveat: the fused absolute confidence scale is compressed, so high bars answer
very few samples. The honest claim is the *monotonic precision@answered*, plus
the ranking lift on profile-covered sources, plus calibrated abstention where no
static profile exists.

Family miss breakdown (`metrics_misclassification/report.json`, baseline
predictions vs corrected GT, 338 GT-joined):

| bucket | n | meaning |
|--------|---|---------|
| label_unresolvable | 137 | GT is a catch-all (abusech 94) — unmatchable, floor |
| under_matched      | 46  | GT specific, pred generic/unknown (abstention) |
| wrong_family       | 35  | GT specific, pred a different specific family — the real ceiling |

Baseline correct 120 on 201 specific rows and 137+46+35=218 misses on the 338
GT-joined rows are mutually consistent (338-218=120).

## 3. Binary Classification Protocol

Deployment model: `evaluation/classifier_data/malben_rf.pkl` (RandomForest,
20 features; features listed by `python analysis/binary_explainer.py --all`).

**Two different accuracy numbers must never be conflated:**

1. In-sample diagnostics on `features.csv` (509 rows = the training cache):
   **0.9568** (487/509, FP 5, FN 17). This is an *explainability* set; the RF was
   fitted on this population, so the number is not a generalization claim.
   `binary_explainer.py` and `source_aware_eval.py` print it as "in-sample".
2. Deployment-grade (from `evaluation/real_world_accuracy_report.json`):
   **200 held-out: 97.0% overall, 0 FN, 6% FP; 5-fold CV ~90.8%**. Independent
   5-fold CV re-run on the 509 cache (seed 0): **0.8920**.

Thesis section must cite (2) as accuracy and (1) only for per-prediction
explanations / FN-FP anatomy.

### Ablation (5-fold StratifiedCV, refit per fold, seed 0)

```
python evaluation/cv_ablation.py
```

Results (verified 19-Sep-2026):
| removed feature       | CV acc | Δ vs baseline |
|-----------------------|:------:|:-------------:|
| none (baseline)       | 0.8920 | —             |
| num_permissions       | 0.8841 | -0.0078       |
| num_dangerous_perms   | 0.8861 | -0.0059       |
| decompiled_classes    | 0.8881 | -0.0039       |
| native_libs_found     | 0.8880 | -0.0040       |
| file_size_kb          | 0.8880 | -0.0040       |
| total_strings         | 0.8919 | -0.0000       |
| num_c2                | 0.8939 | +0.0020       |
| num_c2_fb_ip          | 0.8939 | +0.0020       |
| **all 3 C2 features** | 0.8959 | **+0.0040**   |

Reading: permission/structural features carry the signal; **dropping all C2
counts improves CV** — raw C2 count is noise/harmful here. Do NOT publish the
sketched "−3.54 / −1.79 / −0.82 / −0.17" table from earlier notes; it is an
in-sample artifact, not this ablation.

### The C2 finding (locked, reproducible)

```
# analysis: corr(P(malware), num_c2) = -0.158
# median num_c2: benign (F-Droid) 5 > malware 3
# FN (n=17): median num_c2 12; 11/17 have >=5 C2 domains
```

Interpretation: benign apps embedding analytics/ad SDKs carry *more* plaintext
domains than the malware population. High-C2 malware (packed droppers with junk
domains) therefore sits on the benign side of the C2-count axis. The model is not
"undetaching C2" — it has learned the corpus property that C2 *quantity* leans
benign. C2 *quality* (real-vs-private, domains per family signature) is the
discriminator, which the family fusion uses via c2_alignment (profile.domain in
sample). Two-pass recommendation: keep structure-only for high-confidence
malicious (C2 count can't help), use C2-alignment only inside family fusion.

### Confidence thresholds (in-sample, on the 409 malware + 100 benign cache)

| threshold (P(mal)) | FP remaining | TP retained |
|:------------------:|:------------:|:-----------:|
| 0.50 | 5 (100%) | 392/409 (95.8%) |
| 0.75 | 1 (20%)  | 335/409 (81.9%) |
| 0.85 | 0 (0%)   | 278/409 (68.0%) |
| 0.90 | 0 (0%)   | 238/409 (58.2%) |

The "0.85 kills all FP keeping 98% TP" claim is **not reproducible** — at 0.85
you keep 68.0% of TPs. If the thesis wants that operating point, it must cite
68.0%, not 98%.

## 4. Explainability & Miss Anatomy

```
python analysis/binary_explainer.py --all             # -> evaluation/binary_explanations.json
python analysis/binary_explainer.py --sha <sha256>    # one sample
python analysis/binary_explainer.py --top-misses 10
python evaluation/misclassification_analysis.py       # -> metrics_misclassification/report.json
```

- FP = 5, all F-Droid benign apps with elevated dangerous-permission counts
  (device managers / ROM flashers) that mimic malware structure.
- FN = 17: abusech 10, AndroZoo 5, androzoo_drebin 1, modern_eval 1. 11/17 have
  >=5 C2 domains — see the C2 finding above.
- Every explanation row carries feature_values + top-5 signals with per-family
  median contrast.

## 5. Reproducibility Checklist (for the thesis appendix)

```
python -m pytest tests/analysis/test_family_confidence_scorer.py \
                  tests/evaluation/test_misclassification.py \
                  tests/analysis/test_labels.py -v
python evaluation/family_ensemble_eval.py
python evaluation/source_aware_eval.py
python evaluation/misclassification_analysis.py
python analysis/binary_explainer.py --all
python evaluation/cv_ablation.py        # 5-fold binary ablation table
```

Checklist:
- [ ] `metrics_v2/predictions.json` and `ground_truth_all_corrected.csv` are in
      the repo (both are).
- [ ] scorer is an additive evaluator; `backend/family_id.py` `identify_family`
      is unchanged.
- [ ] 192-sample head-to-head is the same sample set for baseline and fusion.
- [ ] Abstention bar is a tunable parameter (sweep table above).
- [ ] Binary: held-out/CV for the accuracy claim; 509-cache numbers labeled
      "in-sample".