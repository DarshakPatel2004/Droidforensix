# 7. Family Identification: Ceiling, Catch-All Labels, and Abuse.ch Relabeling

> Status: first draft (2026-09-12). Authoritative metrics: `evaluation/metrics_v13/`
> (`metrics.json`, generated 2026-09-09, GT `ground_truth_all_corrected.csv`). Audit
> artifacts: `reports/abusech_label_audit.csv`, `reports/abusech_review_queue.csv`,
> `reports/abusech_relabel_patch.csv`; tooling: `scripts/audit_abusech_labels.py`.

## 7.1 The headline, stated carefully

On the corrected 409-sample corpus, DroidForensix family ID achieves:

| Metric | Value |
|---|---|
| Overall accuracy (409 samples) | 47.2% |
| **Accuracy on specific-labeled families** | **78.1%** (153/196) |
| Specific + confidence >= threshold | 80.0% (136/170) |
| Unknown-refusal correctness | 47.4% (correct when refusing) |

The gap between 47% and 78% is not classifier headroom: it is the **catch-all
label burden**. A sample whose ground-truth family is a vendor-generic label
("AndroidOS", "GenericKD", "Banker") has no family identity to be matched, so it is
scored as a miss. 213 of 409 samples (52%) carry a catch-all ground-truth label.
An older, differently-scoped run reported "64.2% overall"; that figure mixed
specific-family and unknown-abstention scoring rules. The numbers above are the
single version of the truth used in this thesis.

## 7.2 Per-source quality (the abuse.ch problem, quantified)

| Source | n | Specific labels | Specific acc. | Catch-all rate |
|---|---|---|---|---|
| AndroZoo-Drebin | 149 | 87.9% | 86.3% | 12.1% |
| AndroZoo | 76 | 13.2% | 80.0% | 86.8% |
| Modern-eval | 63 | 54.0% | 70.6% | 46.0% |
| **abuse.ch** | 121 | 17.4% | 38.1% | **82.6%** |

The abuse.ch drag is 100/121 (82.6%) vendor-generic labels, led by `AndroidOS`
(28), `GenericKD` (19), `Agent` (13), `Banker` (13), `Gen` (9). These are AV
taxonomy buckets, not families; Family ID is technically correct to decline them,
and the metrics correctly report them as misses.

## 7.3 First audit wave (20 samples, VirusTotal second opinion)

We sampled 20 catch-all abuse.ch rows and queried VirusTotal (per-sample
`last_analysis_results`) plus the existing campaign-cluster proposals
(`reports/label_review_queue.csv`, shared-cert/C2 clustering).

**Relabel evidence recovered:**

| sha256 (12) | GT | Proposal | Source | Verdict |
|---|---|---|---|---|
| `c5544517f1be` | unknown | SpyMax | campaign (shared cert/C2) | accept |
| `b74b65f68641` | Gen | BankBot | VT (`Trojan.AndroidOS.BankBot`) | accept |
| `e4a321eff05a` | HEUR | **BeatBanker** | VT (`HEUR:...BeatBanker.h`) | accept |
| `018f8548c055` | unknown | SpyMax vs BankBot | campaign vs VT | **conflict -> review** |
| `050d91cde706` | AndroidOS | Mirax vs Hqwar | campaign vs VT | **conflict -> review** |
| remaining 15 | GenericKD etc. | none | both sources generic | leave as-is |

**Empirical read:** of the 20 audit samples, only 3 yielded defensible specific
relabels and 2 require adjudication; the dominant `GenericKD.<hash>` family is
*genuinely* generic (Kaspersky's own taxonomy). Extrapolating to all 100 catch-alls,
the recoverable headroom is in the 15–25% band -- not the 35+ pp implied by the raw
82.6% number. Relabeling improves *label quality*; it does not manufacture static
signals for samples that lack them (`thesis_baseline.md` hard wall).

The BeatBanker hit is not coincidence: it is the same family as the RTO.apk case
study (§6), i.e. the relabel audit independently re-encounters the installed national
campaign corpus.

## 7.4 Static-analysis ceiling (unchanged from `thesis_baseline.md`)

- **FakeInst/Opfake cluster (13 samples):** statically indistinguishable --
  zero unique discriminators. Hard wall for signature-based methods.
- **Feature-poor samples (27):** correctly abstain; `unknown` refusal is 47.4% sound.
- **Recoverable families (11):** discriminators operationalized at fp < 1% in
  `analysis/discriminators_36.json`.

## 7.5 Rework deliverables (this iteration)

1. `scripts/audit_abusech_labels.py` -- reproducible audit:
   `--vt` (second opinion, cached in `reports/.vt_abusech_cache.json`),
   `--patch` (emits `reports/abusech_relabel_patch.csv`).
2. `reports/abusech_label_audit.csv` -- all 121 rows, catch-all flags, campaign merges.
3. `reports/abusech_review_queue.csv` -- the 20-sample manual-review queue.
4. `reports/abusech_relabel_patch.csv` -- 3 accepted + 2 conflict relabels.

**Next (human-in-the-loop):** adjudicate the two conflicts, apply the patch to
`ground_truth_all_corrected.csv` with `family_source=relabeled`, and rerun
`evaluation/reeval_families.py` + `metrics_recompute.py` to publish `metrics_v14`.
Expected effect on abuse.ch: catch-all rate 82.6% -> ~75%, specific-accuracy
38.1% -> low 50s%; **materials/appendix text**: +3-5 pp overall, not 10+.

## 7.6 Conclusion

Family ID is at its structural ceiling for signature-based matching (78% on
specific-labeled samples; FakeInst/Opfake + vendor-generic labels are the residual).
The honest thesis claim is: *"78% of malware that carries a family identity is
correctly identified; 82.6% of abuse.ch labels carry no family identity at all."*
That sentence reports clean numbers and a bounded, evidenced relabel plan -- the
defensible position against a reviewer who asks "why is it 47%?"