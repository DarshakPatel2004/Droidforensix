# DroidForensix Thesis — Final Summary (2026-09-24)

> Four claims, each with evidence. No overclaiming.

---

## Claim 1: Binary Malware Detection — 90.6% Five-Fold CV

**Canonical evidence:** `evaluation/results_summary.txt` §2 and
`evaluation/METHODOLOGY.md` §3.

**Protocol:** 5-fold stratified CV on the 509-row cached feature set; seed 0
for the headline, followed by the pre-declared seeds 0–4 robustness check.

| Metric | Value | Interpretation |
|--------|-------|----------------|
| **Headline CV accuracy** | **90.57%** | Primary current result; seed 0 |
| Seed robustness | 90.56–92.93% | Mean 91.55%; 5/5 seeds at or above 90% |
| In-sample diagnostics | 98.04% (499/509) | FP 0, FN 10; explanation-only, not a generalization claim |
| Historical held-out | 97.0% (194/200) | Pre-`c2_alignment` bundle; lucky split, not the current headline |

**Current model:** `analysis/classify_fast.py` → `malben_rf.pkl` (15 features,
RandomForest). Six raw C2 count/chain features are excluded;
`c2_alignment` is the only C2-derived input. Removing it reduces CV to 89.79%
(-0.79 points).

**Coverage caveat:** persisted domain data exist for 199/509 cache rows, all
malware. No-cache and empty-domain rows score 0.0, and 210/409 malware samples
also score 0.0, so zero does not imply benign. Benign 0.0 is a structural
assumption because the C2 pools are malware-only. Deployment recomputes the
value for every APK, so there is no train/deploy availability gap.

---

## Claim 2: Family Identification — 68.2% Fusion; 62.4% Leakage-Free Scorable

**Canonical evidence:** `evaluation/results_summary.txt` §§1 and 5,
`evaluation/metrics_family_ensemble/metrics.json`, and
`evaluation/VALIDATION_359.md`.

**Same-sample head-to-head (192 scorable rows):**

| Metric | Value | Interpretation |
|--------|-------|----------------|
| Production baseline | 60.42% (116/192) | Canonical comparison baseline |
| **Confidence-fusion ranking** | **68.23% (131/192)** | +7.8 points on the identical subset |
| Precision among answered | 95.45% at bar 0.55; 100% at bar ≥0.60 | Higher bars answer fewer samples |

The gain is concentrated in AndroZoo Drebin (67.69% → 86.15%). It falls on
abuse.ch and modern_eval where static family profiles are missing, so this is
evidence for profile-backed fusion, not universal superiority.

**Leakage-free run 359 (no ground truth consulted during inference):**

| Cut | Rows | Alias-aware accuracy | Interpretation |
|-----|-----:|---------------------:|----------------|
| All rows | 377 | 35.54% (134/377) | Includes catch-all labels and 2 errors |
| **Scorable GT** | **194** | **62.37%** | Primary family-validation headline |
| Catch-all GT | 183 | 7.10% (13/183) | Labels such as AndroidOS/Agent carry no family identity |

Strict exact-match accuracy on the scorable cut is 55.67%. The earlier 72.1%
result on 201 specific-label rows remains reproducible in
`evaluation/metrics_v14/metrics.json`, but it belongs to an older protocol and
is not the current headline. The 409-row audit found that 78.5% of abuse.ch
labels were catch-all, explaining much of the raw/full-set gap.

**Coverage ceiling:** FakeInst/Opfake samples remain statically
indistinguishable in the audited feature set. The confidence fusion should be
read as a profile-coverage system, not a universal family oracle.

**Leakage control:** `evaluation/HOLDOUT_SPLIT.md` freezes a 264/113 dev/holdout
split. Use `--split dev` for tuning and inspect the holdout only at declared
milestones; do not tune against the already observed run-359 rows.

**Honest claim:** *"On the same 192 scorable samples, confidence fusion raises
ranking accuracy from 60.4% to 68.2%. An independent leakage-free run scores
62.4% on 194 scorable-ground-truth rows; raw all-row accuracy is 35.5% because
183 of 377 labels are catch-all categories."*

---

## Claim 3: Static Unpacking — RTO.apk Case Study (Novel Hybrid Method)

**Report:** `thesis/06_unpacking_case_study.md` + `rto_analysis/`

**Sample:** RTO.apk (BeatBanker/BTMOB fake e-challan banker, 8.1 MB, 2026)

| Module | Recovery |
|--------|----------|
| M1 — Packing detection | Stub + native lib + high-entropy asset |
| M2 — Inline decrypt | **7,857 bytes** (57.5%), decoy `hidden.dex` (3.3 KB), AES key `SHA1("myg0N2")[:16]` |
| M2 — Container decrypt | 7.8 MB dropper kit (miner, phishing kit, split APKs, Pine hook) |
| M3 — JNI oracle (`EmulateJni2`) | Resolved `StringBuilder` assembly of key; packer-agnostic (also Ijiami) |
| M3b — PRNG installer strings | **177 unique strings** (C2, mining, Firebase, FCM, xmrig flags) |
| Detection | 8 YARA rules, **0 FP / 540 files** |

**Novelty:** No execution environment assumed. Hybrid of:
1. Listing-level symbolic evaluation (Ghidra script)
2. JNI oracle (shim vtable, logs calls)
3. PRNG string-table reconstruction

**Open boundary (closed 2026-09-18):** Stage-3 live bytecode replay IS reproducible from committed artifacts — `stage3_replay.py` + `cjk_pool.txt` + the installer-strings JSON reproduce 175/180 byte-identical (the 5 residual pairs are documented ground-truth artifacts; the Java harness's 6th `\A` "mismatch" was a JSON-unescaping artifact and now matches). Acceptance test: `tests/test_stage3_replay.py`, spec: `rto_analysis/hole1_czrr_definitive.md` + §6.9.

**Attribution:** Independent corroboration (Ostorlab TV_V_23 writeup — Firebase project, miner naming, App-Key format).

---

## Claim 4: C2 Infrastructure — Tier 2 ASN Reputation (Bounded Value)

**Report:** `docs/c2_tier2_censys.md` + `scripts/c2_tier2_censys.py`

**Enrichment:** 172 unique C2 IPs via Censys (7 cached, 165 new)

| Category | IPs | Signal |
|----------|-----|--------|
| Bulletproof | 4 | Raise (Pfcloud, Tyna Host, SonderCloud, Virtual Systems) |
| Telegram | 9 | Bot-API blocks (C2-over-Telegram) |
| Cloud | 68 | Weak (AWS, Oracle, Zenlayer, etc.) |
| Residential/ISP | 30 | Weak-negative (victim hosts) |
| Other | 61 | Unclear |
| Unresolved | 57 | Private/reserved |

**Retiering impact:** 5 samples drop 1 bulletproof-hosted IP each (negligible on `kept_c2`).

**Historical magnitude:** the original 20-feature model assigned 0.041 importance
to C2, and Tier 2 retiering produced no headline accuracy jump. In the current
15-feature binary model, raw C2 counts are excluded; `c2_alignment` is the only
C2-derived input and removing it costs 0.79 CV points. Tier 2 remains bounded
enrichment rather than the primary detector.

---

## Consolidated Thesis Structure

| Chapter | Topic | Status | Key Evidence |
|---------|-------|--------|--------------|
| 5 | Binary Malware Detection | ✅ Done | 90.6% five-fold CV; 5/5 seeds ≥90% |
| 6 | Custom Packer Unpacking | ✅ Done | RTO.apk: 7.8KB inline, 177 strings, 8 YARA |
| 7 | Family Identification | ✅ Done | 68.2% fusion ranking; 62.4% leakage-free scorable |
| 8 | C2 Tier 2 Reputation | ✅ Done | 4 BP IPs, 9 Telegram, bounded |

---

## Files for Submission

```
thesis/
  06_unpacking_case_study.md      # Chapter 6 (full case study)
  07_families.md                   # Chapter 7 (metrics, audit, ceiling)
  08_c2_tier2.md                   # Chapter 8 (from docs/c2_tier2_censys.md)

evaluation/
  results_summary.txt              # Canonical aggregate results
  METHODOLOGY.md                   # Protocols and reproduction commands
  metrics_binary_ablation.json     # 15-feature CV + ablation artifact
  binary_explanations.json         # 509 in-sample explanation rows
  metrics_family_ensemble/metrics.json  # 192-row fusion comparison
  VALIDATION_359.md                # Leakage-free family validation
  DEV_BASELINE.md                  # Dev-only production-path baseline
  DEV_TUNING_H1.md                 # Predeclared scorer calibration + result
  HOLDOUT_SPLIT.md                 # Frozen 264/113 tuning discipline
  FRESH_CORPUS_PROTOCOL.md         # Fresh-corpus inclusion/exclusion gate
  FRESH_CORPUS_MANIFEST.csv        # Frozen 16-row pilot manifest
  FRESH_CORPUS_RESULT.md           # Pilot static evaluation and limitations
  real_world_accuracy_report.json  # Historical 97% pre-c2_alignment report
  metrics_v14/metrics.json         # Earlier 72.1% specific-label protocol
  metrics_v4/predictions.json      # Canonical predictions for the v14 audit
  clean_family_train.csv           # Legacy full-corpus artifact; 58 holdout overlaps
  family_classifier_clean.pkl      # Legacy model; not split-safe until regenerated from dev

scripts/
  audit_abusech_labels.py          # Abuse.ch VT audit + patch
  c2_tier2_censys.py               # Censys enrichment + Tier 2
  retrain_families_clean.py        # Clean-label retrain
  installer_strings_report.py      # Stage-3 string report

reports/
  abusech_relabel_patch.csv        # 5 relabels applied (2 conflicts resolved)
  c2_tier2_report.csv              # Per-IP ASN classification
  c2_retiering_v2.csv              # Per-sample Tier 2 retiering

rto_analysis/
  stage3.md                        # Algorithm spec + acceptance test
  hole1_czrr_definitive.md         # Smali semantics + 5-artifact table
  PHASE4/5/6_FINDINGS.md           # Raw evidence
  phase2/installer_deobfuscated_strings.tsv  # 177 strings

stage3_replay.py                   # Python byte-exact replay (175/5)
tests/test_stage3_replay.py        # Replay acceptance test
```

---

## Honest Positioning for Defense

| Question | Answer |
|----------|--------|
| "What is the current binary result?" | **90.6% five-fold CV** (seed 0), robust across 5/5 seeds; 97% is a historical pre-feature-change holdout. |
| "Why is raw family validation 35.5%?" | 183/377 labels are catch-all. The scorable-ground-truth headline is **62.4%** on 194 rows. |
| "Why is family accuracy lower than binary?" | Different task: family identification depends on specific labels and profile coverage, not only malware-vs-benign signals. |
| "Does unpacking generalize?" | No — RTO-specific. The hybrid blueprint is the contribution, not a universal unpacker claim. |
| "Does C2 help accuracy?" | Domain alignment helps; raw C2 quantity is weak. Tier 2 reputation has bounded, non-headline impact. |
| "What's the production artifact?" | 15-feature binary detector (**90.6% CV**) + 8 validated YARA rules from the unpacking case study. |

---

## Next Steps (Post-Thesis)

1. ✅ **Adjudicated** the 2 conflicts in `abusech_relabel_patch.csv` (VT second opinion: SpyMax→BankBot, Mirax→Hqwar) → `metrics_v14` computed (2026-09-18)
2. ✅ **Stage-3 bytecode replay** reproduced from committed artifacts — `stage3_replay.py` 175/5 + pytest acceptance (`tests/test_stage3_replay.py`)
3. ✅ **H1 evaluator-only calibration** completed on the complete dev split; production integration remains unapproved
4. **Investigate dev-only profile/signature coverage** on the frozen split; the H2 unknown-fallback integration was rejected (0 new answers)
5. **Build the predeclared 200-row fresh holdout** (100 benign + 100 malware), excluding the scored 20-row pilot; reconcile the model runtime before one-shot scoring
6. **Frida fallback** for runtime string extraction
7. **Expand the benign corpus** with an independent, source-documented sample to test false-positive generalization
