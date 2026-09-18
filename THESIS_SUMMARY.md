# DroidForensix Thesis — Final Summary (2026-09-12)

> Three claims, each with evidence. No overclaiming.

---

## Claim 1: Binary Malware Detection — 97% Real-World Accuracy

**Report:** `evaluation/real_world_accuracy_report.json`  
**Test:** 100 fresh MalwareBazaar malware + 100 F-Droid benign (completely unseen)

| Metric | Value |
|--------|-------|
| Overall accuracy | 97.0% (194/200) |
| False negative rate | **0.0%** (0/100 malware) |
| False positive rate | 6.0% (6/100 benign) |
| Precision (malware) | 94.3% |
| Recall (malware) | 100% |
| F1 score | 0.971 |

**FP details:** 6 high-permission/network apps (F-Droid client, password generator, XMPP client, WiFi setup, acrylic paint app, AAT app) — all legit. Tier 3 allowlist reduced FP from 11.8% (lab) to 6.0%.

**Pipeline:** `analysis/classify_fast.py` → `malben_rf.pkl` (20 features, RandomForest)

---

## Claim 2: Family Identification — 72% on Specific-Labeled Samples

**Report:** `thesis/07_families.md` + `evaluation/metrics_v14/metrics.json`

| Metric | Value |
|--------|-------|
| Overall (409 samples) | 44.7% |
| **Specific families only (201 samples)** | **72.1%** |
| High-confidence specific (174) | 73.6% |
| Unknown refusal correctness (74) | 46.0% |

**The catch-all problem:** 51% of samples carry vendor-generic labels (`AndroidOS`, `GenericKD`, `Agent`, `Banker`). Abuse.ch is 78.5% catch-all.

**Audit/rework:**
- `scripts/audit_abusech_labels.py` — VT second opinion + campaign clustering
- `reports/abusech_relabel_patch.csv` — 5 relabels applied (BankBot x2, Hqwar, SpyMax, BeatBanker); 2 campaign-vs-VT conflicts resolved via VT second opinion (SpyMax→BankBot, Mirax→Hqwar)
- `evaluation/metrics_v14/metrics.json` — recompute on the corrected GT with the canonical committed predictions (`evaluation/metrics_v4/predictions.json`)
- Clean-label retrain: **62.2% CV** (vs 47.2% with all labels) — +15pp

> Note on the 78.1%→72.1% delta vs metrics_v13: v13's predictions
> (`predictions_v12.json`) lived in an ephemeral temp dir and is no longer
> recoverable; v14 recomputes from the only surviving full-run predictions file
> (v4) and the current GT. The drop combines that baseline swap with 5
> abuse.ch catch-alls now relabeled to specific families (196→201).

**Ceiling:** FakeInst/Opfake cluster statically indistinguishable (0 unique discriminators). Hard wall for signature-based methods.

**Honest claim:** *"72% of malware that carries a family identity is correctly identified; 78.5% of abuse.ch labels carry no family identity at all."*

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

**Honest magnitude:** C2 importance = 0.041. Tier 2 cleans IP-direct C2 slice but no headline accuracy jump. Documented as evidence of bounded value.

---

## Consolidated Thesis Structure

| Chapter | Topic | Status | Key Evidence |
|---------|-------|--------|--------------|
| 5 | Binary Malware Detection | ✅ Done | 97% real-world, 0% FN |
| 6 | Custom Packer Unpacking | ✅ Done | RTO.apk: 7.8KB inline, 177 strings, 8 YARA |
| 7 | Family Identification | ✅ Done | 72% specific, abuse.ch audit, ceiling |
| 8 | C2 Tier 2 Reputation | ✅ Done | 4 BP IPs, 9 Telegram, bounded |

---

## Files for Submission

```
thesis/
  06_unpacking_case_study.md      # Chapter 6 (full case study)
  07_families.md                   # Chapter 7 (metrics, audit, ceiling)
  08_c2_tier2.md                   # Chapter 8 (from docs/c2_tier2_censys.md)

evaluation/
  real_world_accuracy_report.json  # 97% binary detector
  metrics_v14/metrics.json         # Family metrics (authoritative)
  metrics_v4/predictions.json      # Canonical per-sample predictions (v14 baseline)
  clean_family_train.csv           # Clean-label retrain data
  family_classifier_clean.pkl      # Clean-label model (62.2% CV)

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
| "Why 44% family?" | 51% catch-all labels. On specific-labeled: **72%**. |
| "Why not 97% family?" | Different task. Binary = malware vs benign. Family = which clan. |
| "Does unpacking generalize?" | No — RTO-specific. Hybrid blueprint is the contribution, not universal unpacker. |
| "Does C2 help accuracy?" | C2 importance 0.041. Tier 2 cleans slice but no headline jump. Documented honestly. |
| "What's the production artifact?" | Binary detector (97%, 0% FN) + YARA rules from unpacking. |

---

## Next Steps (Post-Thesis)

1. ✅ **Adjudicated** the 2 conflicts in `abusech_relabel_patch.csv` (VT second opinion: SpyMax→BankBot, Mirax→Hqwar) → `metrics_v14` computed (2026-09-18)
2. ✅ **Stage-3 bytecode replay** reproduced from committed artifacts — `stage3_replay.py` 175/5 + pytest acceptance (`tests/test_stage3_replay.py`)
3. **Frida fallback** for runtime string extraction
4. **Expand benign corpus** to 200 Play Store apps (reduce FP further)