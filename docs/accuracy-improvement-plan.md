# APK Identification Accuracy Improvement Plan

**Project:** DroidForensix  
**Date:** 2026-08-29 (wired 2026-08-30 with Master Key + KT)  
**Scope:** `is_malicious` (malicious vs benign) and `family` identification  
**Dataset:** 405 APKs (305 malware + 100 benign) — `ground_truth_all_corrected_100legit.csv:1`  
**Pipeline:** 18 steps `analysis/pipeline.py:59` + `backend/family_id.py:1` + **Phase 0 Master Key** `analysis/step0_master_key.py:1` (wires `docs/MASTER_KEY_STRATEGY.md` + `docs/FULL_KNOWLEDGE_TRANSFER.md`)

---

## Table of Contents
0. [Phase 0 — Master Key + KT Wiring (wired 2026-08-30)](#0-phase-0--master-key--kt-wiring-wired-2026-08-30)
1. [Baseline Metrics](#1-baseline-metrics)
2. [Root Cause Analysis](#2-root-cause-analysis)
3. [Phase 1 — Quick Wins (1–2 weeks)](#3-phase-1--quick-wins-12-weeks)
4. [Phase 2 — Medium Term (1–2 months)](#4-phase-2--medium-term-12-months)
5. [Phase 3 — Long Term (3–6 months)](#5-phase-3--long-term-36-months)
6. [Detailed File-Level Change Spec](#6-detailed-file-level-change-spec)
7. [Data Strategy](#7-data-strategy)
8. [Evaluation & Verification](#8-evaluation--verification)
9. [Success Criteria](#9-success-criteria)
10. [Risks & Mitigations](#10-risks--mitigations)
11. [Appendix](#11-appendix)

---

## 0. Phase 0 — Master Key + KT Wiring (wired 2026-08-30)

**Goal:** Decrypt before classify. Rescue opaque families (`Opfake 2/21`, `FakeInstaller 10/25`) whose 0 static signal is an *encryption* problem, not a model problem. Wire `docs/MASTER_KEY_STRATEGY.md` (7-step oracle playbook) and `docs/FULL_KNOWLEDGE_TRANSFER.md` (packer taxonomy, E-codes, triage matrix) as Step 0 before `analysis/pipeline.py:59` string enumeration. See `analysis/step0_master_key.py:1`.

**Why this is Phase 0, not Phase 3:**
- `Opfake` has `family_knowledge_base.json:134` `strings:[]` because its dex is encrypted at rest. No threshold tuning (`mine_discriminators.py:37`) can mine a string that is not there. `MASTER_KEY §5-6` (PK/dex validation) decrypts it first.
- `PENDRIVE_MASTER_KEY_INTEL.md:21` proves it: 3/3 myg0N kit samples (seeds `UZrF0u2`, `ZoCv0N2`, `LAZx0b2`) recovered with `sha1(seed)[:16]/sha256(seed)[:16]` AES-CBC, 10-entry kit.zip with byte-identical `bootstrap.dex 35b48528`. Without this, `FakeInstaller` would stay 60% forever.
- Commercial VMP (Ijiami/Bangcle/360Jiagu, Calculator ×3 `PENDRIVE_MASTER_KEY_INTEL.md:89`) is `E-NATIVE-NOENTRY` per `MASTER_KEY §16` + `FULL_KT §4` - expected limit, not a miss. Metrics must treat as catch-all.

**What was wired:**

| File | Change | Master Key / KT ref |
|------|--------|---------------------|
| `analysis/step0_master_key.py:1` | NEW - runs `scripts/triage.py:H1-H6` `triage_apk()` then `scripts/unpack.py` dispatcher (`java_route` for `so_count:0` injected repack `MASTER_KEY §2.5`, `native_route` for myg0N custom `MASTER_KEY §3-5`) + myg0N KDF brute `stem+"2"` `FULL_KT §6` | `MASTER_KEY §1-7`, `FULL_KT §2-6` |
| `analysis/pipeline.py:59` | After Step1 `extract_apk`, call `run_master_key_preprocess()` `pipeline.py:327`, enrich strings via `enrich_strings_with_recovered()` if `RECOVERED` (merges decrypted dex strings into `categories/string_literals` for downstream `step5_c2` + `family_id`) | `FULL_KT §15` indeterminate never benign |
| `analysis/pipeline.py:634` | `family_with_fallback()` returns `unknown` with `method:e_coded` + `ecode` for `is_e_coded` samples, so evaluation can distinguish expected VMP limits from model errors | `MASTER_KEY §16` E-codes, `FULL_KT §4` taxonomy |
| `evaluation/metrics_recompute.py:73` | `CATCH_ALL_LABELS` extended with `e-native-noentry`, `e-java-runtime-delivery`, etc. (sync with `step0_master_key.py:E_CODE_CATCH_ALLS`) → `specific_families` `243` excludes VMP, `overall` not penalized | `FULL_KT §15` triage matrix `0FP/0FN`, `MASTER_KEY §19` indeterminate suspect |
| `docs/accuracy-improvement-plan.md` | This Phase 0 + cross-refs to `MASTER_KEY` + `FULL_KT` | Wiring doc |

**Verification for Phase 0:**
```bash
# Single APK - should show master_key triage + enrichment
python -m analysis.pipeline samples/malware/androzoo_drebin/Plankton_*.apk  # clean_static → SKIPPED
python -m analysis.pipeline PENDRIVE\ DATA/PENDRIVE\ DATA/apk\ fraud/21/Calculator.apk  # packed_known(Ijiami) → E-NATIVE-NOENTRY

# Metrics - specific accuracy should not drop when E-coded pendrive samples added
python analysis/mine_family_knowledge.py  # now sees decrypted strings for myg0N kit
python evaluation/reeval_families.py --output-dir evaluation/metrics_v2
python evaluation/metrics_recompute.py --gt ground_truth_all_corrected.csv --predictions evaluation/metrics_v2/predictions.json --output-dir evaluation/metrics_v2 --verbose
# Expect: enriched Opfake mine coverage 0.0 → ≥0.2 with 5+ strings, overall +3-5%
```

**KT reading order for accuracy work:** `FULL_KNOWLEDGE_TRANSFER.md:172` 1→2→3, then this Phase 0, then Phase 1-3 below. E-code list `PENDRIVE_MASTER_KEY_INTEL.md:89` is the honest map of where oracle stops.

---

## 1. Baseline Metrics

| Metric | Value | Source |
|--------|-------|--------|
| Family exact-match overall | **64.2% (226/352)** | `README.md:87`, `evaluation/metrics_recompute.py:243` |
| Family exact-match specific families only | **68.6% (216/315)** | `README.md:88` |
| High-confidence specific | **70.0% (189/270)** | `README.md:319` |
| Unknown refusal accuracy | **30.3% (10/33)** | `README.md:320` |
| C2 Recall | **95%** (recovered from 80% after heuristic fix) | `README.md:86` |
| C2 Indicator precision (22 samples, 380 indicators) | **2.4% malicious, 68% benign (260/380), 29% suspicious** | `evaluation_results/fp_final_report.json:5`, `README.md:88` |
| Auto 21-sample check | 299 benign (68%), 129 suspicious, 11 malicious /439 | `README.md:274` |
| Domain legitimacy (285 domains) | 68 junk /134 benign /75 suspicious /8 malicious | `README.md:274` |
| Speed | ~1.5 min LLM path, ~0.4 min heuristic skip (40% skip rate) | `README.md:82` |

**Repro:**
```bash
python analysis/mine_family_knowledge.py
python evaluation/reeval_families.py --output-dir evaluation/metrics_v2
python evaluation/metrics_recompute.py --gt ground_truth_all_corrected.csv --predictions evaluation/metrics_v2/predictions.json --output-dir evaluation/metrics_v2 --verbose
```
`evaluation/reeval_families.py:66`, `evaluation/metrics_recompute.py:358`

Remaining misses: `Opfake/FakeInstaller/FakeChrome` (opaque obfuscation, 0 static signal) and `TeaBot↔Hydra↔Ermac↔FluBot` (shared toolkit, hard even for humans) `README.md:325`.

---

## 2. Root Cause Analysis

### 2.1 Malicious vs Benign Classifier

**Current decision path:** `analysis/step7_llm_assessment.py:913` `assess_with_llm()` → `should_skip_llm():312` → `benign_verdict_heuristic():380` → `heuristic_fallback():542` → `sanity_check():212` → `pipeline.py:707` `needs_manual_review` flag.

| Component | File | Problem | Impact |
|-----------|------|---------|--------|
| Risk scoring | `backend/core/androguard_analyzer.py:434` `calculate_risk()` | `high_risk_perms *2` linear sum; `SEND_SMS`+`READ_PHONE_STATE` are universal in benign Chinese pay SDKs | Over-scores benign |
| Permission logic | Same | Single-perm check vs combination | FP |
| C2 confidence | `analysis/step5_c2_extraction.py:1015` `calculate_c2_confidence()` | Base 0.5 +0.2 HTTP, +0.25 public IP → even junk `.cc` gets 0.7 | `heuristic_fallback:589` triggers `high/80` on junk |
| Benign skip | `step7_llm_assessment.py:312` | Skips LLM if `max_conf <0.6` (threshold at `317`) else LLM; but `benign_verdict_heuristic:427` hardcodes `risk_score=45` | Masks low-signal malware (Opfake has 0 C2 → always benign) |
| Obfuscation score | `analysis/step8_obfuscation_analysis.py:183` weights | Reflection 2pts, dynamic_loading 5pts - tuned for Drebin 2013, not modern packers | Mis-calibrated |
| Benign list | `step5_c2_extraction.py:54` `BENIGN_DOMAINS` (500+) | Misses `*.cc` (Mono), `*.aar` (Firebase), `*.so` truncations; `is_benign_url():719` only hostname, not path | 68% FP remain |

**Evidence:** `evaluation_results/fp_final_report.json:76` lists 26 `*.cc` files flagged suspicious (`osbridge.cc`, `java-interop.cc` etc.) - all Mono runtime, not C2.

### 2.2 Family Identification

**3-layer engine `README.md:290` + `backend/family_id.py:131`:**
1. `FAMILY_SIGNATURES` 38 hand-written (`family_id.py:131`..`1067`) - `min_matches`, `require_c2`, `class_count` range, `confidence 0.65-0.95`.
2. Knowledge-base matcher `analysis/family_knowledge_base.json` (mined at `mine_discriminators.py:37` thresholds) - offline precision ~95%, re-eval 76.3% (151/198).
3. LLM candidate guidance - refusal 63.8% → 23.9% (84/352 produce verdict).

**Bottlenecks:**
- `Opfake (21 GT)`: only `opfake` string + `rebillme.net` C2; 15/21 have no `rebillme` in cache (obfuscated) → `min_matches=3` fails.
- `FakeInstaller (25)`: shares `depositmobi.com` with `FakeInst` - removed to avoid theft but now no signal.
- `TeaBot/Hydra/Ermac`: shared `install_library.zip` payload pattern `analysis/recovered/` - statically identical.
- `MinHash` `analysis/step17_family_clustering.py:104` threshold `0.3` fixed for all sizes; `HyPay` 4000-15000 classes vs `FakeInst` 10-50 classes get same threshold.
- Cert boost `family_id.py:1254` `cert_issuer_boost()` disabled for LOW stability families - loses signal for `NGate` self-signed.

### 2.3 C2 Extraction Precision

**Pipeline:** `step2_string_enumeration.py` → `step3_encoding_detection.py` → `step4_decoding.py` → `step5_c2_extraction.py:1132` `extract_c2_infrastructure()`.

- `URL_RE:48`, `DOMAIN_RE:50` over-match code fragments (`builder.name`, `response.body` → TLD `name`/`body`).
- `_is_code_reference():852` + `_is_likely_junk_domain():921` filter many but miss `*.cc` artifact class (treated as `unknown` protocol → `calculate_c2_confidence` still +0.05 `1047`).
- `BENIGN_URL_PATHS:607` only 2 entries; `BENIGN_DOMAIN_PATTERNS:577` regexes (`^crl.`, `^ocsp.`) miss `firebaseio.com` subdomains.

---

## 3. Phase 1 — Quick Wins (1–2 weeks)

**Goal:** +8-12% benign precision, +3-5% family accuracy, no model retrain.

### 3.1 Close C2 Junk Filter

**File:** `analysis/step5_c2_extraction.py:921`

**Change 1a - Extend `_is_likely_junk_domain`:**
```python
# Add at step5_c2_extraction.py:932 after file ext check:
if tld in ('cc', 'aar', 'so', 'apk', 'jar', 'dex', 'png', 'jpg', 'jpeg', 'gif', 'xml', 'json', 'svg', 'ico', 'css', 'js', 'ts', 'aar'):
    return True
# Add Mono/Xamarin detection:
if domain.endswith('.cc') and any(x in domain for x in ['monodroid', 'java-interop', 'xa-internal', 'embedded-assemblies']):
    return True
```

**Change 1b - BENIGN_DOMAINS expansion `step5_c2_extraction.py:54`:**
Add: `firebaseio.com`, `firebasestorage.googleapis.com`, `crashlytics.com`, `googletagmanager.com`, `google-analytics.com`, `appsflyer.com`, `adjust.com`, `facebook.com` graph endpoints, `ytimg.com`, `srgb.com`, `assoc-amazon.com`, `monodroid` pattern.

Count: 500 → ~600. Verify `evaluation_results/fp_validation_auto.json` 299 benign drops to <180.

**Change 1c - AD_NETWORK multiplier `step5_c2_extraction.py:1057`:**
Already `score *=0.5` for `is_ad_network()`. Add same for analytics `is_analytics_domain()` (new set: `google-analytics`, `googletagmanager`, `firebase`, `crashlytics`).

**Verification:** `python scripts/validate_fp.py` → benign 68% → target <45%.

### 3.2 Permission Combination Logic

**File:** `backend/core/androguard_analyzer.py:434` and `analysis/step7_llm_assessment.py:498`

**Replace:**
```python
# androguard_analyzer.py:438-439
high_risk_perms = sum(1 for p in self.results['permissions'] if p['high_risk'])
risk_score += high_risk_perms *2
```
**With:**
```python
from analysis.step7_llm_assessment import _match_behavior_groups
groups = _match_behavior_groups([p['name'] for p in self.results['permissions']])
for g in groups:
    risk_score += g['boost']  # 35 sms_fraud, 25 location_surveillance etc.
# Drop single-perm boost; keep high-risk count only as tiebreak +0.5
```

Already defined at `step7_llm_assessment.py:498` `PERMISSION_BEHAVIOR_GROUPS`. Import it.

**File:** `analysis/step7_llm_assessment.py:634` heuristic fallback - align same: `permission_behaviors = _match_behavior_groups(...)` already used at `549`, extend to `calculate_risk`.

### 3.3 Calibrate Thresholds via ROC

**File:** `analysis/step7_llm_assessment.py:317` `should_skip_llm` `high_conf_threshold=0.6` and `step7_llm_assessment.py:365` `_cap_risk_on_junk_c2` `0.85`

**Action:** Run sweep on 405 GT `is_malware`:
```bash
python evaluation/sweep_threshold.py --gt ground_truth_all_corrected.csv --metric f1
```
Plot PR curve for `risk_score` (0-100) vs `is_malware`. Expected optimal `should_skip_llm` → 0.65-0.70 (currently 0.6 under-skips), `_cap_risk` 0.85 → 0.75. Document in `evaluation/metrics/metrics.json`.

**Change:** Make thresholds config in `backend/config.py:1` not hardcoded.

### 3.4 Knowledge-Base Tuning

**File:** `analysis/mine_discriminators.py:33-37`

**Action:** Lower `CORPUS_FP_MAX 0.05 → 0.02` for toolkit families (`TeaBot`, `Hydra`, `Ermac`, `FluBot`) and raise `TARGET_COVERAGE_MIN 0.5 → 0.7` for them to avoid shared SDK tokens. Re-mine:
```bash
python analysis/mine_discriminators.py
python analysis/mine_family_knowledge.py  # regenerate family_knowledge_base.json
```

**File:** `backend/family_id.py:128` `MIN_PERMISSION_CLUSTER` already 3; audit families with `min_matches=2` (`Geinimi:228`, `Adsms:778`, `SpyHasb:898`) → raise to 3, verify via `evaluation/reeval_families.py`.

**Expected:** +2-3 family points, -5 FP families.

---

## 4. Phase 2 — Medium Term (1–2 months)

**Goal:** Replace heuristics with learned model; +10-15% mal/ben accuracy, +5-7% family.

### 4.1 Supervised Malicious/Benign Classifier

**New file:** `analysis/ml_classifier.py`

**Features (already extracted, no new pipeline cost):**
| Feature | Source | Type |
|---------|--------|------|
| `c2_count`, `c2_max_conf`, `c2_high_conf_count (>=0.7)` | `step5_c2_extraction.py:1338` | numeric |
| `chain_count`, `known_decoded`, `all_unknown` | `step6_correlation.py` + `step7_llm_assessment.py:294` `_count_significant_chains` | numeric |
| `obfuscation_score`, `obfuscation_level` | `step8_obfuscation_analysis.py:183` | numeric |
| `dangerous_perm_count`, `behavior_group_count` | `androguard_analyzer.py`, `step7_llm_assessment.py:498` | numeric |
| `reflection`, `dynamic_loading`, `crypto_apis`, `suspicious_apis` counts | `step8` indicators | numeric |
| `native_lib_count`, `has_native_libs` | `androguard_analyzer.py:285` | numeric |
| `dex_entropy_max`, `likely_packed` | `step8` `dex_entropy` | numeric |
| `string_count`, `hardcoded_secrets_count` | `step2`, `hardcoded_secrets.py` | numeric |
| `vt_detection_ratio`, `otx_pulse_count` | `backend/threat_intelligence.py:192` | numeric (if keys) |
| `is_self_signed`, `cert_age_days` | `analysis/step16_certificate_analysis.py` | numeric |
| `class_count` | `family_id.py` extraction | numeric |

**Model:** XGBoost or RandomForest (imbalanced 305/100 → `scale_pos_weight=3.05` or SMOTE). Train on 405 `ground_truth_all_corrected_100legit.csv:is_malware`, stratified 5-fold CV. Calibrate `predict_proba` via Platt.

**Integration:** `analysis/pipeline.py:538` `severity_score = base_score*4` → replace with `ml_classifier.predict_proba(features)`. Keep `heuristic_fallback` as fallback if model file missing. Add `analysis/ml_classifier.pkl` to repo via `dvc` or `git-lfs`.

**File changes:**
- `analysis/pipeline.py:525` `llm_with_fallback()` → add `ml_verdict = ml_classifier.classify(result)` before LLM; if `ml_verdict.confidence>0.9` skip LLM entirely (saves 2s per sample).
- `backend/config.py` add `ML_MODEL_PATH`, `ML_THRESHOLD=0.5` tunable via ROC.

**Test:** `tests/test_ml_classifier.py` - mock features, assert `predict` in [0,1].

### 4.2 Threat Intel as Feature (not just display)

**File:** `backend/threat_intelligence.py:12` `ThreatIntelligenceEnricher`

Currently `pipeline.py` does not call TI before `assess_with_llm`. **Change:** Call `ThreatIntelligenceEnricher().enrich()` for `c2_infrastructure` at `pipeline.py:405` after `step5`, cache at `analysis/work/censys_cache.json:3`, feed `vt_malicious/70` into ML feature and `sanity_check():212` boost (+10 if VT≥10).

**Rate limit:** Already `ThreadPoolExecutor(max_workers=4)` at `threat_intelligence.py:324`; add file cache 24h TTL.

### 4.3 Family Engine Upgrade

**File:** `backend/family_id.py:131` - expand 38 signatures to 60 covering modern families (`Hydra`, `TeaBot`, `Ermac`, `FluBot`, `NGate`, `SpyNote`) mined from MalwareBazaar.

**For each new family:**
- Mine discriminators via `analysis/mine_discriminators.py` with `TARGET_COVERAGE_MIN=0.6`
- Add `FamilySignature` with `require_c2=True` where C2 unique (`Hydra: hydra.`, `TeaBot: teabot`), else `require_c2=False` but `min_matches=4` forcing string hit.
- Add `class_count` band from `pipeline.py` metadata (`sample_metadata.csv` distribution).
- Test via `evaluation/reeval_families.py --limit 20` per family.

**File:** `analysis/step17_family_clustering.py:104` `match_against_index` threshold `0.3` → dynamic:
```python
threshold = 0.45 if query_signature["total_methods"]>4000 else 0.30 if >500 else 0.25
```
Add hierarchical DBSCAN on MinHash Jaccard (`analysis/step17_family_clustering.py:161` `get_family_graph_data()` is O(n²) `166` - cap at 2000 samples or incremental).

**File:** `backend/family_id.py:1254` `cert_issuer_boost()` - re-enable for `NGate`/`Hydra` where `analysis/cert_profiles.json` stability >70% (check `cert_profiles.py`).

### 4.4 Native ELF Expansion

**File:** `backend/family_id.py:1078` `NATIVE_API_PATTERNS` only 2 families. Extend to `DroidDream` (`rageagainstthecage`), `Jiagu` (`jiagu`), `Generic` packer via `analysis/step13_native_elf_analysis.py` extracted `elf_analysis.packing.level` and `jni_exports`.

**Action:** Add `elf_analyzer.py:355` `ELFBreaker` packing signature → `family_id` signal.

---

## 5. Phase 3 — Long Term (3–6 months)

**Goal:** Unlock opaque families, toolkit disambiguation; target 80%+ family, 90%+ mal/ben.

### 5.1 Dynamic Decryption Correlation (Q1 2027 `README.md:351`)

**File:** `analysis/step11_string_clustering.py` clusters high-entropy strings but no `Cipher.doFinal` link. Add:

- `analysis/step12_reflective_tracing.py:find_reflective_calls` already finds `java/lang/reflect` → extend to `javax/crypto/Cipher` + `MessageDigest`.
- New `analysis/step21_string_deobfuscation.py` (skeleton exists `step21_*__pycache__`): Hook Frida `Interceptor.attach(Module.findExportByName("libcrypto.so", "AES_decrypt"))` or static trace `const-string` → `Cipher.init` → `doFinal` → `new String`.
- Decrypted strings feed back into `strings_result` before `step5`.

**Expected:** +5-10% recall `README.md:352`; unlocks `Opfake` which hides C2 in XOR blob.

### 5.2 Frida-Based C2 Validation (Q2 2027 `README.md:352`)

**New:** `analysis/dynamic_validation.py`

- Run APK in `emulator` with Frida script intercepting `HttpURLConnection`, `OkHttp`, `WebView.loadUrl`, `Socket.connect`.
- Compare static `c2_infrastructure` vs runtime DNS/HTTP observed in 30s.
- Mark `dynamic_confirmed` flag → `calculate_c2_confidence` +0.3, `fp_final_report` benign drops 68%→<20%.
- Pipeline timeout `STEP_TIMEOUTS:82` `step18:45` → add `step19_dynamic:120` optional.

### 5.3 Multi-Sample Attribution Clustering

**File:** `analysis/step18_threat_synthesis.py` (stub) → Threat Synthesis Engine `docs/plans/2026-07-01-threat-synthesis-engine.md`.

- Cross-sample Jaccard on `family_clustering` + `cert` + `C2` + `native libs`.
- Graph community detection (Leiden) on `get_family_graph_data:161` edges → new families.

### 5.4 YARA + STIX Automation

**File:** `data/yara_rules.yar:20,329` - auto-generate per-family rule from mined discriminators (`mine_discriminators.py` top_commit_ready). `backend/threat_intel.py:306` `to_yara()` already exists; promote to `step9_post_process.py` generation.

---

## 6. Detailed File-Level Change Spec

| Priority | File | Line | Change | Effort | Impact |
|----------|------|------|--------|--------|--------|
| P0 | `analysis/step5_c2_extraction.py:932` | `_is_likely_junk_domain` | Add `.cc/.aar` ext, Mono `monodroid` filter | 2h | -15% FP |
| P0 | `analysis/step5_c2_extraction.py:54` | `BENIGN_DOMAINS` | +15 firebase/analytics/ytimg domains | 1h | -10% FP |
| P0 | `analysis/step5_c2_extraction.py:1057` | `calculate_c2_confidence` | `is_analytics_domain` *0.5 | 1h | -5% FP |
| P0 | `backend/core/androguard_analyzer.py:434` | `calculate_risk` | Use `_match_behavior_groups` not count | 3h | +8% mal/ben |
| P0 | `analysis/step7_llm_assessment.py:317` | `should_skip_llm` | ROC-tune 0.6→0.65, config move | 4h | +3% speed |
| P0 | `analysis/mine_discriminators.py:37` | `CORPUS_FP_MAX` | 0.05→0.02 for toolkit families | 2h | +2% family |
| P1 | `analysis/ml_classifier.py` | NEW | XGBoost on 15 features from `ground_truth_all_corrected.csv` | 1w | +10% mal/ben |
| P1 | `analysis/pipeline.py:405` | `step5->TI` | Call `ThreatIntelligenceEnricher` before LLM | 1d | +5% precision |
| P1 | `backend/family_id.py:131` | `FAMILY_SIGNATURES` | +22 modern signatures (Hydra etc) | 1w | +5% family |
| P1 | `analysis/step17_family_clustering.py:104` | `threshold` | Dynamic 0.25/0.30/0.45 by class_count | 3h | +2% family |
| P1 | `backend/family_id.py:1078` | `NATIVE_API_PATTERNS` | + DroidDream/Jiagu ELF | 1d | +1% family |
| P2 | `analysis/step12_reflective_tracing.py` | `Cipher` | Add `Cipher.doFinal` trace | 3d | +5% recall |
| P2 | `analysis/dynamic_validation.py` | NEW | Frida 30s run, confirm C2 | 2w | -30% FP |

**Total P0:** ~13h for +15% benign precision, +5% family. **Do first.**

---

## 7. Data Strategy

**Current:** `ground_truth_all_corrected_100legit.csv` 405 rows: `is_malware yes 305 / no 100`, per `scripts/build_ground_truth.py:633`. Sources: `AndroZoo-Drebin 149`, `MalwareBazaar 97`, `modern_eval 9`, `AndroZoo 26`, `abusech 24`, `F-Droid 100` `README.md:260`. All `confirmed_external` via VT 291 + MB 168 `README.md:288`. 48.5% old GT were catch-alls `AndroidOS/GenericKD` inflated naive scoring `README.md:288`.

**Gaps:**
- Benign 100 only F-Droid/benign_eval; no Play Store top categories (banking, social, game) → pay SDK FP.
- Modern families under-represented: `NGate 15`, `SpyNote 14`, `TeaBot 13`, `Ermac 12`, `Hydra 11` vs `FakeInstaller 25`.
- No dynamic labels.

**Actions:**
1. **Benign expansion:** `scripts/download_samples.py:644` `--legit-only` currently 10; add Play Store scraper or `AndroZoo benign` query (`vt_detection=0`, `dex_date>2023`). Target 200 benign balanced (50 per category). Re-run `scripts/build_ground_truth.py:600` `determine_family_and_label`.
2. **Modern malware:** `scripts/fetch_abusech_c2_samples.py:424` already fetches Hydra/TeaBot; schedule weekly `scripts/censys_backfill.py:88` for NGate NFC relay `family_id.py:521`.
3. **Catch-all purge:** Keep `evaluation/metrics_recompute.py:73` `CATCH_ALL_LABELS` filter; never train on them. Evaluate `specific_families` `243` not overall.
4. **Versioning:** Commit `ground_truth_all_corrected.csv` + `family_knowledge_base.json` per run; use `sample_metadata.csv` for lineage.
5. **Imbalance handling:** In ML, `class_weight='balanced'` or `SMOTE`; in heuristic, boost minority families (`NGate` confidence 0.85 `539`).

---

## 8. Evaluation & Verification

**Single source of truth:** `evaluation/metrics_recompute.py:1` + `evaluation/reeval_families.py:1`

**Commands:**
```bash
# 1. Re-mine KB
python analysis/mine_family_knowledge.py

# 2. Re-eval cached 352 results (needs Ollama at OLLAMA_HOST)
python evaluation/reeval_families.py --output-dir evaluation/metrics_v2

# 3. Compute metrics vs corrected GT
python evaluation/metrics_recompute.py \
    --gt ground_truth_all_corrected.csv \
    --predictions evaluation/metrics_v2/predictions.json \
    --output-dir evaluation/metrics_v2 --verbose

# 4. FP validation (22-sample manual equivalent)
python scripts/validate_fp.py --auto
python scripts/check_legitimacy.py  # domain 285 check

# 5. Full 405 run (requires APKs)
python evaluation/run_validation_359.py --gt ground_truth_all_corrected.csv
```

**Outputs:** `metrics.json` (overall `170`, `subset_metrics:259`), `per_source_accuracy.csv:302`, `per_family_breakdown.csv:313`. Gate PR on `accuracy_specific` and `fp_final_report.json:5` `benign_count/380`.

**Existing tests:** `tests/test_c2_and_correlation.py:364`, `tests/test_step9_post_process.py:473`, `tests/test_attribution.py:272` - add `tests/test_ml_classifier.py` and update `tests/analysis/test_step14_network_protocol_analysis.py:30` for new analytics allowlist.

**CI:** `.github/workflows/test.yml` runs `pytest tests/ -v` + `vitest` 247 frontend tests `README.md:369`. Add metric gate: fail if `accuracy_specific` <64.2%.

---

## 9. Success Criteria

| Criterion | Baseline | P1 Target | P2 Target | Verified By |
|-----------|----------|-----------|-----------|-------------|
| Family overall | 64.2% | 68% | 75% | `metrics_recompute.py` overall `174` |
| Family specific | 68.6% | 72% | 78% | `subset_metrics.specific_families:260` |
| Family high-conf specific | 70.0% | 74% | 80% | `high_confidence_specific:265` |
| C2 precision malicious | 2.4% | 8% | 15% | `fp_final_report.json` |
| C2 benign FP | 68% | <50% | <30% | `fp_validation_auto.json` |
| Malicious recall | 95% | 95% | 97% | `run_validation_359.py` |
| Malicious F1 (balanced) | - | 0.88 | 0.92 | ML CV |
| Unknown abstention | 30.3% | 40% | 50% | `unknown_refusal:270` |
| Pipeline time | 1.5 min | 1.2 min | 1.0 min | `pipeline.py:691` timeline |

**Do not ship** if recall drops or `abusech` `35.0%` specific `README.md:324` not improved.

---

## 10. Risks & Mitigations

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Overfit to 100 benign (F-Droid bias) | High | Expand to 200 Play Store benign before ML; holdout 20% |
| Threshold tuning overfits 352 | Med | Keep 100-sample holdout `evaluation/metrics_v2` not in tuning |
| `FAMILY_SIGNATURES` order tie-break theft (e.g. `BaseBridge` before `DroidKungFu` `family_id.py:132`) | Med | Unit test `tests/test_attribution.py` asserts tie-break; new families append last `741` |
| `get_family_graph_data:161` O(n²) at 2000+ samples | High | Cap incremental update, note at `192` |
| Frida emulator flake | High | Make dynamic step optional `STEP_TIMEOUTS:82`, fallback to static |
| VT/OTX key missing → silent skip `family_id.py:99` `CIRCL_AVAILABLE` | High | File cache + `is_malware` not dependent on TI |
| LLM hallucination (narrative claims C2 w/o extraction) | Med | `sanity_check:261` already caps; add `_cap_risk_on_junk_c2:365` |

---

## 11. Appendix

### A. Key Files

| File | LOC | Role |
|------|-----|------|
| `analysis/step5_c2_extraction.py` | 1,360 | C2 parsing, benign allowlist `54`, junk filter `921`, confidence `1015` |
| `analysis/step7_llm_assessment.py` | 1,201 | LLM + `should_skip_llm:312`, `heuristic_fallback:542`, `sanity_check:212` |
| `backend/family_id.py` | ~1,700 | 38 signatures `131`, `NATIVE_API_PATTERNS:1078`, `cert_issuer_boost:1254` |
| `backend/core/androguard_analyzer.py` | 550 | `calculate_risk:434`, permissions `179` |
| `analysis/step17_family_clustering.py` | 192 | MinHash `24`, `threshold:104`, `O(n²):163` |
| `analysis/mine_discriminators.py` | 239 | Miner `CORPUS_FP_MAX:37` |
| `evaluation/metrics_recompute.py` | 391 | Ground truth join `106`, metrics `145` |
| `analysis/pipeline.py` | 769 | 18 steps `59`, `STEP_TIMEOUTS:82` |

### B. Ground Truth Resolution Order (`README.md:288`)

`filename_prefix` → `MalwareBazaar signature` → `GT specific` → `VT recheck` → `verified pipeline C2` → `MB tags` (`scripts/build_ground_truth.py:437` `determine_family_and_label`). Old 48.5% catch-alls inflated naive 32% → corrected 17.3% → upgraded 64.2%.

### C. Future Work Already Planned (`README.md:348`)

- Threat Synthesis Engine Q1 2027 `docs/plans/2026-07-01-threat-synthesis-engine.md`
- Dynamic Validation Q2 2027
- `Cipher.doFinal` tracing +5-10% recall `README.md:352`

### D. Commands Quick Reference

```bash
# Health
pytest tests/ -v                          # backend 17 files
cd frontend && npm test                   # 247 tests

# Single APK
python -m analysis.pipeline samples/malware/example.apk

# Batch
python scripts/run_batch_analysis.py --max-samples 50

# FP audit
python scripts/validate_fp.py
cat evaluation_results/fp_final_report.json | jq .malicious_indicators
```

---

**Owner:** DroidForensix team  
**Review:** After P1, re-eval on 352 corrected GT; promote to `ground_truth_all_corrected.csv` only if `accuracy_specific` ↑ with no recall regression.  
**License:** MIT
