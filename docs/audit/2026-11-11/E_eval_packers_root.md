# Audit slice E: packers/, root scripts, evaluation/, site/

Date: 2026-11-11. Branch `chore/codeowners-live` (HEAD 7f633ab) plus the uncommitted working tree. Read-only audit. I ran small scripts from the scratchpad: synthetic in-memory ZIP probes against `packers/`, hash-overlap and source checks over the evaluation CSVs and JSONL files, `ruff check` on this slice, and one local pytest run (`tests/test_stage3_replay.py`). No network calls, no sample APKs, nothing written to the repo.

Evidence tags: **CONFIRMED** means I traced the code, ran it, or computed the result. **PLAUSIBLE** means it follows from reading the code but I did not reproduce it.

---

## 1. packers/ findings (most severe first)

| id | sev | category | file:line | finding | consequence | minimal fix | tag |
|---|---|---|---|---|---|---|---|
| P1 | medium | evasion / coverage | packers/breaker/blobs.py:121-125, 154-159 | When `zipfile` cannot read a member that is not flag-encrypted, the member gets `content=None`, and line 125 then labels it `SKIPPED_ZIPCRYPTO`. One case is an unknown compression method, a known Android anti-analysis trick: Android treats the member as STORED, while `zipfile` raises NotImplementedError. Ran it: a member with method 99 came out as `SKIPPED_ZIPCRYPTO`, detail "unreadable: NotImplementedError". | The breaker never attacks the member, and coverage.json says it was ZipCrypto, which is false. Malware that uses this trick evades the breaker without any visible failure. | Reuse the manual local-header read in `_flagged_content` (which treats a non-deflate method as stored, like Android) as a fallback for non-flagged members. Give unreadable members their own outcome, e.g. `SKIPPED_UNREADABLE`. | CONFIRMED |
| P2 | medium | correctness | packers/breaker/blobs.py:207; engine.py (no reader) | `collection.recurse` is filled with plaintext ZIP/JAR members, but nothing in engine.py reads it (grep: the only use is the append). Only *decrypted* ZIP hits are recursed into (`_nested_entries`, engine.py:411-425). | An encrypted payload inside a plaintext `assets/*.jar` or `*.zip` is never attacked, only string-mined. The docstring "recurse" contract is silently unmet. | In `break_apk`, call `collect_from_zip` on each `collection.recurse` entry (depth+1), mirroring `_nested_entries`, and fold its counts into the books. | CONFIRMED |
| P3 | medium | crypto validation | packers/breaker/engine.py:164-173 (compare 126) | `_is_json` runs `json.loads` on the raw decrypted buffer. AES-CBC/ECB output still carries PKCS#7 padding, so `json.loads` fails with "Extra data". The DEX path strips padding (line 126); the JSON path does not. Ran it: `validate_payload(b'{"a": 1}' + pad)` returns None, while the unpadded buffer returns json. | An AES-encrypted JSON config, a common C2 config carrier, can never be RECOVERED. Its correct key is counted as a probe false positive instead. | Retry on `data[:-_pkcs7_pad_length(data)]` when the pad length is non-zero. | CONFIRMED |
| P4 | medium | hostile input / DoS | engine.py:517-535; framework.py:104; blobs.py:157 | Validation and artifact listing are not bomb-bounded, unlike the gzip probe (engine.py:58-60). `testzip()` decompresses every member with no deadline check. `_payload_artifacts` calls `archive.read(name)` on up to 50 members, fully in memory. Nested `collect_from_zip` reads every member fully. | A malware author controls the decrypted plaintext. A ZIP64 bomb inside the encrypted container can stall past `budget_s`, or trigger MemoryError or an OOM kill. (MemoryError is caught at :528 and silently skipped.) | Check `info.file_size` against a cap before reading. Hash members via `archive.open()` streaming with a byte limit. Skip `testzip` when total `file_size` exceeds a cap. | PLAUSIBLE |
| P5 | medium | crash on hostile input | packers/framework.py:96-118, 104 | `verify_unpack`/`validate_zip` only catch `BadZipFile`. `testzip()` raises RuntimeError on an encrypted-flag member, and NotImplementedError on unknown compression. Ran it: `verify_unpack(zip with encrypted bit)` raises `RuntimeError: File 'a' is encrypted`. | `MyG0NOracle.unpack` (myg0n.py:91-94) and any caller of the public `packers.verify_unpack` crash on hostile plaintext. `engine._zip_evidence` wraps it, so the breaker is safe. | `except Exception` in `validate_zip`, returning `(False, f"...{type(exc).__name__}")`. | CONFIRMED |
| P6 | low | crash on hostile input | packers/breaker/blobs.py:169 | `struct.unpack("<HH", raw[offset+26:offset+30])` runs after only a 4-byte signature check. A truncated flagged member raises `struct.error`. Ran it: confirmed. | One malformed member aborts `break_apk` for the whole APK, and no coverage.json is written. | Return `(None, "", "truncated local header")` when `len(raw) < offset+30`. | CONFIRMED |
| P7 | low | budget / perf | engine.py:57; blobs.py:44; schemes.py:105-130 | The probe magic `{` is one byte, so about 1 in 256 non-AES candidates passes the probe. Each pass triggers a full pure-Python XOR/RC4/LCG decrypt of the whole blob. Single-byte XOR alone guarantees about 1 such hit per blob. | On multi-MB blobs, JSON false positives can eat most of the shared 300 s budget. Other members' deep tiers then get `E-KDF-BUDGET`. The budget is still respected; only coverage suffers. | Require `{"` or `{\n` (2 bytes) for the probe, or cap the full-decrypt size for non-AES ciphers. | PLAUSIBLE |
| P8 | low | false positive | packers/myg0n.py:36, 43, 60-64 | `_CONTAINER_RE` matches any 4–16 char alphanumeric extensionless asset, e.g. `assets/LICENSE` or `assets/version`. The `"." not in` check is redundant. `recover_seed` takes the first match in namelist order. | `classify` reports RTO_MYG0N for ordinary APKs that have such an asset and no asset DEX. Seed recovery may also pick the wrong asset. | Also require high entropy (`shannon_entropy` ≥ 7.9) and size ≥ 512 B, as in blobs.py. | CONFIRMED (by reading the regex) |
| P9 | low | robustness | packers/myg0n.py:79-89 | `decrypt_asset` does no PKCS#5 unpad, and the ValueError on ciphertext that is not a multiple of 16 bytes is not handled. | The returned plaintext still has its padding. A non-container asset crashes `unpack`. | Unpad with `Crypto.Util.Padding.unpad` and catch ValueError. | CONFIRMED |
| P10 | low | packaging / lint | pyproject.toml (`[tool.setuptools] packages`); .github/workflows/test.yml (`ruff check analysis backend droidforensix tests`); packers/myg0n.py:14 | `packers` is not in setuptools `packages`, and it is outside the CI ruff scope. Unused `Path` import at myg0n.py:14 (ruff F401). | After `pip install .`, `analysis/step0_master_key.py:131` (lazy `from packers...`) fails outside the repo checkout. Lint debt grows unchecked. | Add `packers`, `packers.breaker` to packages. Add `packers` to the CI ruff paths. | CONFIRMED |

Checked and correct: the KDF (`framework.derive_key`, truncation guard). The `matrix_schemes` count of 61 (computed: 8 key specs × 5 IVs + 8 ECB + 9 XOR + 4 RC4). The `java.util.Random` LCG constants and signed `nextInt`. RC4 KSA/PRGA. The single-byte XOR excluding key 0. Duplicate-name handling via `archive.read(info)`. The coverage-book invariant. Budget accounting: one shared cap, checked before each attempt, so worst-case overshoot is one candidate. No unbounded brute-force loop exists. Every stream is finite: prior ≤ about 2.6k (substring windows cap the literal at 24 chars), matrix ≤ 61 × (13 + 2000 + extra), plus 255 + 7.

---

## 2. Evaluation methodology findings (most severe first)

| id | sev | category | file:line | finding | consequence | minimal fix | tag |
|---|---|---|---|---|---|---|---|
| E1 | critical | wrong claim | README.md:22, 26; evaluation_results/fp_final_report.json (tracked) | README says "Indicators confirmed as genuine C2: **2.4% (9/380)**". The 9 `malicious_indicators` in the backing file are `color.xyz` ×2, `rect.top` ×2, `result.top`, `4.0.4.android`, `staging.api.id.mipay.com`, and two Xiaomi `*.elb.amazonaws.com` resolvers. The flag reasons are "suspicious TLD / NXDOMAIN / unusual protocol". These are code-token parse artifacts and vendor infrastructure, not confirmed C2. The file covers `total_samples: 22`, but README:26 says the indicator evaluation uses 352 samples. | The "honest numbers" row overstates C2 precision. On this file the confirmed-genuine-C2 count is 0/380, and the 2.4% figure is mislabeled. | Restate the row as "9/380 auto-flagged by heuristics; 0 manually confirmed; 22 samples", or redo the review. | CONFIRMED |
| E2 | high | train/test leakage | README.md:21; evaluation/metrics/metrics.json (=metrics_v2); evaluation/metrics_v2/predictions.json; analysis/mine_family_knowledge.py:1, 32; evaluation/reeval_families.py:34, 75-79 | The 64.2% (226/352) comes from `metrics_v2`. In it, 198/352 predictions use `method=knowledge_base`. The KB is mined from `ground_truth_check_all.csv` over the same corpus, keeping only tokens with ≥ 0.90 precision on that corpus, and reeval_families reads its sample list from the same file. That makes the number in-sample. Leakage-aware evidence in the repo: dev baseline 35.5% (DEV_BASELINE.md), `metrics_baseline` 38.1% (134/352), later full runs v4–v14 at 40–47% on 409 rows. On unseen LAMDA families the shipped KB scored **0/51 correct with 25 confident wrong predictions** (lamda_fetch/kb_score_shipped.json). `run_validation_359.py:1` calls itself "leakage-free", but it only disables the GT lookup (:60-63), not the KB. | The family headline is a training-set score. The out-of-sample figure is about 35%, and on unseen families the KB misattributes with confidence. | Quote the dev baseline (35.5%) as the headline. Label 64.2% "in-sample (KB mined from the same labels)". Cite the LAMDA 0/51 result. | CONFIRMED |
| E3 | high | dataset confound | evaluation/fetch_more_malware.py:53-57; evaluation/fetch_fdroid_benign.py:56-59; malben_eval/*.csv | Every malware sample in the "fresh" holdout (150/150), validation (50/50), train_extra (50/50) and manifest200 (100/100) comes from `data/drebin_sha256_family.csv`, i.e. Drebin, 2010–2012. Every benign sample is the newest F-Droid build (150/150 in fdroid_benign_fetch.jsonl), and the 100 original training benign apps are F-Droid too. On the 200 same-source val+extra rows, **`file_size_kb < 2400` alone scores 88.5%**: benign median 5.8 MB, malware median 0.58 MB. Neither README nor site discloses this. "Fresh" here means unseen hashes, not recent malware. | The 97.3% largely measures "old Drebin vs modern F-Droid". It does not support claims about current malware or Play-store apps. | Disclose sources and era in README and site. Add a holdout with modern malware (abuse.ch / AndroZoo ≥ 2022) and Play-store benign apps. | CONFIRMED (sources); PLAUSIBLE (how much it inflates) |
| E4 | high | evaluated ≠ shipped | analysis/classify_fast.py:10, 97; droidforensix/cli.py:45; malben_eval/run_200/report.json (tracked); benign_baseline_2026-10-23/benign_summary.json (tracked); malben_eval/retrain_result.json | The README headline uses `malben_rf_retrained.pkl` at threshold 0.7 (untracked file). The product default is `malben_rf.pkl` at 0.5, and `droidforensix classify` passes no model or threshold. Tracked evidence for the shipped default: run_200 at 82.0% (164/200, benign specificity 67/100). On 100 Play-store benign apps it flagged **70/100** (FPR 0.70). On the validation split it flagged 22% of benign. | Users of the CLI get a model with a 33–70% false-positive rate on benign apps, while the README advertises 97.3%. | Ship the retrained bundle and the 0.7 threshold as the defaults (track the pkl), or state plainly which model the headline describes. | CONFIRMED |
| E5 | high | broken leakage guard | scripts/evaluate_malben.py:11, 42, 157-161, 267 | `TRAIN_MAP = classifier_eval_2026-10-23/train_apk_map.json`. That file holds the **222 pilot rows** (equal to pilot_gt.csv), not the 509 training rows of `classifier_data/features.csv`: 387 training shas are not in it. It also ignores `train_extra.csv` and `validation_split.csv`, and with `--model` it checks nothing about that model's training data. I computed the actual overlaps (fresh ∩ features.csv / train_extra / validation / manifest200): all 0, so the headline is not inflated. But the docstring's "refuses to run on leakage" guarantee is false. | A future manifest that does overlap the training data would pass validation. | Check against `features.csv` ∪ `train_extra.csv` ∪ `validation_split.csv`. Record the training-set hash inside the model bundle. | CONFIRMED |
| E6 | high | reproducibility | README.md:30, 35; malben_eval/ (untracked); report.json `git_commit`; scripts/evaluate_malben.py diff; analysis/classify_fast.py diff | The headline's inputs are all untracked: `run_fresh_t070/report.json`, `fresh_manifest.csv`, `malben_rf_retrained.pkl`, `train_extra.csv`, `validation_split.csv`, `split_features.csv`, `retrain_result.json`, `retrain_with_extra.py`, `extract_split_features.py`. The report stamps `git_commit 1479d1b`, but `--model`/`--threshold` exist only in the **uncommitted** diffs to evaluate_malben.py and classify_fast.py, so that commit cannot produce the report. The README links to files that are absent from the repo. | The published numbers cannot be reproduced from any commit. | Commit those files and the two diffs together, then regenerate the report from that commit. `report.json` should record a dirty-tree flag. | CONFIRMED |
| E7 | high | secret leak (pending) | evaluation/fetch_more_malware.py:69, 87-88; evaluation/new_malware_fetch.jsonl (tracked, modified) | The AndroZoo key is sent as a URL query parameter, and `str(exc)[:120]` from requests ConnectionError includes that URL. The working-tree copy of the tracked log has **5 lines containing `apikey=<key prefix>`**; HEAD has 0. (Value not reproduced here.) | The next `git add` / commit of this modified tracked file publishes the AndroZoo key to GitHub. | Log `type(exc).__name__` only. Scrub the 5 lines before committing. Rotate the key. | CONFIRMED |
| E8 | medium | selective reporting | malben_eval/run_retrained_t070/report.json (untracked) | The same retrained model at 0.7 was also scored on the hash-clean 200-APK manifest: **189/200 = 94.5%**, malware recall 93/100. README reports only the 300-APK run (97.3%). | Readers see the better of two holdout looks. | Report both runs, or say why the 200 set was retired. It was used for diagnosis (run_200, run_fixed). | CONFIRMED (files); PLAUSIBLE (intent) |
| E9 | medium | silent result mixing | scripts/evaluate_malben.py:76-89, 287-291, 348 | `_load_done` resumes every `status=ok` row from an existing predictions.csv without checking model or threshold. The default `--out-dir` is the shared `evaluation/malben_eval/`. The report then stamps the *new* model and threshold. | Re-running with a different `--model`/`--threshold` into the same directory yields a report whose rows came from a different configuration. | Store model_sha and threshold per row, and resume only matching rows (or refuse when they differ). | CONFIRMED |
| E10 | medium | dead features | classifier_data/features.csv; malben_eval/split_features.csv; analysis/classify_fast.py:16, 72 | `target_sdk` is 0 in **all 509** training rows, `min_sdk` is non-zero in 1 row, and the split features show the same pattern (medians 0). So 2 of the 15 features carry no signal. The root cause is in analysis/ (`target_sdk_version` key), outside this slice. | The model is effectively 13 features. METHODOLOGY ablations over these features are meaningless. | Fix the manifest key in step 1/classify_fast, then retrain. | CONFIRMED |
| E11 | medium | label noise from disk state | classifier_eval_2026-10-23/pool_score.py:37-40; tune_pool.py:27, 39; score_v2.py:27, 31 | New-pool labels are `malware iff samples/new_malware/<sha>.apk exists on this disk`. A moved or deleted malware file is silently labeled benign. | Results depend on gitignored local state and cannot be reproduced. | Read labels from the tracked `new_all_gt.csv` (sha, group). | CONFIRMED |
| E12 | medium | denominator | evaluation/metrics_recompute.py:105-107, 155, 354-363; reeval_families.py:76-79 | GT rows without a prediction are dropped from the accuracy denominator (stderr warning only). reeval only re-scores samples with a cached `analysis/work/<sha>/pipeline_result.json`, so the 352 denominator excludes samples that never produced a result. | Samples that never ran don't count against accuracy, so the score is inflated by that selection. analysis/work is gitignored, so it can't be reproduced. | Join from GT, not from predictions, and count missing rows as wrong. | CONFIRMED |
| E13 | low | holdout reuse (LAMDA) | classifier_eval_2026-10-23/extra_score.py:3, 18 (+ extra_score_fp0.05/0.10/0.16.json, frozen_config.json); pool_score.py; score_v2.py; tune_pool.py; lamda_fetch/model_compare.py; learning_curve.py | Docstrings say LAMDA is "scored once". But extra_score ran at 3 FP ceilings × 3 arms, and `frozen_config.json` freezes the arm and ceiling (extra_only, 0.16) with the highest LAMDA detection (0.9412). Five more scripts each score LAMDA again. Not a README headline. | The LAMDA detection numbers in docs are tuned on that holdout. | Freeze the config before any LAMDA scoring, or call the result "selected". | CONFIRMED (files) |
| E14 | low | unverifiable literal | evaluation/source_aware_eval.py:216-217, 244 | It writes a hardcoded "held-out 200 ... 0.970 overall, 0 FN, 6% FP; CV 0.906" into metrics.json. The source `real_world_accuracy_report.json` has no per-sample hashes and describes an older 20-feature model. | A stale, unverifiable metric is presented as "deployment-grade". | Drop the literal, or compute it. | CONFIRMED |
| E15 | low | threshold noise | malben_eval/retrain_result.json; retrain_with_extra.py:57 | 0.7 is the single argmax of a 13-point sweep on 100 rows (50 benign). The 0.65→0.7 step changes only 2 benign apps. | The threshold is noisy. It held up on the 300-set, but expect drift. | Report the sweep curve, or pick from a stability plateau. | PLAUSIBLE |
| E16 | low | metric math consistency | evaluation/metrics_recompute.py:133-141 vs 150; same in run_validation_359.py:311-336 | Macro precision/recall use exact string equality, while accuracy uses alias-aware `is_correct`. Mojibake `ΓÇö` appears in comments and printed text (:34, 102, 359). | Macro P/R undercount alias matches, so they are inconsistent with accuracy. | Compare canonicalized labels in both places. | CONFIRMED |
| E17 | low | fetch robustness | evaluation/fetch_lamda_apks.py:59-61, 75-84 | On a download error the partial `.apk` is left at `samples/lamda/<sha>.apk`. Error rows go into `done`, so they are never retried. | A truncated APK sits under a valid name; `run_lamda_pipeline` would analyse it. | Write to `.part` and rename; exclude error rows from `done`. | CONFIRMED |
| E18 | low | env drift | malben_eval/run_fresh_t070/report.json (`python 3.13.14`, `sklearn 1.9.0`); requirements-lock.txt (`scikit-learn==1.7.2`); CI python 3.10 | The headline ran outside the pinned environment. RF pickles saved by 1.9 may warn or behave differently under 1.7.2. | "Anyone can re-run this" (evaluate_malben.py:3) does not hold in the locked environment. | Re-run under the lock, or bump the lock to the version used. | PLAUSIBLE |

Checked and correct: Wilson CI math (recomputed 292/300 → [0.9483, 0.9864]; 146/150 → [0.9334, 0.9896]). Errors count as wrong in every rate (compute_metrics). train_extra ∩ validation = 0. fresh ∩ {features.csv, train_extra, validation, manifest200, pilot, holdout_split_v1, LAMDA lists} = 0. The README training/validation counts (509 + 100, validation 98% / 0 benign flagged at 0.7, AUC 0.9816→0.9944) match retrain_result.json. `make_holdout_split.py` is deterministic and stratified. `select_lamda_samples.py` splits by family (sound for family OOS testing). `cv_ablation.py` refits per fold.

---

## 3. Root-script findings (most severe first)

| id | sev | category | file:line | finding | consequence | minimal fix | tag |
|---|---|---|---|---|---|---|---|
| R1 | critical | destructive script | cleanup.ps1:4-5, 10-13, 46, 61-62 | It runs `Remove-Item -Recurse -Force D:\DroidForensix\evaluation`, which deletes all tracked evaluation code and data. It also deletes `.claude`, `droidforensix_llm.py` (imported at backend/main.py:21), and `backend/pdf_report.py` (imported at backend/routers/reports.py:15). | One run breaks the backend at import time and wipes the evidence behind every README number. | Delete cleanup.ps1. | CONFIRMED |
| R2 | high | CI break | tests/test_stage3_replay.py:30; stage3_replay.py:24; .gitignore:230 (`rto_analysis/*`) | The acceptance test reads `rto_analysis/phase2/installer_deobfuscated_strings.json`. That file is gitignored and untracked (`git ls-files rto_analysis` → 3 other files). It passes locally only because the file exists on this disk. | On a fresh clone or in CI, all 4 tests raise FileNotFoundError, and the "faithful port" acceptance check is not verifiable by anyone else. | `git add -f` the 8 KB fixture (plus `hole1_czrr_definitive.md`), or `pytest.skip` when absent. | CONFIRMED |
| R3 | medium | packaging | pyproject.toml `py-modules` (lines 31-41); brute_replay.py:4-9 | `pip install .` installs 9 one-off scripts as top-level modules (`ioc_scanner`, `batch_classify`, `metrics_summary`, …). `brute_replay` has no main guard: importing it reads CWD-relative files and raises FileNotFoundError. `packers` is missing (see P10). | It pollutes site-packages with generic names, and `import brute_replay` crashes. | Keep only `stage3_replay` and `droidforensix_llm` in py-modules. | CONFIRMED |
| R4 | low | port fidelity | stage3_replay.py:96-102, 15-16, 168 | Line 96 computes `chunk` with Java truncation, but `pos = i % 0x1FFF` uses Python floor-mod. Java `rem-int` is negative for negative `i`, so the VM would throw, while the port returns a char. The `pos < 0` branch is dead. The docstring says "174 exact + 6", but main and the test assert 175/5. `main()` writes `replay_result.txt` into the repo root. | The port is not faithful for negative indices; a crash in Java shows up as a mismatch here. The acceptance result is unaffected (175/5 still holds). | `pos = int(math.fmod(i, 0x1FFF))`; fix the docstring; write output to a temp dir. | CONFIRMED |
| R5 | low | broken script | metrics_summary.py:4-7, 46, 67 | It reads `evaluation_results/campaign_purity.json` and `campaign_purity_final.json`, which are gitignored and untracked. Division by zero when `total == 0`. Unused `os` import. | It crashes on any clone. | Delete (one-off). | CONFIRMED |
| R6 | low | double counting | classify_malware_batch.py:6-13, 25-33, 49-60 | It lists `samples/malware` *and* its subdirectories as separate roots. A sha present in two dirs is appended twice, because `processed_shas` is not updated in the loop. It deduplicates against the uncorrected `ground_truth_all.csv`. | Duplicate rows in `untested_malware_all.csv` inflate counts. | Deduplicate `apks` by sha. Superseded by scripts/evaluate_malben.py: delete. | CONFIRMED |
| R7 | low | nondeterminism | batch_classify.py:8, 11, 17, 23 | It slices unsorted `os.listdir()[20:40]`, prints "/100", and writes `legitimate_predictions_20_40.csv` (untracked). | Which APKs get scored differs per filesystem. | Delete (superseded by classify_all_legitimate.py / evaluate_malben.py). | CONFIRMED |
| R8 | low | hardcoded paths | batch_classify.py:2, 7, 23; classify_all_legitimate.py:2, 8, 13; classify_malware_batch.py:2-13, 22, 38; ioc_scanner.py:14-33, 561-562; decompile_java.py:5; metrics_summary.py:4-56; evaluation/run_validation_359.py:70 | Absolute `D:/DroidForensix/...` paths, an upload UUID path, and a per-user Ollama exe path under `C:\Users\<user>\AppData`. | These only run on the author's machine. The user path discloses the account name in a public repo. | Use `Path(__file__).parent`; read `OLLAMA_EXE` from the environment only. | CONFIRMED |
| R9 | low | misleading output | ioc_scanner.py:35-40, 587-588 | Four hardcoded "known decrypted C2" domains are added to the catalog unconditionally, as if scanned. Also line 259 is a dead branch and line 265 classifies twice. | The catalog reports IOCs the scan never found. | Label them as seeded, or drop them. | CONFIRMED |
| R10 | low | dead code | decompile_java.py:5-27 | The loop does nothing: `DecompilerDAD` is never used and the body is `pass`. | No value. | Delete. | CONFIRMED |

Lint (ruff 0.17.1, run read-only; these paths are not in CI): 40 findings across slice files. Mostly B905 (`zip` without strict) and F401. Notable: evaluation/run_validation_359.py:33-34 unused re-export imports that metrics_recompute relies on (keep them; add `# noqa`). Also evaluation/lamda_fetch/model_compare.py:42 unused `n_base`, and packers/myg0n.py:14.

---

## 4. site/ findings

| id | sev | category | file:line | finding | consequence | minimal fix | tag |
|---|---|---|---|---|---|---|---|
| S1 | medium | missing caveats | site/index.html:222, 264-280 | "How the holdout was kept clean" and the caveats cover only CI width. Nothing says the holdout malware is 100% Drebin-era and the benign apps are 100% F-Droid (E3), or that the CLI default is a different model with 70% Play-store FPR (E4). | The public page overstates how far the result generalizes. | Add two caveat bullets (sources/era, deployed-model difference). | CONFIRMED |
| S2 | low | hardcoded numbers | site/index.html:7, 193, 227-237, 249-253, 287-290, 313 | Every figure is literal HTML, not computed from predictions.csv. **They are currently consistent.** I checked: site/predictions.csv has 300 rows identical to run_fresh_t070/predictions.csv (0 differences in label, prediction, correct, or confidence); TP/FN/TN/FP = 146/4/146/4; the CIs match report.json; the README numbers match. The "no overlap" claim checks out (computed 0). | A future CSV refresh will drift from the HTML without anyone noticing. | Compute the headline from the loaded CSV. | CONFIRMED |
| S3 | low | labelling | site/index.html:288, 334 | The "Errors · 8" chip filters *wrong predictions*, while report.json has `errors: 0` (pipeline errors). | It conflates two meanings of "error". | Rename to "Wrong · 8". | CONFIRMED |
| S4 | low | parser | site/index.html:315-324 | The naive `split(',')` CSV parser works for the current 6-column CSV. The full schema's `error` column contains commas. | Columns misalign if the CSV schema changes. | Quote-aware split, or keep the 6-column export. | PLAUSIBLE |

The confidence column is already 0–100 (classify_fast.py:112), so the "%" suffix is correct.

---

## 5. Reproducibility check (README "Honest numbers")

| README number | Backing file | Tracked? | Reproducible from tracked files? |
|---|---|---|---|
| 97.3% (292/300), CI 94.8–98.6, recall 146/150, specificity 146/150 | evaluation/malben_eval/run_fresh_t070/report.json | **No** (untracked). The same rows are in site/predictions.csv (tracked). | **No.** The model `malben_rf_retrained.pkl`, `fresh_manifest.csv`, and the `--model/--threshold` code (uncommitted diff) are all untracked; APKs live in gitignored `samples/`. Only the per-row outcome table is tracked (site/predictions.csv). |
| Threshold 0.7, validation 98% / 0 benign flagged, AUC 0.9816→0.9944 | evaluation/malben_eval/retrain_result.json | No | No (split_features.csv, train_extra.csv, validation_split.csv, retrain_with_extra.py are untracked) |
| Training 509 + 100 | classifier_data/features.csv (tracked, 509); train_extra.csv (untracked, 100) | Partly | Partly |
| "No hash overlaps with training or validation" | none; my computation | n/a | True (computed 0), but evaluate_malben's own guard checks the wrong set (E5) |
| Pilot 55% (11/20) | evaluation/FRESH_CORPUS_RESULT.md (tracked); malben_eval/pilot20/report.json (untracked) | Doc yes, data no | Doc only |
| Family 64.2% (226/352), 68.6% specific (216/315) | evaluation/metrics/metrics.json = metrics_v2/metrics.json + metrics_v2/predictions.json | Yes | Metrics recompute from tracked predictions + ground_truth_all_corrected.csv: yes. Regenerating the predictions needs gitignored analysis/work. The number is in-sample (E2). |
| C2 2.4% (9/380), 68% benign | evaluation_results/fp_final_report.json (force-tracked) | Yes | Counts match (9 malicious, 260/380 = 68.4% benign). But the 9 are not "confirmed genuine C2" (E1), and the sample count is 22, not 352. |
| "352 samples … checked against VirusTotal and MalwareBazaar" | ground_truth_all_corrected.csv | Yes | Plausible. Indicator data covers only 22 samples. |

---

## 6. Delete / merge candidates

- **Delete:** `cleanup.ps1` (R1, dangerous). `decompile_java.py` (R10, no-op). `brute_replay.py` (superseded by stage3_replay.py; it tests a wrong state variant, `t1` instead of `t2`). `batch_classify.py` (R7). `metrics_summary.py` (R5, inputs untracked).
- **Merge into scripts/evaluate_malben.py, then delete:** `classify_all_legitimate.py`, `classify_malware_batch.py` (same loop over `classify_malware_fast`, without manifest/hash/leakage checks). `scripts/evaluate_fresh_corpus.py` also overlaps evaluate_malben (pilot path).
- **Move out of root:** `ioc_scanner.py` (single-sample research tool with absolute paths) → `scripts/research/`. Remove it from `py-modules`.
- **Evaluation:** `evaluation/predict_with_model.py` duplicates `score_benign_classifier.py` scoring. `retrain_play_cv.py`, `lamda_fetch/threshold_sweep.py`, `model_compare.py`, `learning_curve.py`, and `classifier_eval_2026-10-23/{extra_score,pool_score,score_v2,tune_pool}.py` each rebuild the same 5-fold RF + threshold-from-benign-OOF helper; one shared helper would cut about 200 lines. `extract_new_all.py`, `extract_new_benign.py`, `build_*_features.py` and `mine_kb.py` are 12–21-line wrappers (fine; just research scaffolding). `evaluation/clean_family_train.csv` + `family_classifier_clean.pkl` (16.5 MB) are flagged contaminated in HOLDOUT_SPLIT.md:27-34; delete or move. `evaluation/classifier_data/` has 514 per-sample JSON files that are duplicated by features.csv.

---

## 7. Coverage

All code files in the slice were read fully, every line. Data files (.csv/.json/.jsonl/.pkl/.npz) were not line-read; I checked them for size, tracked status, overlaps, and sources as described above.

| file | lines | tracked | read fully |
|---|---:|---|---|
| packers/__init__.py | 30 | yes | yes |
| packers/framework.py | 142 | yes | yes |
| packers/myg0n.py | 94 | yes | yes |
| packers/breaker/blobs.py | 225 | yes | yes |
| packers/breaker/engine.py | 562 | yes | yes |
| packers/breaker/schemes.py | 265 | yes | yes |
| packers/breaker/seeds.py | 161 | yes | yes |
| batch_classify.py | 26 | yes | yes |
| brute_replay.py | 173 | yes | yes |
| classify_all_legitimate.py | 74 | yes | yes |
| classify_malware_batch.py | 92 | yes | yes |
| decompile_java.py | 27 | yes | yes |
| ioc_scanner.py | 777 | yes | yes |
| metrics_summary.py | 67 | yes | yes |
| stage3_replay.py | 181 | yes | yes |
| cleanup.ps1 | 65 | yes | yes |
| evaluation/classifier_eval_2026-10-23/build_pilot_features.py | 14 | yes | yes |
| evaluation/classifier_eval_2026-10-23/cert_api_features.py | 70 | yes | yes |
| evaluation/classifier_eval_2026-10-23/extra_features.py | 127 | yes | yes |
| evaluation/classifier_eval_2026-10-23/extra_score.py | 78 | yes | yes |
| evaluation/classifier_eval_2026-10-23/pilot_score.py | 88 | yes | yes |
| evaluation/classifier_eval_2026-10-23/pool_score.py | 103 | yes | yes |
| evaluation/classifier_eval_2026-10-23/score_v2.py | 75 | yes | yes |
| evaluation/classifier_eval_2026-10-23/tune_pool.py | 84 | yes | yes |
| evaluation/cv_ablation.py | 116 | yes | yes |
| evaluation/extract_classifier_features.py | 46 | yes | yes |
| evaluation/extract_new_all.py | 12 | yes | yes |
| evaluation/extract_new_benign.py | 12 | yes | yes |
| evaluation/family_ensemble_eval.py | 322 | yes | yes |
| evaluation/fetch_fdroid_benign.py | 93 | yes (uncommitted diff) | yes |
| evaluation/fetch_lamda_apks.py | 93 | yes | yes |
| evaluation/fetch_more_malware.py | 95 | yes (uncommitted diff) | yes |
| evaluation/lamda_fetch/build_binary_features.py | 33 | yes | yes |
| evaluation/lamda_fetch/build_eval_features.py | 14 | yes | yes |
| evaluation/lamda_fetch/build_kb_features.py | 14 | yes | yes |
| evaluation/lamda_fetch/learning_curve.py | 45 | yes | yes |
| evaluation/lamda_fetch/mine_kb.py | 21 | yes | yes |
| evaluation/lamda_fetch/model_compare.py | 68 | yes | yes |
| evaluation/lamda_fetch/monitor.html | 76 | yes | yes |
| evaluation/lamda_fetch/packed_check.py | 68 | yes | yes |
| evaluation/lamda_fetch/score_kb.py | 63 | yes | yes |
| evaluation/lamda_fetch/threshold_sweep.py | 65 | yes | yes |
| evaluation/make_baseline.py | 80 | yes | yes |
| evaluation/make_holdout_split.py | 91 | yes | yes |
| evaluation/metrics_recompute.py | 372 | yes | yes |
| evaluation/misclassification_analysis.py | 159 | yes | yes |
| evaluation/predict_with_model.py | 56 | yes | yes |
| evaluation/reeval_families.py | 104 | yes | yes |
| evaluation/retrain_play_cv.py | 74 | yes | yes |
| evaluation/run_benign_pipeline.py | 54 | yes | yes |
| evaluation/run_lamda_pipeline.py | 70 | yes | yes |
| evaluation/run_malware_baseline.py | 68 | yes | yes |
| evaluation/run_validation_359.py | 507 | yes | yes |
| evaluation/score_benign_classifier.py | 59 | yes | yes |
| evaluation/select_lamda_samples.py | 65 | yes | yes |
| evaluation/source_aware_eval.py | 249 | yes | yes |
| evaluation/malben_eval/extract_split_features.py | 101 | **untracked** | yes |
| evaluation/malben_eval/retrain_with_extra.py | 110 | **untracked** | yes |
| scripts/evaluate_malben.py | 359 | yes (uncommitted diff, read with diff) | yes |
| site/index.html | 371 | yes | yes |

Skipped as instructed: droidforensix_llm.py, run_full_pipeline.ps1. Context read but not audited: analysis/classify_fast.py (lines 1-115 and diff), analysis/mine_family_knowledge.py:1-60, the README "Honest numbers" section, and the evaluation/*.md provenance notes.
