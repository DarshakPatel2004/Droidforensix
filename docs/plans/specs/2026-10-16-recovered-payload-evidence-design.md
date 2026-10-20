# Recovered Payload Evidence - Design Spec

**Date:** 2026-10-16
**Approach:** Static evidence extraction from recovered payloads, merged additively into the classifier's inputs
**Status:** Pending user review
**Related docs:** `docs/plans/2026-10-15-master-key-breaker-plan.md`,
`docs/plans/specs/2026-10-15-master-key-breaker-design.md`,
`docs/accuracy-improvement-plan.md`, `analysis/recovered/PENDRIVE_MASTER_KEY_INTEL.md` (local-only),
`evaluation/VALIDATION_359.md`

---

## 1. Overview

The Master Key breaker now runs as a bounded second chance inside
`analysis/step0_master_key.py`. When it recovers a payload it materialises it into the
layout the pipeline already reads (`<work_dir>/<sha16>/kit.zip`) and
`enrich_strings_with_recovered` mines **strings** from it. Nothing else about the
payload reaches the classifier.

That leaves most of the recovered evidence on the floor. Inspection of the
breaker's own local evidence (`analysis/master_key_breaker/<sha16>/hit.json`,
gitignored) shows the recovered payloads are usually the **genuine application**, not
spare strings:

| Sample | Recovered payload member | What it actually is |
|---|---|---|
| PNB ONE ACTIVATION (`49b59c87`) | `assets/trustifying` | 50-member ZIP: **49 `classes*.dex`** (multidex, up to 1.15 MB each) + 1 xml |
| PNB ONE ACTIVATION | `assets/protoconidagropyron` | a **full APK**: `AndroidManifest.xml` (10 KB), `resources.arsc` (995 KB), 39 png, res/ |
| PNB ONE ACTIVATION | `assets/heeleyaccommodateness` | native payload: `arm64-v8a`, `armeabi-v7a`, 4.6 MB blob |
| `fea09cb6` (`fea09cb62...`) | `assets/4qZE2YiJUkIj2a2a/RioFpQvI` | `classes.dex`, 578 KB |
| M PARIWAHAN / `ff742233` | `assets/dKcSeAyvsM`, `assets/zAVokcYn` | 7.5 MB payload; shared 1.4 MB payload `dd7cfd96...` across samples |

The classifier's family signals are exactly the ones sitting unused in there. Signatures
score on the class count - we observed `Ermac` matched on `classes:1224` and
`classes:1501` - and the LLM assessment reasoned about `REQUEST_INSTALL_PACKAGES`, which
comes from the manifest. Today the classifier sees only the **stub's** manifest and the
**stub's** class count, because the real code and manifest arrived after extraction (the
breaker runs at step 0, after `extract_apk` at step 1, and nothing merges back).

**This effort** extracts classes, permissions, and native-library evidence from the
recovered payloads and merges it additively into `extraction` at the one place the
pipeline already performs master-key enrichment.

## 2. Goals

1. Recovered payloads contribute their **real class count**, **manifest permissions**,
   and **native libraries** to the classifier's inputs.
2. The merge is **additive**: nothing the stub contributed is ever deleted.
3. Evidence is extracted **statically, in memory**, with no new dependency, no apktool
   or JADX invocation, no payload execution, and no new files on disk.
4. **No fabricated evidence**: any parse failure contributes nothing and is recorded as
   diagnostics.
5. The blast radius is confined to samples that were previously unclassified misses -
   see 4.5.

## 3. Non-Goals

- **No change to the unpack recovery path.** `_attempt_unpack` recoveries keep their
  current behaviour (strings only). See 4.5.
- **No change to string enrichment.** `enrich_strings_with_recovered` continues to mine
  the first `kit.zip` only.
- **No signature-band recalibration.** The class count gets a larger, truer value; the
  bands are untouched.
- **No apktool/JADX, no smali, no `resources.arsc` parsing, no API-call-level analysis.**
  This is evidence extraction, not re-analysis of the recovered app.
- **No changes to `packers/breaker/*` or `scripts/unpack.py`.**
- **No new dependency** (androguard is already required by step 1).

## 4. Design Decisions

### 4.1 Analysis runs inside the breaker's second chance, in memory

`_breaker_second_chance` already re-derives each top-level hit's plaintext via
`_materialize_payload(apk_path, hit)`. The new collector consumes those same byte
strings, so no new disk layout, no extra extraction, and nothing to clean up.

Only payloads that pass the engine's structural validation (`validation` starts with
`zip`) are analysed. The two `xor:single-byte` / `validation=json` recoveries therefore
produce no evidence and cannot alter anything - they stay inert exactly as the previous
effort verified.

### 4.2 Evidence collected, and how

| Signal | Source in the payload | Method |
|---|---|---|
| Class count | every non-empty `*.dex` member | `androguard.core.dex.DEX(...).get_classes()` |
| Permissions | `AndroidManifest.xml` member | `androguard.core.axml.AXMLPrinter` -> text -> the same `uses-permission` regex step 1 already uses |
| Native libraries | members under `lib/`, named `*.so`, or whose first bytes are `\x7fELF` | path/extension hint plus magic sniff (no ELF parsing) |

Class count is apples-to-apples with the stub's: `extract_apk` computes
`decompiled_classes` with the same androguard `DEX` class enumeration. Permissions are
the same strings apktool yields for the stub manifest, so the signature matcher sees a
consistent vocabulary.

A recovered payload may hold several ZIP members that are themselves ZIPs; this spec
deliberately analyses **one level** (the payload's own members), matching the engine's
`artifacts` listing. Nested members are a follow-up, not a goal.

### 4.3 Merge policy: additive, into `extraction`, at one site

`analysis/pipeline.py` performs master-key enrichment at one site (~line 470) with a
`try/except`. The merge happens there, into the local `extraction` dict:

```
extraction["decompiled_classes"]              = max(stub, payload)
extraction["native_libs_found"]               = sorted(union(stub, payload))
extraction["manifest_info"]["uses_permissions"] = sorted(union(stub, payload))
extraction["recovered_payload_evidence"]      = <provenance record>
```

One site is sufficient because everything downstream reads *from* `extraction`:

- both result assemblies (~648 and ~785) copy `native_libs_found` and
  `decompiled_classes` into `result["extraction"]`, and `uses_permissions` into
  `result["manifest"]`;
- `manifest_perms = manifest.get("uses_permissions", [])` (~918) feeds step 15;
- `family_id` reads `extraction["decompiled_classes"]` as `class_count` (~1685),
  `extraction["native_libs_found"]` (~1686), and `result["manifest"]["uses_permissions"]`
  as the permission fallback (~1521).

The merge site (~470) is comfortably before all of them (~636 onward), so no ordering
change is needed.

### 4.4 Class count is banded, so "additive" does not compose for it

This is the finding that shaped the merge. Signature rules declare
`class_count_min` / `class_count_max` bands (e.g. 100-700, 50-300, 10-50,
`backend/family_id.py:123-443`), not thresholds. A value cannot be in two bands, and the
real app's count (thousands, across up to 63 dex members per payload) falls outside most bands - so
merging the real count can make the `classes:` signal **disappear**, which is a
subtraction even though the merge is "additive".

Decision (user-approved): merge as `max(stub, payload)`. It is the most truthful single
value for "how big is the real app", it also improves the LLM context ("Total classes:
N"), and it accepts that stub-calibrated bands may stop matching on recovered samples.

**Documented fallback:** if the A/B (section 9) shows the class-count merge makes the
metric worse, the class-count merge is dropped - `decompiled_classes` keeps the stub's
value and the payload's count lives only in the provenance record
(`extraction["recovered_payload_evidence"]["class_count"]`), which no band consumes - and
the outcome is recorded in the plan's Amendments. Recording the measurement is the
acceptance; silently keeping a losing merge is not acceptable.

`native:no` is also a signal in some rules, and unioning native libraries can flip it to
`native:yes`. That flip is faithful - the real app does carry native libraries - and it
is called out here so the A/B readings are not misread as noise.

### 4.5 Scope: breaker second chance only, deliberately

The merge is wired to breaker recoveries, not to `_attempt_unpack` recoveries.

Rationale (superseded by the measurement in section 12): the first version of this
scope was chosen to avoid moving samples that are currently predicted correctly. The
dev anchor run measured that premise: all 7 dispatcher-recovered dev samples are
currently wrong, so unpack-path evidence cannot turn a correct prediction wrong.

Unpack-path parity is done (section 12).

### 4.6 Provenance is recorded, not just applied

`extraction["recovered_payload_evidence"]` keeps the evidence and its dimensions
(counts, member names scanned, errors, truncation). It is additive: no existing consumer
keys off it, and it makes the report auditable - the same reason the breaker records
typed diagnostics instead of hiding them.

## 5. Honesty & Validation

- **No fabrication.** A payload that fails to parse contributes nothing; a member over
  the size cap is skipped and counted; caps set `truncated`. The evidence is a record of
  what was actually read.
- **Never raises.** The collector returns partial results plus diagnostics. The pipeline
  merge stays inside the existing `try/except`, so a fault leaves `extraction` exactly as
  `extract_apk` produced it.
- **Measured, not asserted.** The effect is reported as an off/on A/B delta over the
  breaker-recovered samples, against a named baseline revision. The previous effort
  established that `evaluation/validation_359/validation_report.json` (24-Sep, 0.3598) is
  not reproducible from the current 323-row manifest; the newest self-consistent baseline
  is `predictions.json` + `validation_report.partial.json` (6-Oct, 265 rows, accuracy
  0.3547), and that is what the delta is computed against.
  *(2026-10-18: the anchor has since moved. A fresh dev-side baseline on the current
  manifest now backs new A/Bs - see `evaluation/DEV_BASELINE.md` - and this phase's
  recorded delta keeps its 6-Oct anchor as a matter of record.)*
- **Corpus-level claims are labelled as such.** The evidence table in section 1 is read
  from local `hit.json` files, not extrapolated.

## 6. Budgets & Determinism

Named constants in `analysis/payload_evidence.py`, exposed as parameters with defaults:

| Constant | Default | Purpose |
|---|---|---|
| `MAX_PAYLOAD_BYTES` | 64 MiB | total payload bytes analysed per sample |
| `MAX_MEMBER_BYTES` | 32 MiB | per-member skip threshold (the observed 4.6 MB blob passes; a decompression bomb does not) |
| `MAX_DEX_MEMBERS` | 64 | dex members parsed **per payload** (the observed multidex payload carries 63; the counter resets for the next payload so a multi-payload recovery is not truncated cumulatively) |
| `EVIDENCE_BUDGET_S` | 20 | wall-clock guard; on expiry, stop adding and set `truncated` |

Permissions and native-library names are sorted; class count is a sum over parsed dex
members. Re-running on the same payload yields identical evidence.

## 7. Component Changes

| File | Change |
|---|---|
| `analysis/payload_evidence.py` | **new** - pure collector: `collect_payload_evidence(payloads, *, caps) -> dict`, plus `class_count_from_dex`, `permissions_from_binary_manifest`, `native_lib_names`, and a pure `merge_evidence(extraction, evidence) -> dict` |
| `analysis/step0_master_key.py` | gather ZIP-validated top-level hit payloads after materialisation; attach the additive `recovered_evidence` key to the returned report. `ecode`, `verdict`, `is_e_coded`, `taxonomy`, `should_enrich_strings` unchanged |
| `analysis/pipeline.py` | one call to `merge_evidence` inside the existing enrichment `try/except` (~470) |
| `tests/test_payload_evidence.py` | **new** unit tests |
| `tests/test_step0_master_key.py` | extended wiring tests |
| `tests/test_breaker_corpus.py` | opt-in real-payload evidence tests |

Untouched: `packers/breaker/*`, `scripts/unpack.py`, the unpack recovery path, string
enrichment.

## 8. Data Contracts

**Evidence record** (returned by the collector, attached as
`master_key["recovered_evidence"]`, mirrored into
`extraction["recovered_payload_evidence"]`):

```json
{
  "payloads": 3,               // ZIP-validated payloads analysed
  "members_scanned": 103,      // members seen
  "members_skipped": 2,        // over-size / over-count / unreadable
  "class_count": 41203,        // sum over parsed DEX members; 0 if none parsed
  "permissions": ["android.permission.REQUEST_INSTALL_PACKAGES", "..."],  // sorted
  "native_libs": ["arm64-v8a", "armeabi-v7a"],                            // sorted
  "truncated": "none|bytes|members|budget",
  "errors": ["androidManifest.xml: AXMLPrinter: ..."]
}
```

**Invariants**

- No key material in the evidence or anywhere in the returned report (same rule as the
  wiring effort; `key_hex` stays in the gitignored `hit.json`).
- `ecode` never carries breaker or evidence outcomes; those live only in `breaker` and
  `recovered_evidence`.
- A miss (no recovery) produces no `recovered_evidence` key and therefore no merge.
- The merge never removes an existing value from `extraction`.

## 9. Testing Plan

**Unit (`tests/test_payload_evidence.py`, TDD, RED first)**

- `merge_evidence`: `max` for class count; sorted union for permissions and natives;
  stub values never removed; empty evidence is a no-op; idempotent; missing
  `manifest_info` is created defensively.
- `class_count_from_dex`: 0-byte input -> 0 (the observed `classes.dex` stub); garbage
  input -> 0 plus a recorded error, no exception.
- `native_lib_names`: synthetic ELF-magic members detected; plain data ignored.
- `permissions_from_binary_manifest`: decoded-text path returns the exact permission
  strings; malformed input -> `[]` plus an error.
- Caps: an over-size member sets `truncated`; `MAX_DEX_MEMBERS` is honoured.

**Opt-in real-payload tests (`tests/test_breaker_corpus.py`, `DFX_BREAKER_ACCEPTANCE=1`)**

- PNB ONE ACTIVATION, through the real breaker: `class_count > 7000` (its multidex payload
  carries 63 dex members), 22 permissions including
  `android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` and `android.permission.SEND_SMS`
  (measured 2026-10-16 - this manifest does **not** carry `REQUEST_INSTALL_PACKAGES`, contrary
  to an earlier draft of this section), and four native members of which two,
  `arm64-v8a` and `armeabi-v7a`, are detectable only by ELF magic.
- Two further real recovered apps in `analysis/recovered/` for class-count and permission
  coverage, and one for native libraries.
- A sample with no recovery: `recovered_evidence` absent from the pipeline result.

**Wiring tests (`tests/test_step0_master_key.py`)**

- Breaker miss: no evidence key; the existing contract tests (miss preservation, typed
  outcome in `breaker`, no key material) keep passing unchanged.
- Breaker ZIP recovery: evidence present with expected counts.
- Non-ZIP (`validation=json`) recovery: no evidence (inertness preserved).

**A/B acceptance (off/on, reuse of the previous effort's harness)**

- Run the pipeline twice per breaker-recovered sample in one process - evidence merge
  disabled vs enabled - and report the exact delta on accuracy, macro-precision and
  macro-recall against the 6-Oct baseline.
- Confirm samples with no breaker recovery are unchanged.
- Record the outcome, and the class-count fallback decision (4.4), in the plan's
  Amendments.

**Suite gate:** `pytest tests/ -m "not slow"` stays green.

## 10. Acceptance Criteria

1. Evidence extraction is static, bounded, dependency-free, and raises nothing;
   degenerate payloads yield zero evidence rather than an exception.
2. The merge is additive and reaches the classifier through `extraction` only; no other
   module is modified.
3. Samples with no breaker recovery produce no evidence and no merge (verified by test
   and by A/B).
4. The measured A/B delta on the breaker-recovered set is reported honestly, including a
   negative result; if the class-count merge is harmful, the 4.4 fallback is applied and
   recorded.
5. `pytest tests/ -m "not slow"` green; the breaker's existing acceptance tests still
   pass.

## 11. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Larger class count pushes recovered samples out of signature bands, losing matches | Measured by the A/B; documented fallback in 4.4 |
| `native:no` flips to `native:yes`, shifting rules | Faithful to the real app; called out for A/B interpretation |
| A hostile payload causes a parse bomb | Size, count, and wall-clock caps in section 6; no execution ever |
| Evidence leaks key material | Evidence schema is counts/names/permissions only; the existing no-key-material test still gates the result |
| Merge changes behaviour for samples that were previously correct | Scope is breaker-only (4.5): breaker ZIP recoveries were all previously-missed samples |
| AXML parsing differs from apktool's | Permission strings come from the same binary manifest the app ships; asserted by opt-in real-payload tests |

## 12. Follow-ups (not in this effort)

- ~~Unpack-path parity (evidence for `_attempt_unpack` recoveries), with its own A/B.~~
  **Done.** Live A/B on the 7 dispatcher-recovered dev samples, both arms run live:
  evidence attached on 7/7 in the ON arm, 0/7 in OFF; predictions identical in both
  arms; accuracy 0.3553 / macro-precision 0.2822 / macro-recall 0.2956, delta 0.0.
- Mine strings from **all** recovered payloads, not just the first `kit.zip`.
- Nested-members analysis, `resources.arsc`, and smali/API-call-level evidence.
- Recalibrating signature bands against real app sizes rather than stub sizes.
- Resolving the stale evaluation baseline (`validation_report.json`, 24-Sep) so future
  deltas are not anchored to a different manifest revision. **Resolved 2026-10-18:**
  the anchor is the dev-side baseline in `evaluation/DEV_BASELINE.md` (228 rows on the
  current 323-row manifest; command, code revision and result recorded there), which
  also tabulates what each historical artifact actually is. The stale split membership
  is documented in `evaluation/HOLDOUT_SPLIT.md` and pinned by
  `tests/evaluation/test_family_dev_split.py`.
