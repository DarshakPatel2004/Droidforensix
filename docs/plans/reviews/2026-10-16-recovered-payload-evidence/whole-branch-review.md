# Whole-branch review — recovered-payload evidence

**Reviewer:** independent third party (did not write the code)
**Scope:** `703a6b0..aab2eb7` on `main` (10 commits)
**Reviewed at HEAD:** `aab2eb76d9f0e12c477899291363420a3bfc3f70`
**Date:** 2026-10-17
**Binding spec:** `docs/plans/specs/2026-10-16-recovered-payload-evidence-design.md`
**Agreed plan:** `docs/plans/2026-10-16-recovered-payload-evidence-plan.md`
**Ledger:** `.superpowers/sdd/2026-10-16-recovered-payload-evidence-plan/progress.md`

Change set (unchanged from the brief):

```
 analysis/payload_evidence.py                       | 263 +++++++++++++++++++++
 analysis/pipeline.py                               |  14 ++
 analysis/step0_master_key.py                       |  37 ++-
 .../2026-10-16-recovered-payload-evidence-plan.md  |  23 +-
 tests/test_breaker_corpus.py                       |  73 ++++++
 tests/test_payload_evidence.py                     | 224 ++++++++++++++++++
 tests/test_step0_master_key.py                     |  79 +++++++
 7 files changed, 704 insertions(+), 9 deletions(-)
```

---

## 1. Overall verdict

**MERGE-READY (code).** No Critical and no Major defect was found. Every binding
invariant in the brief was checked against the code and holds; the fast suite is green and
the opt-in real-payload tests pass when I ran them myself.

One conditional caveat, owned by the *separate* Task 5 reviewer, not a defect now: the
code always applies `max(stub, payload)` for the class count with no fallback switch. If
the concurrent A/B shows the class-count merge harms the metric, spec §4.4 requires the
fallback (drop the class-count merge, keep the payload count only in provenance) — that
would be a **follow-up code change**, not something present in this branch. As shipped,
the branch implements the spec's default and the plan's agreed path.

---

## 2. Invariant-by-invariant verification

| # | Invariant (from brief) | Verdict | Evidence |
|---|---|---|---|
| 1 | Merge additive/union only; class count `max(stub, payload)`; never delete a stub signal | **HOLDS** | `analysis/payload_evidence.py:248-262`; live check below |
| 2 | `merge_evidence` pure; inputs never mutated; no-op path returns a **fresh** dict | **HOLDS** | `:245-246` `return dict(extraction)`; `:256` copies `manifest_info`; identity/equality check below; `tests/test_payload_evidence.py:177-182` |
| 3 | Breaker is a second chance only; `_attempt_unpack` first, breaker only on non-`RECOVERED` | **HOLDS** | `analysis/step0_master_key.py:326-332` (`if unpack_report.get("verdict") != "RECOVERED"`) |
| 4a | `MAX_PAYLOAD_BYTES` 64 MiB | **HOLDS** | `payload_evidence.py:22` `64 * 1024 * 1024` |
| 4b | `MAX_MEMBER_BYTES` 32 MiB | **HOLDS** | `payload_evidence.py:23` `32 * 1024 * 1024` |
| 4c | `MAX_DEX_MEMBERS` 64 **per payload** | **HOLDS** | `payload_evidence.py:24`; counter is local to `_scan_members` (`:146`, reset per payload); `tests/test_payload_evidence.py:105-111` |
| 4d | `EVIDENCE_BUDGET_S` 20.0 | **HOLDS** | `payload_evidence.py:25` |
| 4e | Truncation typed, never silent | **HOLDS** | `_Tally.cap` first-cap-wins `:119-122`; values `none/bytes/members/budget` `:124-135`; per-member skip sets `bytes` `:152-155`; failed head-read is an `errors` entry (not a silent truncation) `:164-169` |
| 4f | Member rejected by the per-member cap is **never charged** against the payload byte budget | **HOLDS** | `:152-163` cap check `continue`s before `tally.charged += info.file_size`; live check below |
| 5 | Parse failure contributes nothing — counted, never fabricated | **HOLDS** | `_dex_class_count` `:73-80` returns 0 + error; `_member_permissions` `:83-92` returns `[]` + error; broken ZIP `:219-221`; `tests/test_payload_evidence.py:60-65` |
| 6a | No key material in any result | **HOLDS** | evidence schema is counts/member-names/permissions only (`:124-135`); `tests/test_step0_master_key.py:169-185` dumps the whole report incl. the new key and asserts no key/iv hex |
| 6b | Static only, never execute a sample | **HOLDS** | collector is pure `zipfile`/`androguard` reads; no subprocess/exec/import of payload anywhere in the diff |
| 7 | No new dependency | **HOLDS** | `payload_evidence.py` imports only stdlib at module scope (`io, logging, re, time, zipfile, dataclasses, typing`); `androguard` imported lazily inside the two helpers; no requirements/pyproject change in the diff |
| 8 | No new disk artifacts | **HOLDS** | collector is memory-only; `_materialize_hits` docstring `step0_master_key.py:166` "nothing is ever written to disk"; the only writes are the pre-existing `kit.zip` loop |
| 9 | Merge wrapped so it cannot break the enrichment path | **HOLDS** | `analysis/pipeline.py:487-493` own `try/except Exception` with `logger.warning`; runs after the enrichment block, before every result assembly (first assembly at `:651`) |
| 10 | `master_key` contract preserved (`verdict/ecode/artifacts/kdf/is_e_coded/should_enrich_strings`) | **HOLDS** | `step0_master_key.py:363-383`; the new key is additive and conditional (`:381-382`); `tests/test_step0_master_key.py:127-145`, `:337-347` |

Independent live checks I ran (read-only, in-memory, no files written):

```
per-member-reject-not-charged: skipped=1 truncated=bytes   # big(100B) rejected, small(5B) admitted
no-op fresh object: True equal: True
class kept: 99 natives: ['n.new', 'n.old'] perms: ['p.new', 'p.old'] pkg kept: x
input unchanged: 99 ['p.old']
T4 signature columns: 104
```

The first line demonstrates the per-member/per-sample accounting split directly: the
100-byte member rejected by the 10-byte member cap is **not** charged, so the 5-byte member
is still admitted under the 50-byte payload budget (`skipped == 1`; charging the rejected
member would have made it `2`). The merge line shows `max` keeps the larger stub count,
unions both name sets, and preserves the unrelated `manifest_info` key `package` while
leaving the input dict untouched.

---

## 3. Findings

### Critical
None.

### Major
None.

### Minor

**M1 — `analysis/payload_evidence.py:19`: module logger defined but never used.**
`logger = logging.getLogger(__name__)` has no call sites (`grep logger.` in the file:
only `time.monotonic() - started` matches, no `logger.` usage). The plan's Task 1 Step 3
explicitly asked for it, so it is plan-conformant, but AGENTS.md forbids dead code.
Harmless; remove or use for a diagnostics line. **Not a blocker.**

**M2 — `analysis/payload_evidence.py:156-163`: the per-member cap trusts the declared
`info.file_size`.** A crafted ZIP whose central directory under-declares `file_size` could
still inflate past 32 MiB at `member.read()` (`:77`, `:89`). This is the spec's own
declared-size mitigation (§6 "the observed 4.6 MB blob passes; a decompression bomb does
not") and the payload is already the output of a bounded breaker run, so the residual is
accepted by design. Worth recording as a known limitation, not a defect.

**M3 — `analysis/step0_master_key.py:224,255`: all hits are materialized in memory up front.**
`_materialize_hits` holds every recovered plaintext simultaneously and re-reads/re-parses
the whole APK once per hit via `_materialize_payload`. This is a deliberate trade to
analyze every ZIP recovery (the plan requires it; `test_every_zip_recovery_is_analysed…`
pins it) and the observed set is ~10 MB across 7 payloads, but peak memory grows with the
hit count. **Not a blocker.**

**M4 — pipeline merge call site has no fast test.** `analysis/pipeline.py:487-493` is
exercised by no fast test (there is no fast `run_pipeline` test). The plan (Task 3 Step 7,
Self-Review "Known gap") and spec §5 acknowledge this; Task 5 Step 4 is the behavioral
guard and is under a separate concurrent audit. I flagged it, did not duplicate it.

No other discrepancies between spec/plan and code were found. The plan's amended rule 8
(charged scope) matches the code; the Task 3 fixture amendment matches the test; the spec
§9 `REQUEST_INSTALL_PACKAGES` correction matches the opt-in assertions.

---

## 4. Exact test output observed

Runner: `.venv\Scripts\python.exe`, Python 3.13, PowerShell, HEAD `aab2eb7`.

**Fast gate.** The brief's command is `-m pytest tests/ -m "not slow" -q`. `pytest.ini`
already sets `addopts = -q --tb=short`, so the CLI `-q` makes it `-qq`, which suppresses the
final count line. The exact command therefore ends (RC **0**):

```
-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
```

Re-running with the duplicate `-q` removed (same selection) surfaces the count:

```
861 passed, 14 skipped, 16 deselected, 12 warnings in 33.40s
```

Matches the expected `861 passed, 16 deselected`; the 14 skips are **pre-existing**
fixture-absent skips, not new: 13 × "Test APK not found (samples/goodware/benign_eval/*.apk)"
(`tests/test_dissection.py`) and 1 × `tests/test_backend.py:131` "requires real APK + tools".
The branch's new opt-in tests are deselected by `-m "not slow"`, as intended.

**Module tests** `-m pytest tests/test_payload_evidence.py tests/test_step0_master_key.py -q`
(same `-qq` caveat; RC **0**). Without the duplicate quiet flag:

```
39 passed in 2.62s
```

**Opt-in Task 4 evidence tests** (my own run, code verification — *not* the Task 5 A/B;
all four fixtures present):

```
$env:DFX_BREAKER_ACCEPTANCE=1; python -m pytest tests/test_breaker_corpus.py -k evidence
....                                                                     [100%]
4 passed, 12 deselected in 12.30s
```

This independently reproduces the Task 4 claims (real recovered apps yield the asserted
class floors / permissions / native list, and the PNB ONE ACTIVATION end-to-end path runs
the real breaker and collector).

`git status --short`: only the pre-existing untracked user docs
(`docs/HOW_IT_WORKS.md`, `docs/HOW_IT_WORKS.pdf`,
`docs/RTO_encrypted_apk_breakdown_CASE_STUDY.md`, `docs/internal/`). No residue from tests.

---

## 5. Deferred-Minor adjudication

Each finding was re-checked against the code, not accepted from the ledger's framing.

| # | Deferred finding | Code truth | Adjudication |
|---|---|---|---|
| D1 | T1: native predicate treats only a leading `lib/` as lib-dir | `payload_evidence.py:57` `lowered.startswith("lib/") or lowered.endswith(".so") or head[:4] == ELF_MAGIC` | **Acceptable as-is.** APK natives live under a rooted `lib/<abi>/x.so`, so they hit `.so` anyway; a `.so` anywhere is caught by suffix, and a stripped/renamed lib is caught by ELF magic. The spec's wording "path under `lib/`" is satisfied by a leading `lib/`; the opt-in real-payload test's exact 4-name native list (two ELF-magic-only) shows nothing real is missed. No practical miss. |
| D2 | T1: no fast-suite positive-path test for `permissions_from_binary_manifest` | positive path only in `tests/test_breaker_corpus.py:186` (slow + opt-in); fast file has only the raise-path test `tests/test_payload_evidence.py:31-33` | **Acceptable as-is (real but minor coverage gap).** The helper needs genuine AXML bytes to succeed; the repo's documented convention is to cover such parsers opt-in. I confirmed the opt-in positive path passes on real manifests. A fast positive test would need a checked-in AXML fixture — an accepted, deliberate omission, not a defect. |
| D3 | T1: unused module logger | `payload_evidence.py:19`; zero `logger.` call sites | **Acceptable as-is** = M1. Plan-mandated, harmless dead code. Recommend deletion in a cleanup pass. Not a blocker. |
| D4 | T2: evidence keys indexed directly → `KeyError` inside the pipeline `try/except` | `payload_evidence.py:248,252,257`; pipeline guard `analysis/pipeline.py:490-493` `except Exception` | **Acceptable as-is.** The collector always emits all 8 keys (`_Tally.record`), and step0 attaches only collector output, so an out-of-contract record cannot occur in production. If it somehow did, `KeyError` is an `Exception`, caught at the call site (degrades to no-merge, never a crash). Switching to `.get()` would silently swallow a malformed record, which AGENTS.md forbids. The ledger's reasoning is sound and I confirmed the catch. |
| D5 | T2: docstring line uses a plain hyphen where the file's other docstrings use an em dash | `payload_evidence.py:241` (` - `); `grep '—'` over the file returns **zero** em dashes | **Acceptable as-is; the stated rationale is unsupported.** There are no em dashes anywhere in the file, so there is nothing to be inconsistent with. Purely cosmetic. |
| D6 | T3: fixture padding was "not legitimate" (previously refuted with measurements) | `tests/test_step0_master_key.py:29,52-59` `KIT_NATIVE_PAD = 1024`; `packers/breaker/blobs.py:212` `if len(content) < MIN_BLOB_SIZE (512): SKIPPED_SIZE`; `_classify` runs after the extension filter (`:209-214`) | **Correctly refuted; acceptable as-is (not a defect).** I re-derived the sizes in memory: un-padded kit = **302 B**, outer AES member = **304 B** (< 512 → `SKIPPED_SIZE`, never attacked → `FAILED`/`E-KDF-EXHAUSTED`, no evidence); padded kit = **1326 B**, outer member = **1328 B** (> 512 → attacked → `RECOVERED`, `payloads = 1`). The padded test passes in the fast module run. The padding changes no asserted value. Ruling stands. |
| D7 | T4: test signature at `tests/test_breaker_corpus.py:186` is 105 columns | measured length = **104** columns (`Select-String … .Line.Length`) | **Acceptable as-is (cosmetic).** `pyproject.toml` defines no Black/ruff/line-length config (confirmed: no such keys). Repo-wide convention already exceeds 100 columns in several test files. The exact length is 104, not 105 — immaterial. |

---

## 6. Could not verify

1. **Task 5 A/B behavioral outcome and the spec §4.4 fallback decision.** This is the
   concurrently-audited measurement; I did not run or read its artifacts. The code always
   applies `max` (`payload_evidence.py:243` "this function always applies `max`"), so if the
   A/B demands the fallback, a follow-up code change is required.
2. **The pipeline merge call site at runtime.** No fast test executes `run_pipeline`; I did
   not run the full pipeline (needs external tools/ollama). Verified instead by static
   ordering: merge at `pipeline.py:491` precedes the first result assembly at `:651` and the
   full one at `:788`, and `family_id` reads `extraction["decompiled_classes"]`
   (`backend/family_id.py:1685`), `extraction["native_libs_found"]` (`:1686`) and
   `result["manifest"]["uses_permissions"]` (`:1522`).
3. **Behavior on a genuinely hostile ZIP** (a member whose declared size is honest but whose
   inflate stream is unbounded). I reasoned about it (M2) but did not construct a bomb; the
   spec accepts the declared-size mitigation.
