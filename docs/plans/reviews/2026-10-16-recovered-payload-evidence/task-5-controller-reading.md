# Task 5 — controller's live reading of the measurement

Read-only analysis performed while the run was in flight. It is **evidence for the Task 5
reviewer**, not the T5 result: the results job (interpret, decide the §4.4 fallback, amend the
plan, commit) is still the implementer's. Reproduce with the scripts named below.

Run: authoritative `ab` + `ctrl` from the single process started 2026-10-17 20:22:49
(`evidence_ab_run.log`, `progress.log`). Quarantined earlier attempts are not read.

## Affected set

`readings\s1\affected.json` → `samples` has **17** entries (keys: `samples`, `packed_rows`), all 17
with ≥1 breaker ZIP hit, all 17 with complete off/on recordings. The 18th recording present in
`readings\pipeline\` is `3a03b35a`, a *control* sample the `ctrl` phase also writes there — not an
18th affected sample. (`show_ab.py`)

## Movement — the merge fires on 6 of 17

off → on, from `readings\pipeline\<sha>_{off,on}.json`:

| sample | ground truth | classes | natives | manifest perms |
|---|---|---|---|---|
| 49b59c87 | FraudDropper | 3054 → **7012** | 0 → 4 | 0 → 22 |
| c7944bda | 40094400 | 1397 → **1622** | 0 → 4 | 0 → 9 |
| de1d599d | Android/Agent | 5204 → **6857** | 0 → 4 | 0 → 33 |
| f5ac462d | FraudDropper | 1501 → **6859** | 0 → 4 | 0 → 23 |
| fea09cb6 | General | 2 → **1098** | 0 → 0 | 0 → 0 |
| ff742233 | AndroidOS | 4 → **6857** | 0 → 4 | 0 → 33 |

The other 11 affected samples (018f8548, 44b5086d, 5af77b5f, 95236ef7, addbd877, bca248d3, 0e81a0fd,
e0f530ac, e4a321ef, fcd233be, 1869b4b8) show **no** movement: their recovered ZIP yielded no
DEX/manifest/native evidence, or the pipeline never reached the breaker for them (see the control
note below). `49b59c87 → 7012` reproduces Task 4's measured `class_count=7012` exactly.

`ff742233` on-run provenance: `payloads=7`, `members_scanned=918`, `members_skipped=0`,
`class_count=6857`, `truncated=none`, `errors=[]`, 33 permissions, 4 native entries
(`['arm64-v8a','armeabi-v7a','lib/arm64-v8a/liblixhokfsmav.so','lib/armeabi-v7a/liblixhokfsmav.so']`
— two of them ELF-magic only, as the spec allows).

**No family prediction changed off → on in any of the 17 samples.** Early signal, not a result:
the classifier's verdicts are identical, so the three-metric delta will likely be **0** and the
§4.4 fallback (which triggers only on an accuracy or macro-recall *drop*) likely will not fire.

## Control equality — passes in substance, fails literally, and the log line lies

`phase_ctrl` selected its three controls from the **`dispatcher` bucket only** (13 candidates);
`select_controls` fills all three from the first key rather than taking one `dispatcher`, one
`exhausted`, one `clean` as the brief's Step 3 described. Substantively sound — dispatcher-recovered
samples are exactly the ones where the breaker's second chance never runs, i.e. "no recovery" — but
narrower than the brief asked for.

`check_control_equality` (harness lines 316-338) logs `ctrl <sha>: off == on (after dropping
timeline)` **unconditionally at line 327**, then logs the differing keys only when they differ. So
the log text is a mislabel; the real verdict is the `equal` flag saved to
`readings\ctrl\<sha>_equality.json`:

| control | `equal` |
|---|---|
| 018f8548 | **False** |
| 3a03b35a | **False** |
| 44b5086d | **False** |

The literal criterion ("the two result dicts are equal after dropping `timeline`") therefore fails.
The reason is benign and is an artefact of the harness's own design — off and on run in **different
work directories** (`work\ctrl\<sha>\off` vs `\on`), so any recorded path differs by construction,
and wall-clock fields were never dropped. Full diff (`why_master_key_diff.py`), every differing leaf:

| sample | differing leaf | off | on |
|---|---|---|---|
| 018f8548 | `master_key.artifacts[0].file` | `...\off\master_key...` | `...\on\master_key...` |
| 018f8548 | `master_key.unpack_report.artifacts[0].file` | `...\off\...` | `...\on\...` |
| 018f8548 | `master_key.triage_report.duration_seconds` | 0.211 | 0.203 |
| 3a03b35a | `master_key.artifacts[0].file` | `...\off\master_key...` | `...\on\master_key...` |
| 3a03b35a | `master_key.breaker.wall_s` | 1.359 | 1.378 |
| 3a03b35a | `master_key.triage_report.duration_seconds` | 0.258 | 0.260 |

**Every difference is a path or a wall clock. Nothing outside `master_key` differs at all**, and
inside it nothing but those three leaves — in particular `master_key.recovered_evidence` is
identical, so the merge does not leak into `master_key`. Reading: "samples with no breaker recovery
are unchanged" **holds**, once `timeline` is joined by the path/timing metadata that the two-work-dir
design guarantees will differ. The strict form can never pass, so the criterion as written in the
brief is mis-specified — the reviewer should rule on the reading, not on the raw `equal: false`.

## Metrics — complete, and all three deltas are exactly 0.0

`readings\metrics\summary.json`, 265 rows evaluated, 0 errors:

| metric | baseline | off | on | delta |
|---|---|---|---|---|
| accuracy | 0.3547 | 0.3547 | 0.3547 | **0.0** |
| precision_macro | 0.3049 | 0.3049 | 0.3049 | **0.0** |
| recall_macro | 0.3123 | 0.3123 | 0.3123 | **0.0** |

The §4.4 fallback triggers only on a *drop*, so it is **not triggered**. Baseline and off are **not
identical**: exactly one row changes value, and it changes the same way in both arms —
`fea09cb6` baseline `unknown` → off `Bradesco` → on `Bradesco` (ground truth `General`, wrong either
way). That single row is the *only* source of the per-family difference `unknown` precision
0.122 → 0.125, by removing one false positive from `unknown` (same support 7, fewer FPs). So the
headline `baseline == off` is a coincidence at 4 dp, and the off arm is **not** a reproduction of the
6-Oct baseline. Corrected after independent review (finding F3); the earlier "rounding artefact of
the same counts" explanation in this document was wrong.

**Three counts a reader must not conflate** (all verified independently, and corrected here after
review findings F4/F11):

| set | size |
|---|---|
| "affected" — the standalone breaker sweep recovered a ZIP payload | 17 |
| in the 265-row eval set | **11** |
| actually got `recovered_evidence` attached by the pipeline (so the merge had anything to do) | **6** |
| both in-eval *and* carrying evidence — the only samples the metric can reflect | **3** (`fea09cb6`, `ff742233`, `49b59c87`) |

The other 11 affected samples record `recovered_evidence: None`, i.e. the pipeline attached no
evidence at all: `s1` flags them via the *standalone* breaker, but in the pipeline they are
dispatcher-recovered so the breaker's second chance never runs. They do not "yield no evidence" —
they never reach the merge. Of the 3 that are both, none changed verdict: `49b59c87` (GT
FraudDropper) and `ff742233` (GT AndroidOS) still predict `unknown` despite class counts jumping to
7012 and 6857 and 33 permissions arriving.

**On blindness — precisely:** the metric sees the merge exactly when the merge changes a *verdict*.
`extraction` feeds `family_id`, so a flipped band or signal would surface as a changed `family` and a
non-zero delta. None did. So `0.0` is a genuine null on verdicts; the metric is blind only to
`extraction`-only changes (the merge's direct effect, which the movement table shows). An earlier
draft of this document said the metric was "structurally unable to see" the change — that overstated
it (finding F5).

## The `metrics` phase crashed on a harness bug; the controller patched `substitute`

`phase_metrics` exited 1 — `substitute()` did `row["prediction"] = family["family"]`, but the
recording's `family` field is already the family **name string** (see `run_sample_twice`), so
`family["family"]` raised `TypeError: string indices must be integers`.

Patch applied by the controller at ~21:2x, **after `ab`, `ctrl` and `wire` had all completed**: the
three lines now read the recording's flat `family` / `method` / `confidence`. `substitute` is a
pure-analysis helper — it reads the run's recordings to rewrite a copy of the baseline rows and
touches no recorded reading — so the patch cannot invalidate any measurement artefact. Metrics then
ran exit 0 and wrote `readings\metrics\summary.json`.

Disclosed so a reviewer can judge for itself whether the patch is behaviour-preserving rather than
having to trust it.

## The third control differs in `llm_assessment` — and it is LLM nondeterminism, not leakage

`44b5086d` is the one control whose off/on diff is not confined to `master_key`. Every difference is
inside `llm_assessment`: `narrative`, `raw_llm_output`, `recommended_actions[0..1]`,
`threat_indicators[0..1]`.

It is not the merge. Both runs record `recovered_evidence: None` — the sample is
dispatcher-recovered, so the breaker's second chance never ran and there was no evidence to merge —
and their `extraction` mappings are byte-identical on all seven keys, including
`total_strings_extracted = 3779` and `decompiled_classes = 9`; `manifest_uses_permissions` is `[]` in
both; `family` / `method` / `confidence` are identical (`FakeInstaller` / `llm` / `0.5`). Identical
inputs, different prose: the LLM is simply nondeterministic. The on-run's extra indicator names
`android.permission.REQUEST_INSTALL_PACKAGES`, a permission this app does not have — an LLM re-roll,
not leaked evidence.

Consequence for acceptance: a control criterion demanding whole-dict equality **cannot** hold for
LLM-scored samples. It holds over the fields that decide the outcome (`extraction`,
`family_identification`) and over `master_key` once `timeline` is joined by the path and wall-clock
metadata that the two-work-dir design makes differ by construction.

## Scripts

- `show_ab.py` — per-sample table, wiring count, last sample's provenance block
- `why_master_key_diff.py` — leaf-level off/on diff for the controls

## Adjudication of the independent measurement review (2026-10-17)

The reviewer (`task-5-measurement-review.md`) reproduced both headline numbers independently — the
movement split with every value, and the metrics by re-implementing the substitution in memory
without the harness — and returned **"sound enough to accept the A/B, with conditions"**, no
Critical. Rulings, one per finding:

| finding | ruling |
|---|---|
| **F1** (Major) control criterion fails literally; `check_control_equality` logs `off == on` unconditionally at line 327 and never asserts | **Accepted.** The criterion is met **in substance, not as written**. Evidence: for all three controls `extraction` is byte-identical and `recovered_evidence` is `None` in both arms; the only differing leaves are artifact paths (guaranteed by the two-work-dir design), wall clocks, and — on `44b5086d` — LLM prose. No re-measurement: the evidence already exists. The plan's Step 3 wording and the criterion get corrected in the Amendments, and the harness defect is recorded as a harness defect. |
| **F2** (Major) Step 7 outstanding — no Amendments, HEAD still `aab2eb7` | **Accepted.** This is the results job, dispatched now. |
| **F3** (Minor) my "rounding artefact" explanation was wrong | **Accepted — my error, corrected in this document.** Verified independently: exactly one row changes vs baseline (`fea09cb6 unknown → Bradesco`, both arms). |
| **F4** (Minor) only 3 of the 6 firing samples are in the eval set | **Accepted.** Stated in the Amendments; the three-count table above is now in this document. |
| **F5** (Minor) "structurally unable to see" overstated | **Accepted — corrected in this document.** The metric sees the merge iff a verdict moves. |
| **F6** (Minor) metrics come from post-hoc patched code | **Accepted, no action.** The reviewer reproduced the same numbers *without* the harness, so the patch is not the source. Recorded. |
| **F7** (Minor) `substitute` over-substitutes (12 rows, incl. one control) and silently skips failed runs | **Accepted as a harness limitation.** Recorded in the Amendments; harmless here (the control value equals its baseline prediction). No re-run. |
| **F8** (Minor) `affected.json` predates the authoritative run (mtime 10-16 19:57, from attempt 01) | **Accepted carry-over.** `s1` is deterministic pure analysis (`break_apk` + `_materialize_payload`, no pipeline, no LLM); it reports 17 affected / 40 packed rows, matching the brief's ~17 expectation and the phase-1 sweep's 40 packed. Recorded. |
| **F9** (Minor) two affected recordings overwritten by `ctrl` | **Accepted.** `018f8548` and `44b5086d` are in both the affected set and the dispatcher control bucket, so `phase_ctrl` re-ran them and overwrote their `readings\pipeline` files. Immaterial (both: `recovered_evidence: None`, no movement). Recorded so "17 affected recordings" is not overstated. |
| **F10** (Minor) one run per arm with an LLM in the loop | **Accepted as a caveat.** Nondeterminism is *demonstrated* on `44b5086d`; a single run per arm cannot rule it out elsewhere. No verdict claim depends on it — none of the 6 firing samples changed family. Recorded. |
| **F11** (Minor) inconsistencies in this document | **Accepted — corrected.** The control table now lists all three controls; the "11 non-moving samples yielded no evidence" wording is replaced by the accurate "they never reach the merge" (`recovered_evidence: None`). |

Nothing in the review requires re-running the measurement or changing production code. Everything it
raises is either already true of the artifacts (F1, F3, F4, F5, F7-F11) or is the outstanding Step 7
(F2).
