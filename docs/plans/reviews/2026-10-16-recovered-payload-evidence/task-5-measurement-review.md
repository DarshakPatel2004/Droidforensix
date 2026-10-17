# Task 5 (measured A/B) — independent third-party review

Reviewer: independent (did not implement, did not run the pipeline/LLM, did not orchestrate).
Date: 2026-10-17. Method: read the requirements, the harness, the recordings and the logs; recompute the
movement, the metrics and the control diffs **in memory** from the saved artifacts only. No pipeline
run, no LLM call, no file modified (this report is the only write). `bash`/`awk` unavailable; used
`.venv\Scripts\python.exe` and PowerShell.

## Verdict

**The measurement is sound enough to accept the A/B result, with conditions.** The two numbers the
controller asked me to falsify hold up under independent recomputation:

- **Metrics:** baseline/off/on = `0.3547 / 0.3547 / 0.3547`, `0.3049 / 0.3049 / 0.3049`,
  `0.3123 / 0.3123 / 0.3123`, deltas exactly `0.0`. This follows from the recordings, the row set is
  265, and the substitution is correct. It is a **real null on verdicts** — not a harness that
  structurally could not see the change (see F5).
- **Movement:** 6 of 17 affected samples moved `extraction`, 11 did not; I reproduced both the split
  and every off/on value from the recordings, exactly matching the controller's table.

The conditions are not fatal but must be stated, because two of them make the literal acceptance
wording false:

1. **The control criterion fails literally and was never enforced** (F1). All three saved verdicts are
   `equal: false`; the harness logged `off == on` regardless; Step 3 said "Assert", nothing was
   asserted. It holds in substance only if the criterion is read as "outcome-bearing fields unchanged".
2. **Task 5 Step 7 is not done** (F11): no `## Amendments` section, `HEAD` is still `aab2eb7`. The
   measurement is complete; the task is not.

Everything else is Minor. No Critical. The controller's reading is accurate except where flagged
(F3 is a substantive mis-explanation; F12 is imprecision).

---

## Findings

### F1 — Major — the control-equality criterion fails literally, the log lies, and nothing was asserted
- Artifact: `C:\Users\darsh\AppData\Local\Temp\opencode\evidence_ab.py:316-338` (`check_control_equality`);
  `readings\ctrl\*_equality.json`; `phase_ctrl.out`.
- Evidence: line 327 logs `ctrl <sha>: off == on (after dropping timeline)` **unconditionally**, before
  the `if not equal` branch. `phase_ctrl.out` therefore contains, back to back:
  `ctrl 018f8548: off == on (after dropping timeline)` / `ctrl 018f8548: DIFFER ['master_key']`. The saved
  verdicts are `equal: false` for **all three** (`018f8548`, `3a03b35a`, `44b5086d`).
- The harness computes `equal` and saves it; it never raises or aborts. Plan Step 3 said "**Assert** the
  two result dicts are equal after dropping `timeline`". No assertion was performed.
- Reconstructed leaf diffs (from the saved `work\ctrl\<sha>\{off,on}\pipeline_result.json`, timeline dropped):

  | control | differing leaves | nature |
  |---|---|---|
  | 018f8548 | `master_key.artifacts[0].file`, `master_key.unpack_report.artifacts[0].file`, `master_key.triage_report.duration_seconds` | 2 paths, 1 wall clock |
  | 3a03b35a | `master_key.artifacts[0].file`, `master_key.breaker.wall_s`, `master_key.triage_report.duration_seconds` | 1 path, 2 wall clocks |
  | 44b5086d | `master_key.artifacts[0].file`, `master_key.unpack_report.artifacts[0].file`, `master_key.triage_report.duration_seconds`, `llm_assessment.narrative`, `raw_llm_output`, `recommended_actions[0..1]`, `threat_indicators` | 2 paths, 1 wall clock, 5 LLM-prose |

- Everything outside `master_key`/`llm_assessment` is identical for all three; in particular
  `extraction` is byte-identical and `recovered_evidence` is `None` in both arms. The criterion holds
  **in substance** for the fields that decide the outcome, and can never hold literally because the two
  arms run in different work dirs by construction. Ruling: met in substance, **not met as written**.

### F2 — Major — Task 5 Step 7 (record + commit) is outstanding
- Artifact: `docs/plans/2026-10-16-recovered-payload-evidence-plan.md` (no `## Amendments` section;
  Task 5 checkboxes unticked, lines 685-737); `git rev-parse HEAD` = `aab2eb7` (Task 4 tip);
  `git log` shows no "record the measured ... delta" commit.
- Step 7 and spec §9/§10.4 require the measured outcome and the §4.4 fallback decision to be **recorded
  in the plan's Amendments**. That has not happened. Correctly deferred to the results job, but until it
  lands, Task 5 is incomplete and spec §10.4's "recorded" half is unmet.

### F3 — Minor — the controller's "rounding artefact" explanation is wrong; the off run is **not** the baseline
- Artifact: `readings\metrics\summary.json`; `evaluation\validation_359\predictions.json`;
  `readings\pipeline\fea09cb6..._{off,on}.json`.
- The controller wrote the `unknown` precision `0.122 → 0.125` is "a rounding artefact of the same
  counts". It is not. Independently substituting the recordings into the baseline: exactly **one** row
  changes value, and it changes in **both** arms — `fea09cb6` baseline prediction `unknown` → `Bradesco`
  (ground truth `General`, wrong either way). Removing one false positive from `unknown` changes
  `unknown`'s precision from `0.122` to `0.125` (same support 7, different FP count). The per-family
  diff baseline→off is exactly `{unknown: 0.122→0.125}`; off→on is `{}`.
- Consequence: the headline equality `baseline == off` is a genuine coincidence at 4 dp, not because the
  fresh off run reproduced the 6-Oct baseline. A careful reader should know the "baseline" arm and the
  "off" arm differ on one prediction.

### F4 — Minor — the metric only sees 3 of the 6 samples where the merge fired
- Artifact: `readings\s1\affected.json`, `readings\pipeline\*`, `predictions.json`.
- Moved (merge fired): `49b59c87, c7944bda, de1d599d, f5ac462d, fea09cb6, ff742233`.
  Inside the 265-row eval baseline: `49b59c87, fea09cb6, ff742233` (3).
  Outside it (so their extraction changes never reach the scorer): `c7944bda, de1d599d, f5ac462d` (3).
- The substitution therefore reports the merge's verdict effect on half its firing samples. This is
  correct per the brief ("affected **in-eval** samples") but should be stated with the 0.0.

### F5 — Minor — "structurally could not detect the change" is overstated; the null is real for verdicts
- Artifact: `evidence_ab.py:377-426` (`phase_metrics`/`substitute`), `analysis/pipeline.py:487-493`,
  the family_id chain (spec §4.3: `family_id` reads `extraction`).
- The metric moves whenever a `family` prediction moves. The merge's effect reaches `extraction`, and
  `extraction` feeds `family_id`; had any band/signal flipped a verdict, the recording's `family` would
  differ and the delta would be non-zero. It did not. So `0.0` is a genuine null on verdicts, and the
  metric is blind **only** to extraction-only changes (the merge's direct effect, which the wiring table
  shows). The controller's caveat is correct in substance but its phrase "a null the metric is
  structurally unable to see" is imprecise: the metric can see the merge iff the merge changes a verdict.

### F6 — Minor — the metrics result is from post-hoc patched code, but is independently reproducible and read-only
- Artifact: `phase_metrics.err` (original crash: `evidence_ab.py:423  row["prediction"] = family["family"]`,
  `TypeError: string indices must be integers`); `evidence_ab.py:412-426` (patched to read the flat
  `recording["family"]`); `evidence_ab_run.log` (ab EXIT 0 20:50:11, ctrl EXIT 0 21:19:38, wire EXIT 0
  21:19:40, metrics EXIT 1 21:19:42); mtimes: `evidence_ab.py` 21:20:38, `metrics\summary.json` 21:20:51.
- The patch post-dates every recorded reading; `substitute` only reads recordings and rewrites an
  in-memory copy of the baseline; it writes nothing. I did **not** use the patched helper — I
  re-implemented the substitution from the recordings and re-ran `rv.build_report` in memory, getting
  the identical `0.3547 / 0.3049 / 0.3123` and deltas `0.0`. So the metrics result is not an artefact of
  the patch. (See "Could not verify" for the one unverifiable part.)

### F7 — Minor — `substitute` over-substitutes and silently skips failed runs
- Artifact: `evidence_ab.py:412-426`.
- Evidence: it rewrites **any** baseline row that has a `<sha>_<seam>.json` with `status == "success"`,
  not just affected in-eval rows. That pulls in the control-only recording `3a03b35a` (12 rows overridden
  = 11 affected in-eval + 1 control). Harmless here because the control value equals its baseline
  prediction, but it is not the brief's rule. Conversely, if an affected run had failed
  (`status == "error"`), the row would be silently left at the baseline prediction, understating the
  merge's effect rather than flagging it.

### F8 — Minor — the affected set is an input from a killed earlier process
- Artifact: `readings\s1\affected.json` mtime `2026-10-16T19:57:45`, i.e. from the first attempt; the
  authoritative run started `2026-10-17T20:22:49`. `phase_ab`/`phase_wire` read it; the authoritative
  launcher never re-ran `s1`.
- `s1` is deterministic pure analysis (`break_apk` + `_materialize_payload`, no pipeline/LLM), so this is
  a defensible carry-over, but the authoritative off/on run depends on a set produced by a different
  process. Reported shape: 17 affected, `packed_rows = 40` — matches the brief's "~17 ZIP".

### F9 — Minor — two "affected" recordings were overwritten by the control phase
- Artifact: mtimes of `readings\pipeline\018f8548*_{off,on}.json` = 21:12:37/21:12:46 and
  `44b5086d*` = 21:16:23/21:19:37, i.e. during `phase_ctrl` (20:50-21:19); the `ab` phase wrote them
  around 20:23-20:32.
- `018f8548` and `44b5086d` are in both the affected set and the dispatcher control bucket, so
  `run_sample_twice` ran them again in the `ctrl` work dir and overwrote their `readings\pipeline`
  recordings. `phase_wire` (21:19:38) and `phase_metrics` therefore used the **control** runs for these
  two. Immaterial — both carry `recovered_evidence: None` and show no movement — but the "17 affected
  recordings" are not all from the `ab` phase.

### F10 — Minor — one run per arm with an LLM in the loop
- Artifact: `44b5086d` control: `llm_assessment` differs across arms (`narrative`, `raw_llm_output`,
  `recommended_actions[0..1]`, `threat_indicators`) while `extraction` is byte-identical, `family` =
  `FakeInstaller`/`llm`/0.5 in both, and `recovered_evidence` is `None` in both. The on-run's extra
  indicator names `android.permission.REQUEST_INSTALL_PACKAGES`, a permission this app does not carry
  and which the evidence (absent) could not have contributed.
- This confirms the controller's "LLM nondeterminism, not leakage" reading. It also means a single
  off/on run on an LLM-scored sample cannot fully separate "merge had no effect on the verdict" from
  "the reroll happened to agree". The affected moved samples are `llm`/`signature_v3`/`knowledge_base`;
  none changed family, so no verdict claim relies on LLM determinism, but the caveat stands.

### F11 — Minor — controller-reading inconsistencies
- Its control table lists only `018f8548` and `3a03b35a`, omitting the third control `44b5086d`
  (`equal: false`) that the prose then discusses.
- Its claim that the 11 non-moving affected samples "yielded no DEX/manifest/native evidence, or the
  pipeline never reached the breaker" is imprecise: **all 11 have `recovered_evidence: None`**, i.e. the
  pipeline attached no evidence at all (they are dispatcher-recovered; s1's standalone breaker is what
  flagged them). None of the 11 even reaches the merge with an evidence record.

---

## Independent recomputations (in memory, from recordings only)

### Movement (Question 6)
From `readings\pipeline\*_{off,on}.json`, recomputed criterion = change in
`decompiled_classes` OR `len(native_libs_found)` OR `len(manifest.uses_permissions)`:

- 17 affected recordings → **6 moved, 11 identical**; over all 18 recordings (incl. control `3a03b35a`)
  → 6 moved, 12 identical. Matches `readings\wire\comparison.json` (6 `moved: true`) and
  `phase_wire.out` (`6 moved, 11 identical`).

| sample | ground truth | off → on classes | natives | perms | evidence |
|---|---|---|---|---|---|
| 49b59c87 | FraudDropper | 3054 → 7012 | 0 → 4 | 0 → 22 | y/y |
| c7944bda | 40094400 | 1397 → 1622 | 0 → 4 | 0 → 9 | y/y |
| de1d599d | Android/Agent | 5204 → 6857 | 0 → 4 | 0 → 33 | y/y |
| f5ac462d | FraudDropper | 1501 → 6859 | 0 → 4 | 0 → 23 | y/y |
| fea09cb6 | General | 2 → 1098 | 0 → 0 | 0 → 0 | y/y |
| ff742233 | AndroidOS | 4 → 6857 | 0 → 4 | 0 → 33 | y/y |

Every other affected sample: off == on on all three fields, `recovered_evidence: None`. Each on-run value
equals the merge rule (`max(stub, payload)` / union), e.g. `49b59c87` `max(3054, 7012)=7012`, natives =
the 4 evidence natives, perms = the 22 evidence perms; `c7944bda` `max(1397,1622)=1622`. This is strong
evidence the on-run difference **is** the merge and not work-dir noise. The controller's table is exact.

### Metrics (Question 2)
Re-implemented `substitute()` from `readings\pipeline\<sha>_<seam>.json` and called
`evaluation.run_validation_359.build_report`:

- Row set: `predictions.json` is a 265-element list; `build_report` reports `evaluated: 265, errors: 0`.
- Rows overridden: **12** (11 affected in-eval + control `3a03b35a`). Only **1** changed value vs baseline
  (`fea09cb6: unknown → Bradesco`), and it changed the same way in both arms.
- Result: `baseline = off = on = {accuracy 0.3547, precision_macro 0.3049, recall_macro 0.3123}`;
  deltas `{accuracy 0.0, precision_macro 0.0, recall_macro 0.0}` — identical to `metrics\summary.json`.
- Per-family tables: baseline vs off differ only in `unknown` precision (`0.122 → 0.125`); off vs on
  differ in nothing. So **on − off = 0 is exact**, and the true source of the `0.122→0.125` is F3, not
  rounding.

**Plain answer:** a **real null result** — for verdicts. The merge fired on 6 samples and changed
`extraction` every time, but no `family` prediction changed, so accuracy/precision/recall are unchanged.
It is **not** a test that structurally could not detect a change: the metric would move if any band/signal
flipped a verdict. It is, however, blind to the merge's extraction-only effect, and it only covers 3 of
the 6 firing samples (F4), on a single run per arm (F10).

### Validity of the A/B (Question 1)
Single-variable comparison: **yes**.
- One process for `ab`: `phase_ab.out` shows one `ab start` per sample, `progress.log` 17 starts + one
  `PHASE ab done`, `evidence_ab_run.log` one `PHASE ab START ... EXIT 0`. The prior attempts are
  quarantined and unread by `wire`/`metrics`.
- Only the seam differs: `run_sample_twice` sets `pipeline_module.merge_evidence = IDENTITY_MERGE` (off)
  vs `REAL_MERGE` (on) (`evidence_ab.py:33-34,220-234`); `pipeline.py:487-493` resolves the module global
  at call time, so the swap takes effect. The off arm still attaches `recovered_evidence` (all 6 show
  `y/y`), so the only difference between arms is the merge call. Order is always off then on.
- Same input: same `resolve_apk_path(row)` for both arms. The two arms use separate work dirs
  (`work\...\{off,on}\`), which guarantees the path/timing leaves in `master_key` differ (F1) but leaves
  `extraction` unaffected (proven by the 11 non-moving samples being byte-identical on the fields that
  matter).

### Patch (Question 3)
Behaviour-preserving, as far as artifacts allow. The crash trace pins the original line 423 as
`row["prediction"] = family["family"]`; the recordings' `family` is already the name string (confirmed,
e.g. `49b59c87_off.json:7 "family": "unknown"`). The patched line 423 reads the string directly. The
summary is identical to my independent in-memory recomputation, which never touches the harness. So the
metrics result cannot be an artefact of the patch (F6).

### Third control's `llm_assessment` difference (Question 4)
LLM nondeterminism, not a merge leak: `44b5086d` is dispatcher-recovered, `recovered_evidence: None` on
both arms, `extraction` byte-identical (7/7 keys), `manifest_uses_permissions` `[]` both, family
identical; only `llm_assessment` prose and 3 `master_key` path/timing leaves differ (F10).

### Control set (Question 5)
All three controls came from the `dispatcher` bucket (13 candidates); `select_controls`
(`evidence_ab.py:199-211`) breaks once `len(selected) >= 3` and the dispatcher bucket alone fills it, so
`exhausted` (21) and `clean_static` (278) are never consulted. The brief asked for one of each. The
criterion itself ("no breaker recovery ⇒ unchanged") is still substantively tested — dispatcher samples
are exactly the no-recovery case, and the 11 affected-no-evidence samples are an independent,
larger sample of the same property — but the packed-but-exhausted path and the non-packed path are
**not** covered. Deviation, not a false result (F2 in Findings is the Step 7 issue; this is the control
scope).

---

## Per-criterion verdict table

| Criterion | Verdict | Basis |
|---|---|---|
| Plan T5 Step 1 — identify affected set (~17 ZIP) | **Met** | `affected.json`: 17 samples, `packed_rows 40`; all 17 have ≥1 breaker ZIP hit. (Set predates the run — F8.) |
| Plan T5 Step 2 — off/on in one process, seam-only, record fields | **Met** | Single `ab` process; seam = `pipeline_module.merge_evidence`; recordings carry family/method/evidence/classes/natives/perms. |
| Plan T5 Step 3 — one dispatcher + one exhausted + one clean; assert equal after dropping timeline | **Not met (literal); met in substance** | Controls all dispatcher (F2); `equal:false` ×3 and nothing asserted (F1). Outcome fields unchanged. |
| Plan T5 Step 4 — wiring actually fired | **Met** | 6/6 evidence samples moved `extraction`; `comparison.json` 6 moved. |
| Plan T5 Step 5 — metric delta baseline/off/on | **Met** | Reproduced `0.3547/0.3049/0.3123`, deltas `0.0`, 265 rows, correct substitution. |
| Plan T5 Step 6 — fallback only on a drop | **Met** | No drop → fallback correctly not applied. |
| Plan T5 Step 7 — record Amendments + commit | **Not met** | No `## Amendments`; `HEAD` `aab2eb7` (F11/Step 7). |
| Spec §10.1 — static/bounded/no-raise evidence | **Not assessed here** | Task 1/2/4 scope; A/B produced no evidence-collection errors. |
| Spec §10.2 — additive, via `extraction` only | **Met (measurement-consistent)** | Extraction moved; family unchanged; no-recovery untouched. "No other module modified" is a T3 diff fact, not an A/B fact. |
| Spec §10.3 — no recovery ⇒ no evidence, no merge (test + A/B) | **A/B part met in substance; literal A/B literal fails** | 3 controls + 11 affected-no-evidence all unchanged in outcome; whole-dict equality false (F1). Test part is T3/T4. |
| Spec §10.4 — delta reported honestly incl. negative; fallback if harmful | **Measurement met; recording not met** | Deltas recorded in `summary.json`; fallback not triggered; Amendments absent (Step 7). |
| Spec §10.5 — suite green; breaker acceptance passes | **Not assessed here** | Out of scope for this measurement; not re-run. |
| Spec §9 — off/on per recovered sample, delta vs 6-Oct baseline | **Met** | 265 rows, baseline `predictions.json`, deltas `0.0`; caveats F4/F10. |

---

## Reconciliation with the controller's reading

Agree: single process; seam-only; 17 affected; 6/17 moved with the exact values and provenance
(`ff742233` payloads 7 / scanned 918 / class_count 6857; `49b59c87` 7012); deltas 0.0; fallback not
triggered; `check_control_equality` logs unconditionally while saving `equal:false`; control diffs are
paths/wall-clocks (plus LLM prose on `44b5086d`, which is nondeterminism, not leakage); all three
controls from the dispatcher bucket; the `substitute` patch is post-hoc and read-only.

Disagree / correct:
- F3: the `0.122 → 0.125` `unknown` precision is a **real one-row prediction change**
  (`fea09cb6: unknown → Bradesco`, in both arms), not "a rounding artefact of the same counts". The
  headline `baseline == off` is coincidental at 4 dp.
- F5: "a null the metric is structurally unable to see" overstates it — the metric sees a merge that
  changes a verdict; the merge changed none.
- F11: the control table omits the third control; the 11 non-moving samples have no evidence at all, not
  "evidence that yielded nothing".
- Additional gaps the reading does not mention: only 3 of 6 firing samples are in-eval (F4); `s1` set is
  cross-process (F8); two affected recordings were overwritten by `ctrl` (F9); `substitute`
  over-substitutes and skips failed runs (F7); Task 5 Step 7 outstanding (Step 7).

---

## Could not verify

- **The full pre-patch text of `evidence_ab.py`.** Only the traceback line proves line 423 was
  `family["family"]`; whether the patch touched the two adjacent lines and nothing else cannot be
  diffed from the artifacts (no VCS copy of the scratch file). Mitigated by the independent
  reconstruction in F5/F6, which reproduces the metrics without the harness.
- **Whether the off/on arms are free of LLM nondeterminism on the 6 moved samples.** Only `44b5086d`
  demonstrates nondeterminism; a single run per arm cannot rule it out elsewhere (F10). No verdict claim
  depends on it.
- **Reproducibility of the 10-16 `s1` set today.** Would require re-running `s1` (out of scope).
- **The suite gate (spec §10.5).** Not exercised by this measurement.
- **Full leaf-level diffs of the 6 moved affected samples' `pipeline_result.json`.** The recordings store
  a projection; the full dicts exist under `work\ab\` but were not diffed here (unnecessary — the
  movement table + merge-rule arithmetic already localise the change to the merge).

## Bottom line

Accept the A/B measurement: the deltas and the movement are correct, reproducible from the saved
readings, and explainable by the code. Rule the control criterion **satisfied in substance, false as
written** (all three controls are dispatcher, the assertion was never enforced, and whole-dict equality
is unachievable by the two-work-dir design). Do not treat `0.0` as "the merge did nothing" — it did fire
on 6 samples and moved `extraction` on all 6; it changed no verdict. Before Task 5 is declared complete:
finish Step 7 (Amendments + commit) and, in that write-up, state plainly that only 3 of the 6 firing
samples were in the evaluated row set and that the off arm is not a reproduction of the 6-Oct baseline.
