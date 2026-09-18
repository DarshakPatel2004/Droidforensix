# Threat Synthesis Engine — Audited & Fixed Implementation Plan

**Goal:** Add 9 static analysis features (steps 10–18) to the DroidForensix pipeline, plus pipeline integration and 3 frontend surfaces.
**Scope of this document:** every task from the original plan, with the audit finding (if any) and the fix or decision applied, in one place. Contract-level — inputs, outputs, behavior. Code generation happens at implementation time, not here.

**Verdict:** 2 blockers (would've failed the plan's own TDD loop), 4 silent correctness gaps (wrong numbers, no crash), 3 propagation gaps caught on re-review (a rename or new state added upstream that didn't reach every downstream consumer), 5 items of documented debt. All resolved or explicitly decided below.

---

### Task 1: Binary Packing Detection (`#17`) — clean
`analysis/step10_binary_packing.py`. Detects oversized/high-entropy DEX sections, DEX-in-DEX nesting, missing classes.dex, oversized native libs.

**Audit:** no issues found. **Fix:** none needed.

---

### Task 2: String Entropy & Clustering (`#2`) — clean
`analysis/step11_string_clustering.py`. Entropy-based extraction, Jaccard-set similarity clustering, base64/hex/plaintext classification.

**Audit:** no issues found. **Fix:** none needed.

---

### Task 3: Reflective Method Invocation Tracing (`#3`) — clean
`analysis/step12_reflective_tracing.py`. Regex/smali pattern matching for `Class.forName`, `Method.invoke`, `getDeclaredMethod`, resolved against a sensitive-API map.

**Audit:** no issues found. **Fix:** none needed.

---

### Task 4: Native ELF Analysis (`#20`) — FIXED
`analysis/step13_native_elf_analysis.py`

**Audit finding (C1):** `detect_elf_obfuscation()` was implemented and unit-tested in isolation, but `analyze_native_libraries_from_apk()` — the function actually wired into the pipeline — initializes `lib_result["obfuscation"] = {}` and never calls it. The test suite covered the standalone function only, so this passed every test while shipping dead code. Downstream: Task 9's scorer reads `lib.get("obfuscation", {}).get("obfuscation_detected", False)` for the native-code term — that's 10 of 100 weighted score points that were structurally unreachable, always `False`.

**Fix:** `analyze_native_libraries_from_apk()` must, for each extracted `.so` with a resolvable on-disk path, build a section map (size + entropy per section, via pyelftools section headers) and call `detect_elf_obfuscation()`, storing the result under `lib_result["obfuscation"]`. If the library can't be read from disk, `obfuscation` stays `{}` — expected. If it can, obfuscation must be computed, not skipped.

**New test requirement:** assert that a library with a resolvable path and high-entropy sections produces `obfuscation.obfuscation_detected == True` from the full pipeline function — not just from the isolated `detect_elf_obfuscation()` call. This is the exact gap the original suite missed.

---

### Task 5: Network Protocol Analysis (`#9`) — clean
`analysis/step14_network_protocol_analysis.py`. URL/IP extraction, C2 signal scoring (non-private IP + suspicious port + suspicious path), benign-domain allowlist.

**Audit:** no issues found. **Fix:** none needed.

---

### Task 6: Reflective Permission Correlation (`#1`) — FIXED, DECIDED
`analysis/step15_reflective_permission_correlation.py` (renamed from `step15_permission_correlation.py`)

**Audit finding (C3):** `correlate_permissions()` marked a declared permission "used" only if its API class appeared in `reflective_calls` (Task 3's output — reflection-based invocation specifically). A benign app calling `SmsManager.sendTextMessage()` directly, with no reflection anywhere, never shows up in `reflective_calls` — so every declared permission on a clean, non-obfuscated app reads as unused. Fed into Task 9's `permission_mismatch` weight, this flags clean apps on this axis by construction, not by evidence. This was the finding most likely to inflate the false-positive rate against the AndroZoo clean set, since it isn't a bug that crashes — it's a bug that looks like a signal.

**Decision (yours): ship reflective-only, under an honest name.** Extending to direct calls means scanning every smali method body against `PERMISSION_API_MAP` — a separate, heavier static pass beyond what step 12 produces. Step 15 already only receives `reflective_calls` from step 12 in the current pipeline wiring (Task 10). The right fix is naming, not scope expansion — SHA-256 fingerprinting doesn't need to become a call-graph analyzer to be honest about what it measures.

**Fixed contract:**
- Rename module: `step15_permission_correlation.py` → `step15_reflective_permission_correlation.py`.
- Rename function: `correlate_permissions()` → `correlate_reflective_permission_usage()`.
- Rename the output field `used` → `used_reflectively` — drop the bare `used`, it implied general usage and it isn't.
- **`usage_ratio` is unaffected — do not rename it.** It's a computed field (`len(used_reflectively-true permissions) / total_permissions`), not the renamed raw field. `score_zero_day_risk` reads `usage_ratio` directly (Task 9, current line ~1904) — only the underlying `used` boolean is being renamed, not the ratio built from it. State this explicitly in the function contract so an implementer doing a find-and-replace on `used` doesn't also touch `usage_ratio` by accident.
- Module docstring states explicitly: *"Measures permission usage evidenced by reflective invocation only. A permission used exclusively via direct (non-reflective) calls will read as unused here — this is a scoping choice, not a defect."*
- **Task 9 impact:** rename `permission_mismatch` in `THREAT_WEIGHTS` to `reflective_permission_mismatch`, update its `description` to match. Weight (15/100) unchanged — a permission only reachable via reflection with no direct usage is a legitimate signal, it just needed a name that doesn't overclaim.
- No new extraction pass. No new test beyond renaming existing ones to match.

**Black book framing:** "reflective permission usage mismatch," not "permission-behavior correlation" — the latter implies call-graph coverage this doesn't have.

---

### Task 7: Certificate Analysis (`#11`) — FIXED
`analysis/step16_certificate_analysis.py`

**Audit findings (D2, D3):**
- `KNOWN_BAD_CERTIFICATES` shipped as an empty dict — `check_known_bad_certificate` always returns `known_bad: False`. Not labeled as a stub anywhere, despite the original plan's self-review claiming zero TBDs. Functionally a TBD wearing a finished-looking name.
- `SUSPICIOUS_ISSUERS` includes `"O=Google Inc."` and `"CN=Android"` — depending on substring matching against real issuer strings, this can flag legitimate Google Play App Signing certs as suspicious.

**Fix:**
- `KNOWN_BAD_CERTIFICATES` ships empty, but the module docstring and task acceptance criteria must state explicitly it's a placeholder pending a real known-bad cert feed. Real future work, just needs to be declared as such instead of implied complete.
- Before trusting `suspicious_issuer` in the score, validate `SUSPICIOUS_ISSUERS` against 5–10 known-clean Play Store APKs from the existing AndroZoo clean set. If `"O=Google Inc."` or `"CN=Android"` trip false positives, narrow to exact issuer-string match or drop those two entries.

---

### Task 8: Family Clustering (`#16`) — FIXED, DECIDED
`analysis/step17_family_clustering.py`, `analysis/cross_sample_index.py`

**Audit findings:**
- **(B2, blocker)** `test_step17_family_clustering.py` calls `hashlib.sha256(...)` in two tests with no `import hashlib` — collection-time `NameError`, entire file dies before any test runs.
- **(C4)** The "MinHash" implementation is `sha256(signature + seed)` for 5 fixed seeds, collected into a flat set — not MinHash. Real MinHash takes the *minimum* hash value per independent permutation over a shingle set, producing a fixed-size sketch that makes Jaccard-over-minhash an unbiased, size-independent similarity estimator. What's implemented biases Jaccard by method count: a 100-method sample can produce up to 500 set elements vs. a 5-method sample's 25, so larger samples read as systematically less similar to smaller ones regardless of actual code overlap.
- **(D1)** `cross_sample_index.json` is read-modify-written with no file lock, runs unconditionally on every pipeline execution (wired into the main pipeline in Task 10, not optional), and has no eviction — grows forever.

**Decision (yours): renamed heuristic, not real MinHash.** The implementation is SHA-256 fingerprinting with fixed-seed expansion, compared via direct set Jaccard — no random permutations, no k-signature sketch, no probabilistic size-independence. That's method-signature fingerprinting. Real MinHash's value proposition is sublinear similarity estimation over corpora too large to compare pairwise directly — not the situation at single-APK-comparison scale, so there's nothing to gain from implementing it beyond the label.

**Fixed contract:**
1. Add the missing `import hashlib` to the test file.
2. Rename throughout, don't reimplement:
   - Module docstring: **"method signature similarity index,"** not MinHash-based clustering.
   - `minhash_signatures` field → `expanded_signature_hashes`.
   - `jaccard_similarity()` docstring: note it computes Jaccard over expanded hash sets, and that the metric is influenced by method count — document as a known property, not a bug to fix.
   - `get_family_graph_data()` and any UI-facing labels (Task 12's panel, if it surfaces this) say "method signature similarity," not "MinHash clustering."
3. `# NOTE:` in `cross_sample_index.py` documenting the no-lock, no-eviction limitation and the assumption that pipeline execution is sequential. Needs a lock before it's safe to parallelize — flag as a prerequisite, not a surprise.

**One more thing surfaced after the decision, not in the original audit:** `cross_sample_index.json` is cumulative across every sample ever analyzed, and `get_family_graph_data()` builds the similarity graph with an `O(n²)` pairwise loop over the whole index on every call. Your "no benefit from real MinHash at single-APK scale" reasoning is correct for the per-request comparison — but the index itself is a growing corpus-scale structure, and the `O(n²)` edge-building will get slow well before MinHash would ever matter. Doesn't change the naming decision — "method signature similarity index" is still accurate — but add a `# NOTE:` in `get_family_graph_data()` flagging that it needs a cap or incremental-update strategy once the index passes a few thousand samples. Not blocking now.

**Black book framing:** "method signature similarity index" (SHA-256 fingerprinting + Jaccard), not MinHash-based clustering. Accurate and defensible at corpus scale — don't reach for the fancier-sounding name.

---

### Task 9: Zero-Day Payload Scoring (`#15`) — FIXED
`analysis/step18_threat_synthesis.py`

**Audit findings:**
- **(B1, blocker)** `test_synthesize_threat_profile_empty` asserts `risk_level == "unknown"` for an empty context; the implementation's `else` branch returns `"none"` for score `0`. Test and implementation disagree — the plan's own "Expected: passed" was false as written.
- **(C2)** `THREAT_WEIGHTS` sums 7 categories (100 points: packing, reflective, permission mismatch, C2, high-entropy strings, native obfuscation, certificate). The `contributing_signals` breakdown only builds entries for 5 of the 7 — no branch for `native_obfuscation` or `certificate_anomaly`. A sample where a bad cert or obfuscated `.so` drove the score up shows a score with no matching entry in its own explanation — the same backend/UI-breakdown mismatch class as the fixes already shipped in the last pass (#3, #7).

**Fix:**
1. `risk_level` gets a genuine third state: `"unknown"` when the input context is empty or missing required keys entirely (nothing to score — likely an upstream extraction failure), `"none"` when the context is populated and every signal legitimately scored zero (a fully-analyzed, genuinely clean sample). `synthesize_threat_profile` checks for an empty/near-empty context up front and returns `"unknown"` before falling through to the score-based ladder.
2. Add the two missing `elif` branches to `contributing_signals` — `native_obfuscation` (reading `native_elf.native_libraries[].obfuscation.obfuscation_detected`, now populated per the Task 4 fix) and `certificate_anomaly` (reading `certificate.known_bad` / `certificate.suspicious_issuer`). Every point in the score traces to a named entry in the breakdown.
3. **Propagation, not optional:** the new `"unknown"` state has two frontend consumers, not one — `riskLevelBadgeClass` in `AnalysisView.jsx` (Task 11) and the separate `LEVEL_CLASS` map in `ThreatSynthesisPanel.jsx` (Task 12, line ~2366). Both currently fall through to a default slate/gray badge for any unrecognized key, which happens to render *something* for `unknown` today — but that's coincidental, not intentional, since neither map has an explicit entry for it. Both need `unknown: 'badge-slate'` (or a genuinely distinct treatment — a sample that couldn't be scored is arguably worth visually distinguishing from a sample confirmed clean, since one means "check your extraction" and the other means "this app is fine"). Add the key explicitly to both maps rather than relying on the fallback to keep doing the right thing by accident.

---

### Task 10: Integrate New Steps into Pipeline — FIXED, CONFIRMED
`analysis/pipeline.py`, `backend/transformers.py`

**Audit finding (D5):** `TOTAL_STEPS` changes 9 → 18, `STEP_NAMES` gets 9 new entries — but the plan didn't check whether the frontend's WebSocket-driven progress/ETA logic (from the recent frontend rebuild) reads a matching step-count constant client-side. If it does and isn't updated in the same task, the progress bar and ETA desync from the backend the moment step 10 starts emitting events.

**Open question at audit time, resolved:** every new step call passes `_run_step` a variable number of positional arguments after the step function (1 arg for most, 2 for steps 13/15, 3 for step 17) — this assumed `_run_step` accepts `*args` and forwards them.

**Fix + confirmation:**
- Add a step to this task: grep the frontend for any hardcoded step-count constant, ETA-per-step assumption, or `TOTAL_STEPS`-equivalent used by the WebSocket reducer / progress display, and update it in the same commit. Trivial refactor bundled with the feature — fine per your own standard, since splitting it risks a silent desync that's hard to bisect later.
- **Confirmed, not a risk:** `_run_step(step_num, sample_id, apk_size, global_start, emitter, work_dir, func, *args, **kwargs)` at `analysis/pipeline.py:89–91`. The 7 named params are fixed; everything after `func` forwards via `*args, **kwargs`. Steps 13, 15, 17 all work as written — no wrapper, no signature change needed.

Everything else in Task 10 (imports, `STEP_NAMES`, result dict keys, `transformers.py` additions) unchanged — no other issues found.

---

### Task 11: Surface Zero-Day Risk in AnalysisView Hero — FIXED (propagation from Task 9)
`frontend/src/components/AnalysisView.jsx`

**Audit finding:** original code review found no issues, but Task 9's fix adds a genuine third `risk_level` state (`"unknown"`) that this component's `riskLevelBadgeClass` map doesn't have an explicit entry for. It currently falls through to the default `slate` badge, which happens to look reasonable but isn't an intentional decision.

**Fix:** add `unknown: 'badge-slate'` explicitly to `riskLevelBadgeClass`'s map (or a visually distinct treatment — see Task 9, item 3, for the reasoning). Don't rely on the fallback to keep doing the right thing.

---

### Task 12: Threat Synthesis Panel (New Tab) — FIXED (propagation from Tasks 6 & 9)
`frontend/src/components/ThreatSynthesisPanel.jsx`

**Audit finding:** two rename/state changes upstream don't reach this component as originally planned, both missed in the first pass because the panel was reviewed as "consumes `contributing_signals` generically" without tracing the specific keys through:

1. `SIGNAL_LABELS` (line ~2359) still has `permission_mismatch: 'Permission Mismatch'`. Task 6 renamed the underlying signal key to `reflective_permission_mismatch` (to match the honest naming decision). Without this update, the panel either shows a blank/unlabeled entry for that signal or silently keeps displaying the overclaiming old label — the exact outcome the Task 6 rename was meant to prevent.
2. `LEVEL_CLASS` (line ~2366) has the same missing-`unknown`-key gap as `AnalysisView.jsx`'s `riskLevelBadgeClass` (Task 11) — it's a separate map in a separate file, so fixing one doesn't fix the other.

**Fix:**
1. `SIGNAL_LABELS`: `permission_mismatch: 'Permission Mismatch'` → `reflective_permission_mismatch: 'Reflective Permission Mismatch'`.
2. `LEVEL_CLASS`: add `unknown: 'badge-slate'` (or the same distinct treatment chosen for Task 11 — keep the two maps' `unknown` handling visually consistent since they render in the same app).

---

### Task 13: Augment ObfuscationView with Packing & Reflection Cards — clean
`frontend/src/components/ObfuscationView.jsx`

**Audit:** no issues found.

---

## Self-Review

**1. Spec coverage:** unchanged from original — all 9 features + pipeline + 3 frontend tasks covered.

**2. Placeholder scan:** `KNOWN_BAD_CERTIFICATES` (Task 7) is now a declared placeholder, documented in its task spec instead of silently implied complete. No other undeclared placeholders remain.

**3. Test/implementation agreement:** Task 9's `risk_level` test and implementation now agree by construction. Task 8's test file compiles (import fixed). Task 4's obfuscation test now covers the actually-wired path, not just the isolated function.

**4. Decisions closed:**
- **Task 6:** reflective-only, renamed `step15_reflective_permission_correlation.py`. Direct-call coverage out of scope for this pass — would need a separate smali-body scan against `PERMISSION_API_MAP`. Fix was naming, not scope.
- **Task 8:** renamed heuristic — "method signature similarity index," not MinHash. No sublinear-comparison benefit at this corpus scale.
- **Task 10:** `_run_step` signature confirmed at `pipeline.py:89–91`. Multi-arg forwarding works as written.

**5. Propagation gaps (caught on re-review, not the first pass):** every rename or new-state addition in this plan touches at least one file that isn't the one being edited. First pass checked "does the producer of this value make sense" and "does at least one consumer handle it" — it didn't check "does *every* consumer handle it." Two frontend files (`AnalysisView.jsx`, `ThreatSynthesisPanel.jsx`) both render `risk_level`; only one was checked for the new `unknown` state. One frontend file (`ThreatSynthesisPanel.jsx`) has its own `SIGNAL_LABELS` map independent of the backend rename in Task 6; it wasn't grepped. The fix going forward, not just for this plan: when a task renames a field or adds an enum value, grep the whole frontend tree for the old key before marking the task done, not just the component that was already in view.

**6. Debt explicitly carried forward (documented, not blocking):** `cross_sample_index.json` has no write lock — safe under current sequential pipeline execution, flagged as a prerequisite check if the pipeline is parallelized later. `ANTI_ANALYSIS_PATTERNS`' bare `"trace"` substring is noisy against legitimate crash-reporting symbols — worth a word-boundary fix but not blocking generation.

---

## Assumption Inventory

**What I'm assuming**
- [ ] `_run_step`'s confirmed signature (`*args, **kwargs`) doesn't change before this ships.
- [ ] Pipeline execution stays sequential (one sample at a time) — `cross_sample_index.json` has no write lock and relies on this.
- [ ] The frontend's step-count/ETA logic is discoverable by grep (no dynamically-computed constant hiding the dependency).
- [ ] `pyelftools` can read section headers from the `.so` files in your AndroZoo corpus without needing a full ELF loader (some obfuscated/packed natives may resist this — falls back to `obfuscation: {}`, which is the documented expected behavior, not a crash).

**What I'm NOT handling**
- [ ] Direct (non-reflective) permission usage — Task 6 is reflective-only by decision, not oversight.
- [ ] Real MinHash / size-independent similarity — Task 8 uses fingerprinting + Jaccard by decision.
- [ ] Known-bad certificate matching — `KNOWN_BAD_CERTIFICATES` ships empty; real coverage needs a feed you don't have yet.
- [ ] Concurrent pipeline execution — `cross_sample_index.json` isn't lock-safe. Fine now, blocking if you parallelize.

**Debt I'm creating**
- [ ] `cross_sample_index.json`: no lock, no eviction, `O(n²)` graph-building in `get_family_graph_data()` — fine at current corpus size, needs a cap or incremental update once the index passes a few thousand samples.
- [ ] `ANTI_ANALYSIS_PATTERNS`' bare `"trace"` substring match (Task 4) will false-positive on `backtrace`/`stacktrace`/`traceback` symbols in native libs — noisy, not wrong, worth a word-boundary fix when convenient.
- [ ] `SUSPICIOUS_ISSUERS` (Task 7) needs validation against known-clean Play Store certs before its output is trusted in the score — flagged, not yet run.

**Decisions I'd make differently with different constraints**
- If this were feeding a real-time triage tool instead of a thesis pipeline: implement real MinHash in Task 8 immediately, since corpus size would eventually make the fingerprinting approach's `O(n²)` lookup the actual bottleneck, not just a documented note.
- If permission-behavior correlation were a headline result instead of a supporting signal: build the direct-call scan for Task 6 now rather than deferring it — the reflective-only version undercounts on every non-obfuscated sample, which is most of your clean set.
- If `cross_sample_index.json` were shared across concurrent workers today: add the file lock now instead of noting it as a prerequisite for later.
