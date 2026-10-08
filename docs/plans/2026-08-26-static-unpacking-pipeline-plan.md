# Plan: Universal Static Unpacking & Deobfuscation Pipeline ("Break Protected APKs Without a Device")

| | |
|---|---|
| **Status** | DRAFT — awaiting external review |
| **Date** | 2026-08-26 |
| **Author** | kx + ox-alpha (working session) |
| **Scope** | New analysis capability for DroidForensix; static-only until ceiling |
| **Validation target** | `RTO.apk` (known confident-benign false negative) |
| **Related docs** | `docs/MAFIA_v2.1.md`, `thesis_baseline.md`, `ground_truth_all_corrected.csv`. Technical grounding cited below: **[AI]** = `Trimmed Android Internals.md` (Yaghmour, *Android Internals Vol I*); **[PRE]** = `Trimmed Reverse Engineering.md` (Dang/Gazet/Bachaalany, *Practical Reverse Engineering*) |

---

## 1. Problem Statement

### 1.1 The failure we are fixing

Commit `e7acbba` documented that `RTO.apk` received a **confident-benign verdict** from the static pipeline.
Static probe of the sample shows why:

| Evidence | Value | Meaning |
|---|---|---|
| `classes.dex` | **976 bytes** | Stub only — 3 classes, no logic |
| Stub contents | `Dzhugashvili/jD3P extends Application`, calls `loadLibrary("strangulation")` in `onCreate` | Classic packer entry pattern |
| Payload | `assets/myg0N`, **7.8 MB**, entropy ≈ random (`file` reports bare "data") | Encrypted real classes |
| Native lib | `libstrangulation.so`, ARM32+ARM64, stripped, NDK r25c | Custom decryptor |
| JNI surface | Exactly one export: `Java_Dzhugashvili_jD3P_SUO4__` | Single decryptor entry point |
| ELF imports | malloc/memcpy/pthread/C++ runtime **only** — no file I/O, no dlopen, no mprotect, no ptrace | Pure-computation crypto; zero anti-analysis |

### 1.2 Why existing tooling missed it

- `_run_die()` (`scripts/forensic_pipeline.py:481`) is signature-based. RTO uses **custom randomized names**
  (`Dzhugashvili`, `myg0N`, `libstrangulation`) — not Bangcle/Ijiami/Legu/360 markers.
  Signature triage structurally cannot catch custom packers.
- jadx decompiles the 976-byte stub successfully → pipeline sees benign-looking empty app.
- Entropy check exists (`_calculate_entropy`, line 295) but apparently did not gate the verdict.

**Conclusion:** we need *structural* packer detection plus an active decryption capability, not more signatures.

---

## 2. Goals & Non-Goals

### Goals

- **G1.** Detect packed/encrypted APKs via structure and statistics, independent of packer brand or naming.
- **G2.** Recover plaintext DEX from encrypted payloads **without any Android runtime**, using emulation-as-static-analysis.
- **G3.** Recover decrypted strings/configs from protected native libs by invoking their own routines as oracles.
- **G4.** Generalize: works on *any* APK entering the corpus, not tuned to one sample or family.
- **G5.** Integrate as pipeline stages with clean data contracts, batch-capable within VM resource limits.
- **G6.** Flip the RTO.apk false negative into a correct verdict end-to-end.

### Non-Goals (explicitly out of scope)

- Runtime/behavioral dynamic analysis (Frida, network monitoring) — deferred to Tier 5 escape hatch, separate future plan.
- VMP devirtualization research (recovering full custom-VM semantics).
- iOS or other platforms.
- Changing existing stage verdict logic beyond consuming new artifacts.

---

## 3. Constraints & Environment

| Constraint | Value | Consequence |
|---|---|---|
| Kali VM, no `/dev/kvm`, no VT-x passthrough | Hardware-accelerated Android impossible | All work must be device-free; AVD path closed |
| CPU/RAM | 8 cores / 7.7 GB | Max 2–3 concurrent heavy workers; Unicorn is single-threaded per instance → parallelize across samples |
| Existing toolkit | apktool, jadx, DIE, JDK, Python venv | Reuse; add Ghidra, LIEF, Unicorn, capstone, pyelftools, angr |
| Pipeline shape | Stages 0–5 in `scripts/forensic_pipeline.py`; DIE at stage 1 (`packer_analysis`), jadx at stage 2 | New capability slots between stage 1 and stage 2 |
| Corpus evaluation | `ground_truth_all_corrected.csv` (~95 KB), `predictions.csv` | Regression harness already exists conceptually |
| Sample handling | Live malware (live-C2 checks exist elsewhere in repo) | Samples processed read-only, hashed, no network egress from analysis components |

---

## 4. Threat Model: What Protections Exist (and what this plan handles)

| # | Protection class | Examples | Handled where |
|---|---|---|---|
| P1 | DEX encryption w/ custom native decryptor | **RTO.apk**, GhostBat cluster | Tier 3 + 4 (primary target) |
| P2 | Commercial DEX packers | Bangcle (`libsecexe.so`,`com.secneo.apkwrapper`), Ijiami (`com.stub.StubApp`,`libexecmain.so`), Tencent Legu (`libshella*.so`,`com.tencent.StubShell`), 360 (`libjiagu*.so`,`com.qihoo.util`), SecNeo (`libDexHelper.so`), DexGuard (transformed dex, no payload swap) | Same machinery; known-marker table accelerates config (Appendix A) |
| P3 | String/config encryption inside .so | XOR/AES/RC4/XXTEA blobs | Tier 4 oracle invocation |
| P4 | OLLVM obfuscation (flattening, bogus CFG, opaque predicates) | common in P2 native libs | Tier 3 metrics detect; deflatten passes + targeted analysis |
| P5 | Anti-debug / anti-frida / anti-emulation checks | ptrace, TracerPid, /proc scans | Mostly irrelevant (no runtime); anti-emulation handled in Tier 4 failure taxonomy |
| P6 | Hidden/dynamic JNI registration | stripped `Java_*` exports, runtime `RegisterNatives` | Tier 3 static JNINativeMethod-table discovery |
| P7 | VMP / custom bytecode interpreters | high-end banking trojans | ❌ out of scope (ceiling) → escalate to Tier 5 |

---

## 5. Architecture Overview

```
                        ┌──────────────────────────────────────────────┐
                        │            forensic_pipeline.py              │
                        │                                              │
 APK ──► Stage 0 ──► Stage 1 ──► [NEW C1] ──► [NEW C2] ──► Stage 2 ──► ... ──► Verdict
         preflight    threat      Structural   Static       code review
                      indicators  Triage       Extraction
                                      │              ▲
                              packed? │              │ recovered artifacts
                                      ▼              │
                                 [NEW C3] Native Dissection (Ghidra headless / LIEF)
                                      │
                                      ▼
                                 [NEW C4] Emulation Oracle (Unicorn/Qiling + JNIEnv mock)
                                      │
                                      ▼
                          artifacts/: *.dex (plaintext), strings.json,
                                      native_report.json, provenance.json
```

**Design principle:** every protected component is treated as an *oracle* — we never reimplement the
malware's crypto; we make the malware's own code run (in emulation) and capture its output.

**Escalation ladder:** cheapest tier first; stop when G-goal met for the sample:

```
T1 triage → T2 cheap static → T3 dissection → T4 emulation oracle → [CEILING] → T5 host worker (future)
```

**Precedent:** ARM-on-x86 binary translation is already production reality inside Android itself — Intel's Houdini runs ARM JNI libraries on x86 devices ([AI] pp.13, 16). This plan applies the same machinery offline, for analysis rather than compatibility.

---

## 6. Component Specifications

### C1. Structural Triage Engine

**Purpose:** classify an APK's protection state without signatures. Runs on every sample.

**Heuristics (all must emit raw measurements, then a combined verdict):**

| ID | Heuristic | Measurement | Default threshold (tunable) | Rationale |
|----|-----------|-------------|------------------------------|-----------|
| H1 | DEX-to-payload size ratio | `sum(classesN.dex sizes) / total uncompressed size` | ratio < 0.05 AND payload > 1 MB → suspicious | Real apps' dex is usually >20% of content; RTO = 976B / ~8MB ≈ 0.0001 |
| H2 | Asset/blob entropy | Shannon entropy over sliding 4 KiB windows of each asset >100 KB | mean > 7.5 bits/byte → encrypted blob | Compressed data ≈ 7.9 too; combine with H1 to avoid flagging plain zips/images |
| H3 | Application-class native loading | Manifest `android.app.Application` subclass invokes `System.loadLibrary` before super.onCreate, OR dex references `loadLibrary` in `<clinit>` of entry classes | boolean | RTO stub matches exactly |
| H4 | Suspicious JNI export shape | `.so` files with ≤2 exported `Java_*` symbols AND stripped symtab AND ≥1 large (>256 KB) text section | boolean | Decryptors expose one entry |
| H5 | Known packer markers | Filename/content scan against Appendix A table | match → classified (brand identified) | Fast-path for commercial packers; feeds loader hints |
| H6 | Import-table profile | ELF imports contain none of {open/fopen/read/mmap/write} while asset blob present → pure-compute decryptor | enum: `pure_compute \| file_io \| unknown` | Directly predicts Tier-4 difficulty (RTO: pure_compute) |

**Verdict enum:** `clean_static · packed_custom · packed_known(<brand>) · obfuscated_native · indeterminate`

**Output contract:** see §7 schema `triage_report`.

**Edge cases to handle (reviewer: please challenge):**
- Unity/Flutter/React-Native apps ship big non-dex payloads legitimately → H1 must whitelist known engine asset patterns (`assets/bin/Data`, `libflutter.so`, `index.android.bundle` …). Maintain allowlist file.
- Apps with legitimately huge media assets → entropy windows exclude detected media MIME types.
- Multi-dex split payloads (dex fragments reassembled at runtime) → treat like P1; Tier 4 output may need fragment merge.

---

### C2. Static Extraction Orchestrator

**Purpose:** wire existing tools deterministically; produce machine-readable intermediate artifacts.

- apktool decode → manifest, resources, raw assets staged into work dir (already partially done today ad hoc).
- jadx attempt regardless of triage verdict (cheap; sometimes partial-obfuscation still yields most code).
- If `classes.dex` is stub-sized (<50 KB): skip deep dex string extraction (current `_collect_dex_strings` wastes time) and rely on C3/C4 instead.
- Emit `static_extraction_report.json`: what succeeded, coverage estimate (methods decompiled / methods declared via dex header parse using `pyelftools`-style dex parser or `androguard` — dependency already used in pipeline line 324).

---

### C3. Native Dissection Stage

**Purpose:** turn each `.so` into structured intelligence that drives C4.

#### C3.1 Loader & parsing
- LIEF: parse ELF headers, exports, imports (feeds H4/H6), relocations, init arrays.
- Ghidra headless (batch mode) with project-per-sample; scripts emit:
  - Function list w/ sizes, basic-block counts, edge counts
  - Cross-references from the JNI export(s)
  - Detected constant tables (see C3.3)

#### C3.2 JNI method discovery (two algorithms, both always run)
1. **Static exports:** enumerate symbols matching `Java_<pkg>_<cls>_<meth>`; demangle; map back to Java classes found in stub dex (joins stub dex class list ↔ lib exports — catches renamed pairs like `Dzhugashvili/jD3P` ↔ `Java_Dzhugashvili_jD3P_SUO4__`).
2. **RegisterNatives table hunt:** scan `.data.rel.ro`/`.rodata` for `{const char* name, const char* sig, void* fnPtr}` triples whose name/sig pointers resolve into valid C-strings and fnPtr lands in an executable segment. This recovers P6 hidden registrations without running anything.

#### C3.3 Crypto constant detection (Appendix B has full values)
Scan all sections for: AES S-box / inverse S-box, ChaCha/Salsa sigma `"expand 32-byte k"`,
TEA/XTEA/XXTEA delta `0x9E3779B9`, CRC32 poly `0xEDB88320`, SHA-256 IV, MD5 sin table,
RC4 key-schedule patterns (identity permutation init loops 0..255).
Emit `crypto_hints[]` with section+offset → tells C4 what to expect and helps angr constraint choice.

#### C3.4 Obfuscation metrics (OLLVM detection)
- Flattening score: fraction of functions where one hub block has >15 predecessors and block count >30.
- Opaque predicate density: recurring invariant patterns (e.g., arithmetic self-inverse tests).
- Output `obfuscation_metrics.json`; high scores route sample to heavier deflattening passes and raise C4 timeout budget.

**Output contract:** `native_report.json` (schema §7).

---

### C4. Emulation Oracle (the core new engineering)

**Purpose:** execute the malware's own decryptor under Unicorn on x86 and capture outputs.

#### C4.1 Loader
- Preferred engine: **Unicorn** (+ custom thin ELF loader built on LIEF). Qiling evaluated as alternative — see Decision D2.
- Steps:
  1. Map PT_LOAD segments at preferred base (relocate if collision).
  2. Apply R_* relative relocations (LIEF computes; ARM ABS32/REL32 minimal set).
  3. Allocate stack (1 MB) + guard pages; allocate heap arena for shimmed malloc (bump allocator, 16 MB cap).
  4. Point PLT/imports at magic trampoline addresses; each trampoline dispatches to Python libc-shim (C4.2) or JNIEnv handler (C4.3).
  5. Set up call frame: ARM32 → `r0=JNIEnv*`, `r1=jclass/jobject`, stack per AAPCS; ARM64 → `x0/x1` + registers. Support both; prefer arch matching device majority in corpus (Decision D6).

**Grounding ([PRE]):** the calling convention — first four 32-bit args in R0–R3, remainder on stack, return value in R0 (p.58) — fixes both this entry-frame layout and how C4.3 mock handlers inject results back into registers before returning. Entry addresses carry a Thumb-state bit: BX/BLX switch ARM↔Thumb on the target's LSB ([PRE] pp.41, 57–59), and JNI exports such as RTO's `Java_Dzhugashvili_jD3P_SUO4__` may sit in Thumb code — PC must be set honoring that bit or Unicorn decodes garbage. Note [PRE]/[AI] do **not** cover the JNI vtable layout itself; C4.3 is grounded in the canonical JNI spec / checked-in `jni.h` instead.

#### C4.2 libc shim (initial coverage — driven by observed import lists)
`malloc free calloc realloc posix_memalign memcpy memmove memset memchr strlen __strlen_chk strcmp pthread_mutex_lock/unlock pthread_once pthread_key_create/getspecific/delete abort __assert2 __stack_chk_fail __cxa_atexit __cxa_finalize fflush fprintf fputc vasprintf vfprintf __vsnprintf_chk`
- Behavior: faithful enough semantically (malloc returns distinct aligned chunks; pthread ops become no-ops returning 0; abort/assert raise Python exception → captured as failure E1).
- Coverage gap detection: any unhooked PLT call logs `UNSUPPORTED_IMPORT` with symbol name → failure taxonomy E1.

#### C4.3 JNIEnv mock
- Build `JNINativeInterface` struct programmatically: allocate table of ~230 function pointers; compute offsets from canonical jni.h ordering **at build time** (never hardcode indices in source — generate from checked-in `jni.h` copy to survive version drift).
- Every function slot points to a unique magic address; Unicorn code-hook on magic region dispatches to Python handlers.
- Handler registry (priority order for v1):
  - Identity/object registry: fake jobject/jclass pointers ↔ Python-side descriptors
  - `GetVersion` → JNI_VERSION_1_6
  - Array ops: `GetArrayLength`, `NewByteArray`, `GetByteArrayRegion`, `SetByteArrayRegion`, `NewByteArray` ← **critical path for byte[]→decrypt→byte[] flows**
  - String ops: `GetStringUTFChars`, `ReleaseStringUTFChars`, `NewStringUTF`, `GetStringLength`, `GetStringChars`
  - Class/method resolution: `FindClass`, `GetObjectClass`, `GetMethodID`, `GetStaticMethodID`
  - Call routing: `CallObjectMethod`, `CallStaticObjectMethod`, `CallVoidMethod`, etc. → look up registered Java-side callbacks. For asset-loading patterns, register a virtual "AssetManager.open/read" implementation serving bytes of the flagged payload file (this is how RTO's myg0N gets fed despite no file I/O imports — the lib will call *back* into Java through these).
  - Everything else: log-and-fail (E2) with exact function name for rapid mock extension.

#### C4.4 Invocation recipes (per protection pattern)
| Pattern | Recipe |
|---|---|
| Byte[] in → byte[] out (RTO-class) | Build jbyteArray containing payload; call JNI export; capture result buffer; validate `dex\n035\0` magic |
| Asset read via JNI callback | Register AssetManager mocks backed by real file bytes |
| Config-string decryptor (no JNI export) | Call internal function directly at address found by C3 xref analysis; args symbolic/heuristic |
| Key derivation unclear | Switch to angr (C4.6) |

#### C4.5 Capture & validation
- Hook all memory writes to heap arena; after call completes, scan allocated regions for DEX magic / PK zip magic / high-entropy-decline.
- Validate recovered dex: header version parse, checksum/map_off sanity, then jadx trial compile.
- Emit `emulation_trace.log` (import calls, JNI calls, timing) — doubles as debugging aid and thesis evidence.

#### C4.6 Symbolic fallback (angr)
- When concrete args unknown: mark ciphertext buffer symbolic; constrain output[0:8] == `dex\n035\x00`; let solver derive keys/IVs. Budget-capped (timeout, step limit); failure → E5.

#### C4.7 Resource budgets
- Per-sample emulation timeout: 10 min wall (configurable); memory cap: 512 MB per instance.
- Parallelism: 2 workers max given 7.7 GB RAM (Decision D7).

---

### C5. Artifact Store & Provenance

- Directory convention under each sample's work dir:
```
work_dir/
  triage/triage_report.json
  static/static_extraction_report.json
  native/native_report.json  native/ghidra_project/
  emul/emulation_trace.log  emul/recovered/*.dex  emul/recovered/strings_dump.json
  provenance.json           # tool versions, hashes of inputs/outputs, timings
```
- Every artifact records: input SHA256, producing component+version, timestamp, command line. Feeds thesis reproducibility.

### C6. Tier-5 Host Worker Interface (stub only — future plan)

Define now, implement later: a queue-file contract (`tier5_jobs/<sha256>.job`) so that if T4 fails,
the pipeline can hand off to a remote worker (MEmu-on-host, adb/frida over TCP, memuc CLI lifecycle).
Nothing in C1–C4 blocks on C6. Kept as interface stub so escalation needs no refactor later.

---

## 7. Data Contracts (JSON schemas, abbreviated)

```jsonc
// triage_report.json
{
  "apk_sha256": "…",
  "verdict": "packed_custom",          // enum §C1
  "confidence": 0.0,                    // 0..1
  "heuristics": {
    "H1_dex_ratio": {"value": 0.00012, "threshold": 0.05, "hit": true},
    "H2_entropy":   {"mean": 7.98, "windows_flagged": 2048, "total_windows": 2051},
    "H3_native_app_class": true,
    "H4_jni_shape": {"java_exports": 1, "stripped": true, "text_kb": 200},
    "H5_markers": [],                    // e.g. ["com.stub.StubApp"] when known
    "H6_import_profile": "pure_compute"
  },
  "payload_candidates": [{"path": "assets/myg0N", "size": 7815568, "entropy": 7.98}],
  "native_libs": ["lib/armeabi-v7a/libstrangulation.so", "lib/arm64-v8a/libstrangulation.so"],
  "allowlist_overrides_applied": []
}

// native_report.json (abbreviated)
{
  "elf": {"arch": "arm", "bits": 32, "stripped": true, "needed": ["liblog.so","libc.so","libm.so","libdl.so"]},
  "jni_methods": [
    {"name": "Java_Dzhugashvili_jD3P_SUO4__", "addr": "0x6f0d", "source": "static_export",
     "java_hint": {"class": "Dzhugashvili.jD3P"}}
  ],
  "crypto_hints": [{"kind": "aes_sbox", "section": ".rodata", "offset": "0x…"}],
  "obfuscation": {"flattened_function_fraction": 0.31, "opaque_predicate_density": 0.07}
}
```

---

## 8. Failure Taxonomy & Escalation

| Code | Failure | Auto-response | Escalate when |
|---|---|---|---|
| E1 | Unsupported libc import called | Log symbol; extend shim (each is ~10 LOC) | Shim covers all needed imports |
| E2 | Unmocked JNIEnv function invoked | Log name; extend registry | Registry covers the pattern |
| E3 | Anti-emulation behavior detected (env reads, timing loops, self-checksums) | Patch instructions at load (LIEF rewrite) — documented per family; **≥2 failed patches on same stall → escalate to T5 (enforced at M3a gate)** | Patch library grows unwieldy |
| E4 | Self-modifying/decrypted-at-runtime code | Enable write-to-code-region hooks; re-translate. Grounding: ARM i-/d-caches are non-coherent across SMC writes and require explicit flush ([PRE] p.67) — Unicorn's translation-block invalidation plays that role | — |
| E5 | Solver/concrete invocation fails (angr budget exhausted) | Try alternate recipe ordering | Both orders fail |
| E6 | Output not valid dex (fragmented/multi-part) | Fragment merge pass; retry jadx | Merge heuristics exhausted |
| E7 | Anything above | **Write tier5 job stub; mark sample `escalated_dynamic`** | — |

Every failure writes structured reason codes into `provenance.json` — this is also our thesis metric feed
("unpacking success rate per protection class").

---

## 9. Validation Plan

### Acceptance criteria (RTO.apk first, then corpus)
- **AC1:** Triage classifies RTO.apk as `packed_custom` with confidence ≥0.8 in <5 s.
- **AC2:** Emulation oracle returns ≥1 buffer passing dex-magic + checksum validation.
- **AC3:** jadx compiles recovered dex; ≥80% of declared methods yield source (measure vs dex method count).
- **AC4:** Re-running pipeline stages 1–2 + synthesis on recovered artifacts changes RTO verdict away from confident-benign toward its ground-truth label in `ground_truth_all_corrected.csv`.
- **AC5:** No regression: rerun triage over the locked sample list — **frozen 2026-08-26 at `data/triage_locklist_m0.csv` (55 samples: 25 seeded known-clean + 15 F-Droid engine/big-asset apps + 10 GT packed-suspects + RTO + 4 reserve)** — false-positive rate <5%, measured as *misclassified-as-packed / total locked-list samples*. (Denominator pinned deliberately: precision on the clean set is what gates M4 effort; calibration data now on disk, see `data/engine_apps_manifest.csv`.)

### Metrics captured per sample
triage time · dissection time · emulation time · outcome code (success/E-code) · protection class ·
bytes-recovered-ratio · downstream-verdict delta. Aggregate into evaluation framework (existing `evaluation/`).

---

## 10. Safety Notes

- All processing local, no network egress from C1–C4 (unit-test enforced).
- Samples opened read-only; derived artifacts hash-chained in provenance.json.
- Emulating attacker-controlled code on the analyst box: Unicorn sandbox has no syscalls beyond our shims — document residual risk (shim bugs ≠ code exec, but fuzz-hardened shims desirable long-term).

---

## 11. New Dependencies

| Tool | Purpose | License | Install |
|---|---|---|---|
| Ghidra (headless) | Dissection C3.1 | Apache-2.0 (NSA) | tarball to `tools/ghidra`, needs JDK ✔ present |
| unicorn (pip) | CPU emulation | BSD-2 | pip into venv |
| lief (pip) | ELF parse/rewrite | MIT | pip |
| capstone (pip) | disasm in hooks | BSD | pip |
| pyelftools (pip) | light ELF reads in triage | MIT | pip |
| angr (pip) | symbolic fallback C4.6 | BSD-2 | pip (heavy; pin version) |

Pin everything in `requirements-lock.txt` per repo convention.

---

## 12. Milestones

| ID | Deliverable | Exit criteria | Est. effort |
|---|---|---|---|
| M0 | C1 triage prototype + allowlist | AC1 pass; runs over corpus subset. *Sample acquisition already complete: locklist frozen (`data/triage_locklist_m0.csv`, 55 samples) — remaining work is the C1 implementation itself* | 2–3 d |
| M1 | C3 dissection stage + native_report schema | RTO native report populated (JNI join + crypto hints) | 3–4 d |
| M2 | C4 skeleton: loader + libc shim + JNIEnv v1 | Toy ARM .so (self-written test lib) round-trips byte[] through mock | 4–5 d |
| M3a | RTO anti-emulation discovery | Decryptor reaches crypto entry under Unicorn: either clean run or E3 resolved via LIEF patch (**hard gate: after ≥2 failed patches on the same stall, write tier5 job stub and stop — no third attempt**) | 2–3 d |
| M3b | RTO decryption validation | AC2 + AC3 (oracle output → valid dex → jadx compiles) | 2–3 d |
| M4 | Recipes generalization + failure taxonomy wired | ≥3 families unpack or correctly E-coded | 4–6 d |
| M5 | Evaluation integration | AC4 + AC5; metrics in evaluation/ | 2–3 d |

Critical path: M2 → M3a → M3b. Buffer lives there deliberately.

---

## 13. Decision Points for Reviewers (please respond per item)

- **D1.** Triage placement: gate expensive stages strictly on `packed_*`/`indeterminate` verdicts, or run C3/C4 opportunistically on all samples? (Cost: ~×8 pipeline time on clean samples.)
- **D2.** Unicorn-thin-loader (recommended: full control, smaller dep surface) vs Qiling (higher-level, Android/Linux rootfs concepts, heavier). 
- **D3.** Language boundary: keep C1–C4 in Python for repo consistency even though Ghidra scripting is Java/Jython — accept bridge overhead?
- **D4.** Allowlist governance for H1 (engine asset patterns): checked-in YAML reviewed like code?
- **D5.** Confidence scoring for C1: fixed weights vs learned-from-corpus once labels exist? *(Pre-answer: corpus ground-truth doubles as the test set — there is no clean training partition. Fixed weights + AC5 regression decides empirically whether learning is justified; revisit only if AC5 fails.)*
- **D6.** Arch priority: emulate arm64-v8a libs when both exist (matches modern reality) vs armeabi-v7a (RTO's primary)? Recommend: try arm64 first, fall back.
- **D7.** Worker count: hardcode 2 or derive from cgroup memory?
- **D8.** Verdict synthesis when recovery succeeds. **Proposed default (confirm or veto):** final verdict is sourced from the *recovered-dex* artifact (it sees the app's real behavior); the stub-based verdict is always preserved alongside in provenance.json for comparison and thesis delta-metrics. Alternative under consideration: run stage-2 twice, report both, synthesize at stage 5. Must be decided before M2 — synthesis logic depends on it.

## 14. Open Questions

- Are other GhostBat samples the same custom packer (name-randomized variants)? Determines whether family-config abstraction is needed at M3 or M4.
- Does any corpus sample exhibit P6-only (no static exports)? Drives RegisterNatives-hunt testing priority.
- Is there appetite to contribute recovered-artifact corpus back to dataset docs (thesis value)?

## 15. Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| RTO decryptor uses JNIEnv callbacks we underestimated | Med | schedule slip on M3a/b | trace-driven mock extension loop is designed for this; recipes cover asset-manager pattern |
| angr unusable on flattened code | High | low (fallback only) | concrete-first philosophy; angr optional |
| False-positive triage on games | Med | user trust | allowlist + AC5 gate |
| Ghidra headless perf on 8-core box | Low–Med | throughput | per-sample projects, parallel across samples not within |
| Unicorn ARM fidelity gaps (rare SIMD/FP corners — NEON/VFP live in coprocessor space cp10/cp11, [PRE] p.45) | Low | single-sample stalls | capstone-based manual stepping fallback; report E-code |

---

## Appendix A — Known-Packer Marker Table (seed; extend as encountered)

| Brand | Markers (files/classes/libs) |
|---|---|
| Bangcle/SecNeo | `com.secneo.apkwrapper`, `libsecexe.so`, `libsecmain.so`, `libDexHelper.so`, assets `classes*.dex.bak` |
| Ijiami | `com.stub.StubApp`, `libexecmain.so`, `ijiami.dat`, `ajm.dat` |
| Tencent Legu | `com.tencent.StubShell`, `libshella-*.so`, `libshellx-*.so`, `mixz.dex` |
| 360 Jiagu | `com.qihoo.util`, `libjiagu.so`, `libjiagu_art.so`, `libjiagu_x86.so`, `libprotectClass.so` |
| NQ Shield | `com.netqin.android.dopt`, `libnqshield.so` |
| Wangsu/ChinaNetCenter | `libkwsgmain.so`, `libkdp.so` |
| Ali | `libmobisec.so`, `ali.protect` |
| DexGuard | (no payload swap) transformed dex fingerprints: absent strings, injected `SourceFile`-like noise, `--multi-dex` oddities — heuristic, low confidence |

## Appendix B — Crypto Constant Fingerprints

| Kind | Bytes/value |
|---|---|
| AES S-box | `63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76` |
| AES inv S-box | `52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB` |
| ChaCha/Salsa σ | `"expand 32-byte k"` |
| TEA/XTEA/XXTEA δ | `9E 37 79 B9` |
| CRC32 (reflected poly) | `ED B8 83 20` |
| SHA-256 H0 | `6A 09 E6 67 BB 67 AE 85 …` |
| RC4 signature | identity-permutation init loop (i in 0..255 → S[i]=i) — structural, find via small constant-loop pattern |

## Appendix C — Glossary

**Packers** wrap real dex encrypted, decrypting at app start via native stub. **OLLVM** — obfuscating LLVM fork (flattening/bogus-CFG). **Oracle approach** — invoke protected code as black box instead of reversing its internals. **JNIEnv mock** — synthetic JNI function table letting native code run outside Android. **Tier** — escalation level in §5 ladder.

## Appendix D — Technical References & Grounding

Map for reviewers who want to verify claims independently. All substantive citations are
inline where technical depth matters; source texts are checked into the repo root
(`Trimmed Reverse Engineering.md`, `Trimmed Android Internals.md`) so every page reference
is locally verifiable.

### `[PRE]` — *Practical Reverse Engineering* (Dang, Gazet, Bachaalany)

| Page | Content | Used by |
|---|---|---|
| 41 | ARM vs Thumb instruction states | C4.1 entry-point handling |
| 45 | cp10/cp11 coprocessor space (VFP/NEON) | Risks table: Unicorn fidelity gaps |
| 57–59 | BX/BLX interworking via destination-address LSB | C4.1 Thumb-bit handling for JNI exports |
| 58 | Calling convention: args in R0–R3 (+ remainder on stack), return value in R0 | C4.1 call-frame layout; C4.3 result injection |
| 67 | SMC; i-cache/d-cache non-coherence across self-modifying writes | E4 auto-response rationale |

### `[AI]` — *Android Internals Vol I* (Karim Yaghmour)

| Page | Content | Used by |
|---|---|---|
| 13 | Intel Houdini: closed-source ARM-on-x86 emulation extending Dalvik/ART | §5 Precedent |
| 16 | Houdini as production binary-translation example | §5 Precedent |

Broader background (runtime structure, native layer, `System.loadLibrary` resolution)
informs heuristic H3 conceptually; no further page-specific claims are made.

### Canonical JNI specification (`jni.h`)

Ground truth for C4.3: `JNINativeInterface` vtable ordering, function-pointer signatures,
thread-local `JNIEnv` association. The mock registry is generated from a checked-in `jni.h`
copy at build time — offsets are never hardcoded. Neither book covers the vtable layout;
hence the separate grounding.
