# How We Broke the Encrypted APK (`RTO.apk`) — A File-by-File Walkthrough

> **Purpose.** This document lets you walk a LEA investigator or a senior reverse
> engineer through — step by step, file by file — how the encrypted payload inside
> `RTO.apk` (a live 2026 BeatBanker/BTMOB fake e-challan banker) was recovered
> **without ever running it on a phone**. Every section names **which file was
> used for what**, so the evidence chain can be followed, questioned, and
> reproduced.
>
> **Audience.** Two tracks are provided throughout: §5a for a non-technical LEA
> audience, §5b for a technical expert. You do **not** need a device, an emulator,
> Frida, or a kernel VM for any of this — only Ghidra listings, p-code emulation,
> and small Python helpers.
>
> **Verification note.** Every file path in this document was checked against the
> working copy on 2026-10-05. Files that are referenced by our findings reports
> but are *not* present in this checkout are explicitly marked **[not in this
> checkout]** with instructions on how to regenerate or where the equivalent
> artifact lives (see §3.10).

---

## Table of Contents

1. [Executive summary](#1-executive-summary-the-30-second-version)
2. [The target, in one table](#2-the-target-in-one-table)
3. [Which file did what — the evidence map](#3-which-file-did-what--the-evidence-map)
4. [How we know the break is correct](#3b-how-we-know-the-break-is-correct-verification--controls)
5. [The break, step by step](#4-the-break-step-by-step-what-to-say-out-loud)
6. [Explaining it to a LEA](#5a-explaining-it-to-a-lea-non-technical-audience)
7. [Explaining it to an expert](#5b-explaining-it-to-an-expert-technical-audience)
8. [Reproducibility](#6-reproducibility--step-by-step-on-a-fresh-machine)
9. [What we did *not* claim](#7-what-we-did-not-claim-the-honest-boundaries)
10. [Evidence handling](#8-evidence-handling-what-is-in-git-vs-what-must-be-handed-over)
11. [Related case](#9-related-case--the-same-break-five-more-apks)

---

## 1. Executive summary (the 30-second version)

**Cite as:** Darshak Patel, "How We Broke the Encrypted APK (RTO.apk),"
Case study / thesis chapter, NFSU Digital Forensics, 2026.

`RTO.apk` ships its real malware encrypted in a single 7.8 MB asset,
`assets/myg0N`. The encryption key never appears anywhere as plaintext on disk —
it is *assembled in memory at runtime* by a 36,000-instruction,
control-flow-flattened native function (`libstrangulation.so` → `SUO4`).

We recovered the key, the IV, and the full 10-entry dropper kit by combining:

1. **Listing-level symbolic evaluation** — a custom Ghidra script that decodes
   the packer's inline XOR'd string table byte-by-byte without a decompiler,
2. a **JNI emulation oracle** — a fake `JNIEnv*` that answers "which Java call
   is this?" and replays `StringBuilder` assembly so the key seed appears as
   plaintext,
3. a **PRNG byte-replay** — the installer's string table regenerated from its
   own bytecode, with no execution at all.

The recovered key derivation:

```
seed = "myg0N2"   ( = "myg0Nbootstrap.dex".substring(0,5) + "2" )
KEY  = SHA1("myg0N2")[:16]
IV   = SHA256("myg0N2")[:16]
Cipher = AES/CBC/PKCS5Padding  →  assets/myg0N decrypts to a ZIP dropper kit
```

*(Exact KEY/IV hex values are intentionally not printed here — they live in
`rto_analysis/detections/iocs.json` §`crypto` and in the local vault
`docs/cases/pendrive-56-apks/ARTIFACTS_SENSITIVE.md` §8, per this project's
evidence-handling rule that key material only ships in local-only files. The
derivations above re-create them in one line — see §6.1.)*

That one seed (`"myg0N2"`) is the entire wall: everything else — the 7,857
recovered bytes of string table, the decoy DEX, the 177 installer strings, the
C2/Firebase IOCs, the YARA rules — followed from it. The same derivation family
(`key = SHA1(seed)[:16]`, `iv = SHA256(seed)[:16]`, `seed = asset_stem + "2"`)
then unlocked **five more seized APKs** in the companion case (§9).

---

## 2. The target, in one table

| Property | Value |
|---|---|
| Sample | `RTO.apk` (repo root) — 8,397,289 B (8.1 MB), 2026, live |
| SHA-256 | `348f8b090b51ba27e9042f19730a61c04bb31691d7939fd1047dffc5f51a8d4e` (re-verified against the file and against `detections/iocs.json`) |
| MD5 | `b31677bf555589e74d78c9e9618614e9` |
| Cluster | BeatBanker / BTMOB (FakeChallan family): fake Indian e-challan phishing, XMR miner, silent install |
| Stub DEX | `classes.dex` → `System.loadLibrary("strangulation")` → `Application.onCreate()` → native `jD3P.SUO4()` |
| Native | `libstrangulation.so` (338 KB, arm64 — SHA-256 in `iocs.json`), one giant flattened function `Java_Dzhugashvili_jD3P_SUO4__` @ `0x110058` (~36k instrs) |
| Encrypted blob | `assets/myg0N` (7,714,912 B, entropy 8.0 — i.e. ciphertext) |
| Host shell | `dApp.binance.Trading.Signalt` (fake Binance branding), app label "Rto E-Chalan" |

**Why this was hard** (the two dead ends that forced our approach):

- **Decompiler dead end.** Ghidra's decompiler OOMs/timeouts even on 1 KB chunks
  of `SUO4` — the cause is structure, not size: 8,170 `eor` + 8,201 `ldrb` +
  8,207 `strb` in giant straight-line blocks with flattened control flow
  (`rto_analysis/ANALYSIS_REPORT.md` §3).
- **Dynamic dead end.** The sample fingerprints the environment
  (`Build.CPU_ABI`, `SUPPORTED_ABIS`, `MANUFACTURER` vs
  `unknown/generic/google`) and gates the real loader behind
  `SharedPreferences.getBoolean("v") == true` — a naive emulator run only ever
  executes the decoy accelerometer app.

---

## 3. Which file did what — the evidence map

This is the heart of the write-up. Read this section column-by-column and you
know the whole break. Files are grouped by the stage of the break they served.

> **Storage note:** only the published tool + writeups under `rto_analysis/` are
> git-tracked (`unpacking_tool.py`, `README.md`, `validation_matrix.md` — see
> `.gitignore` whitelist); recovered payloads, keys, traces and deep-dive reports
> are deliberately **local-only** evidence. §8 explains what is in git vs. what
> must be handed over separately.

### 3.0 The evidence itself (inputs)

| File | Role in the break |
|---|---|
| `RTO.apk` (repo root) | **The exhibit.** Never modified; all work is read-only on it. SHA-256 above is the chain-of-custody anchor. |
| `RTO.apk!assets/myg0N` | The 7.8 MB AES-CBC ciphertext that held the real payload (extract with `7z x RTO.apk`; we refer to it as `assets/myg0N` throughout because that is its path inside the APK). |
| `RTO.apk!lib/arm64-v8a/libstrangulation.so` | The packer's native decoder — the only interesting `.so` in the APK (the second `.so` is its arm32 twin). Extracted copies from the reference run: `analysis/unpack_standalone/work/libs/*.so`. |
| `RTO.apk!classes.dex` | The stub. Its only job is to load the `.so` and call `SUO4`. |

### 3.1 Triage — deciding this APK needs unpacking (M1)

| File | Role |
|---|---|
| `scripts/triage.py` | Structural packer triage — six heuristics (payload:dex size ratio, `assets/` entropy, native app-class loading, JNI export shape, packer marker files, native import profile). On RTO: **`packed_custom @ 0.85`**. No signature match — a bespoke crypter, not a known packer brand. |
| `data/packer_markers.json` | The known packer-brand marker table (H5) loaded by triage. |
| `data/triage_locklist_m0.csv` | The locklist used for the triage A/B validation run. |
| `rto_analysis/validation_matrix.md` | Triage + end-to-end validation run book: RTO `packed_custom @ 0.85` → **RECOVERED in 1.3 s**; six external packed samples (Ijiami ×3, Bangcle/SecNeo ×2, Java-XOR custom) all detected with the *right* verdict — zero false negatives. |

### 3.2 Ghidra setup & listings (Phase 0–2, Windows)

| File | Role |
|---|---|
| `tools/ghidra/` | Ghidra **12.1.3 PUBLIC** install used for the original analysis (`application.properties` verified), JDK 21. |
| `rto_analysis/ghidra_proj/RTO_win` | Windows-era analysis project **[not in this checkout]** — Ghidra projects are local-only; regenerate by importing the `.so` (auto-analysis ~14 s, 524 functions). Linux twin: `ghidra_proj_linux/RTO_linux` **[not in this checkout]**. |
| `rto_analysis/ListFuncs.java` | Lists the 524 functions in the `.so` so we could locate `SUO4` @ `0x110058`. |
| `rto_analysis/ghidra_scripts/DumpListing.java` | Dumps the raw instruction listing of `SUO4` — the ground truth the symbolic evaluator consumes. |
| `rto_analysis/phase2/listing_arm64.txt` | The 36,850-line dumped ARM64 listing **[not in this checkout]** (large intermediate; regenerate with `DumpListing.java`). It is the *input* to the next script, and the numbers below are quoted from it in `PHASE2_FINDINGS.md`. |
| `rto_analysis/ghidra_scripts/ChunkDecomp.java` | Proved the negative: decompiling isolated 1 KB chunks still times out (×45 s each) — documented so nobody repeats the dead end. |
| `rto_analysis/ghidra_scripts/DecryptStrings.java` | **The breaker.** Forward-pass listing-level symbolic evaluator. The packer decrypts strings inline per byte: `adrp/add xN,page` → base, `mov wK,#imm` → per-byte key, `ldrb` → cipher byte, `eor` → plain byte, `strb` → write-back. Script walks the listing's data-flow and recovers **7,857 bytes = 57.5% of the encrypted table**. |
| `rto_analysis/ghidra_scripts/SliceProbe.java` | Backward, frame-offset-aware memoized slicer that rescues the 642 bytes the forward pass missed (address-as-key `eor`, `movk` composition, `sub/ldur` frame-slot indirection). |
| `rto_analysis/ghidra_scripts/JniTrace.java` | Traps `JNIEnv` vtable offsets and records which JNI methods are called, in program order (36 sites recorded). |
| `rto_analysis/ghidra_scripts/BuilderTrace.java` | Attempt to log `StringBuilder.append` args statically — superseded by emulation (kept as provenance for why we went dynamic-in-emulation). |
| `rto_analysis/ghidra_scripts/EmulateJni.java` | First, skeleton Ghidra p-code emulator for JNI (historical; the real one is `EmulateJni2.java`, §3.4). |
| `rto_analysis/ghidra_scripts/AppendLogger.java`, `ProbeStores.java` | Small probes used while tuning emulator stubs and store-tracking. |
| `rto_analysis/DecompileJni.java`, `ListFuncs.java`, `jni_decode.py` | Support set: JNI-export decompilation, function listing, and mapping raw `JNIEnv` vtable offsets in disassembly back to JNI function names. |

### 3.3 Recovered strings, decoy DEX, crypto block (Phase 2–3 outputs)

| File | Role |
|---|---|
| `rto_analysis/phase2/decrypted_strings.txt` (+ `.bin` / `.map` / `.missing` / `.missed`) | The **7,857 recovered bytes / 381 strings**. `.bin` is the ranged dump used to carve out the decoy DEX; `.map` is the hex view used for provenance; `.missing` lists the offsets the evaluator could not resolve. |
| `rto_analysis/phase2/hidden.dex` | The decoy DEX: a 3,328-byte (`dex\n038`) fake `com.example.accelerometer` app, base64-decoded out of the string table @ `0x151c60`. This is the packer's camouflage — recovering it proved we were inside the *real* payload logic, not the decoy path. |
| `rto_analysis/phase2/crypto_block_annotated.txt` | 724-line annotated crypto flow — **where the KDF was first read out of the binary**: `NewStringUTF("myg0Nbootstrap.dex")` → `substring(0,5)` → `"myg0N"` → `StringBuilder.append("myg0N").append("2").toString()` → `getBytes(UTF_8)` → `SHA-1` → `Arrays.copyOf(...,16)` → `SecretKeySpec(...,"AES")`; a parallel `SHA-256` block builds the IV; then `Cipher.init(DECRYPT_MODE, …)` on `AssetManager.open("myg0N")` → `CipherInputStream` → `ZipInputStream` → entry `myg0Ninstaller.dex`. |
| `rto_analysis/phase2/jni_trace.txt` | Which JNI methods the stub calls and in what order — used to write the emulator's stub table faithfully. |
| `rto_analysis/phase2/decrypted_blob.bin` | Raw ranged dump of the decrypted `.data` region (carving source for `hidden.dex`). |
| `rto_analysis/PHASE2_FINDINGS.md`, `rto_analysis/PHASE3_FINDINGS.md` | Phase narratives: the decompiler failure analysis, the string-table layout, and the KDF reconstruction — plus the *honest* record of Phase 3's "remaining gap" (the exhaustive seed sweep that failed; see §4 Step 4 for why it failed). |
| `rto_analysis/ANALYSIS_REPORT.md` | The master Windows-era report (Phases 0–3): environment, listings, evaluator results, annotated crypto, and the brute-force logs' failure analysis. Carries the **CASE CLOSED** banner pointing at Phases 4–6. |

### 3.4 The emulator — where the key actually fell out (Phase 4)

| File | Role |
|---|---|
| `rto_analysis/ghidra_scripts_linux/EmulateJni2.java` | **The harness that produced ground truth.** ~700 lines of Ghidra p-code emulation: maps the `.so` at `0x100000`, allocates a stack, installs a fake `JNIEnv*` whose 0x900-byte vtable traps into per-index logged stubs, intercepts libc thunks (`malloc/memcpy/str*/pthread*`), and re-implements the Java side (`StringBuilder`, reflection, `MessageDigest`, `Cipher`, `Base64`, `AssetManager`). Runs `SUO4` and captures the exact assembled string and the live key/IV. Dual-arch (arm64/arm32); args: `[funcVA] [maxSteps] [outFile]`. |
| `rto_analysis/ghidra_scripts_linux/ProbeEntry.java`, `ProbeThumb.java` | Entry probes for the arm32/Thumb twin (misaligned-branch and `dmb` pcodeop landmines documented in `PHASE5_FINDINGS.md` §7). |
| `rto_analysis/phase2/emu_trace.txt` | The full JNI trace of the successful `SUO4` emulation run — the primary exhibit for "we observed the key being assembled, we did not guess it". |
| `rto_analysis/phase2/emu_trace_arm32.txt` | Partial arm32 trace (anti-disassembly; full run deferred — same shared crypto code, proven in arm64). |
| `rto_analysis/PHASE4_FINDINGS.md` | **The captured ground-truth crypto**: `seed = "myg0Nbootstrap.dex".substring(0,5) → "myg0N"`; `StringBuilder.append("myg0N").append("2").toString() → "myg0N2"` (**no hidden mutation** — the earlier "StringBuilder mutation" fear was a red herring / validation artifact); `KEY = SHA1("myg0N2")[:16]`; `IV = SHA256("myg0N2")[:16]`; `Cipher.init(2, key, iv)` on `AssetManager.open("myg0N")`. Also lists all 10 kit members (§3.5). |

**Emulator harness gates — all three were required; skipping one silently
breaks the capture** (this is the part an expert will ask about):

1. `SharedPreferences.getBoolean("v")` must return **true** — otherwise only
   the decoy accelerometer app runs and returns.
2. `System.currentTimeMillis()` must advance — otherwise the sample's poll loop
   spins forever.
3. JNI value (`jvalue`) args must be read as full 8-byte slots regardless of
   declared type.

### 3.5 The decrypted payload (Phase 4 output)

> **[not in this checkout]** The original `rto_analysis/phase4_payload/` working
> directory is local-only evidence. **The equivalent artifact is present:**
> `analysis/unpack_standalone/artifacts/kit.zip` (7,815,568 B, SHA-256
> `d414cb8f…614d1` — byte-identical to the `myg0N_decrypted.zip` IOC recorded in
> `iocs.json`), plus the full bundle in `analysis/ARTIFACTS.zip`.

| File (as referenced in PHASE4/5/6) | Role |
|---|---|
| `myg0N_decrypted.zip` | The decrypted 7.8 MB container — **proof the key is correct**: valid ZIP central directory, passes the strict validity gate (`testzip()` + EOCD + PK-magic tail). |
| `installer.dex` (201,330 B) | Stage-3 loader: `com.lqbczc.szubinocgulatizofn.*` — `Miner`, `MinerInstaller`, `MinerExecutableDownloader`, `MinerCommunicator`, `MinerLogParser`, class `LXMRwwbBebzOXNLwYv2` (**XMR miner**). |
| `bootstrap.dex` (13,184 B) | Dalvik bootstrap loader. |
| `payload_split0.apk` (1.57 MB) | Resources + base classes (appcompat UI shell); app label **"Rto E-Chalan"**. |
| `payload_split1.apk` (3.68 MB) | classes2–63.dex — Firebase/GMS-heavy host app; source of the `proj.App.decryptStream` key path (§3.7). |
| `payload_split2.apk` (245 KB) | `libpine.so` (Pine ART-hooking framework) + the encrypted `assets/dataQpoJzkbmfX` (178 KB). |
| `images.zip` (737 KB) | Fake Google Play kit: Play banner, 5-star strip, "Everyone" badge, installer icon, `output8.mp3` (the cluster's foreground-media keepalive trick). |
| `install_library.zip` (2.64 MB) | `com.google.installerlibrary.SplitApkInstaller` + `bypass.*` packages — the permission/signature-bypass **silent installer**; native JNI symbols unicode-escaped. |
| `payload_config.json` (276 B) | Split names, MAC `1YNvFYz2Q8RhDbm4gbUVsg==`, `subscriptionEndMillis=1782968017708` (~2026-06-05). |
| `miner_config.json` (219 B) | Split names, MAC `eVAmHju3UqrVWR56gOMaUQ==`, int64-max expiry (never expires). |
| `miner.apk` (0 B) | **Deliberately empty placeholder** — the real miner ELF is fetched at runtime (evidence for the runtime-delivery boundary, §7). |
| `rto_analysis/PHASE5_FINDINGS.md` | What the decrypted payload *contained*: XMR miner lifecycle, C2 `aptabase.jesfeoqrj3.xyz:8443`, pool `pool.jesfeoqrj3.xyz:8443`, Firebase `waking-21b04`, xmrig flags, silent-install and Pine techniques, full IOC table. |
| `rto_analysis/PHASE6_FINDINGS.md` | Victim-facing narrative ("Rto E-Chalan" + mParivahan WebView phishing flow), the **two runtime key schemes**, attribution to the public BeatBanker/BTMOB cluster, and the detection deliverables. |

### 3.6 The shippable toolchain — the break as a repeatable pipeline (M1/M2/M3/M3b)

This is the portable version of the Ghidra harness: same break, no Ghidra
needed, self-validating output.

| File | Role |
|---|---|
| `rto_analysis/unpacking_tool.py` | **The standalone CLI** (tracked): `--input RTO.apk --output recovered/ [--stage3] [--bundle] [--timeout]`. Always ends in `RECOVERED` (self-validated artifacts) or a typed E-code naming the exact failure. |
| `scripts/unpack.py` | The master-key dispatcher the tool drives: routes native/Java, runs validators (`pkcs7_tail_ok`, `validate_dex`, `validate_zip`), the **`myg0n_kdf_bruteforce` probe** (the KDF path that actually re-cracked RTO in the reference run — see §4 Step 4), and emits typed E-codes (`E-NATIVE-NOENTRY`, `E-JAVA-RUNTIME-DELIVERY`, …). |
| `scripts/emulate.py` | The Unicorn/LIEF JNI emulation oracle: loads the ELF (x86_64, ARM32-Thumb, ARM64), mocks a 233-slot `JNIEnv*` vtable, **replays `StringBuilder` assembly in Python**, sweeps decrypted blobs from memory and validates them (`dex\n` / ZIP magic) before reporting. |
| `scripts/rto_oracle.py` | RTO-specific final oracle: runs the arm64 `SUO4` under Unicorn with full libc + JNIEnv shims and reads out the decrypted base64→DEX from `.data`. |
| `scripts/rto_deep_run.py` | Corrected-vtable continuation with disk checkpointing (every 2M instructions) and device-property serving for key derivation. |
| `scripts/ijiami_oracle.py` | Generalization proof: same harness runs `JNI_OnLoad` in a fake `JavaVM` table — it enumerated the **Ijiami packer's** `RegisterNatives` table, showing the oracle is packer-agnostic. |
| `scripts/triage.py`, `data/packer_markers.json` | M1 (see §3.1). |
| `stage3_replay.py` (repo root) | **M3b: byte-for-byte Python replay** of the installer's 64-bit mul-xorshift PRNG (`lmk`/`nkwa`/`ohm`/`step`, constant `-0x34DB2F5A3773CA4D`) over the CJK pool — straight port of the smali in `_hole1_smali/`. Acceptance: **175/180 seeds byte-identical**, 5 residuals documented. |
| `scripts/stage3_deobfuscator.py` | Earlier in-repo variant of the same replay (reads the seed fixture directly). |
| `cjk_pool.txt` (repo root) | The **4,320-char UTF-16 CJK pool** the installer strings index into (12,960 B = 4,320 × 3-byte UTF-8). Restored from `archive/cjk_pool_true.txt` after an earlier session corrupted it (`hole1_czrr_definitive.md`). |
| `rto_analysis/phase2/installer_deobfuscated_strings.json` (+ `.tsv`, `.summary.json`) | **The seed fixture & result:** 221 seed entries, **177 decoded** strings (`.summary.json`), incl. every infrastructure IOC. The replay's acceptance test checks itself against this file. |
| `rto_analysis/stage3.md` | The PRNG replay specification + acceptance record (status CLOSED 2026-09-18). |
| `tests/test_stage3_replay.py` | Acceptance test: asserts `matches == 175`, `mismatches == 5`, that the 5 residual seeds are exactly the documented ground-truth artifacts, and spot-checks known seeds (e.g. `-9154610674182 → "app_installation"`). |
| `tests/test_unpacking_tool.py` | Tool contract tests: usage errors, kit detection gating, artifact/key collection, stage-3 materialization at the 175/5 bar, bundle excludes workdir. |
| `requirements.txt`, `requirements-lock.txt` | Deps; lock file pins the oracle runtime: `unicorn==2.1.4`, `lief==1.0.0`, `capstone==5.0.9`, `pycryptodome==3.23.0`, `androguard==4.1.4`. |
| `rto_analysis/README.md` | The standalone technical report for the tool (motivation, 4-stage pipeline, E-code contract, dependencies, honest boundaries). |
| `rto_analysis/validation_matrix.md` | Expected reference output for a re-run (the table quoted in §3.1). |

### 3.7 The second layer — the runtime-keyed asset (Hole 5, SOLVED)

`assets/dataQpoJzkbmfX` (178,304 B) inside `payload_split2.apk` resisted every
static key candidate in Phase 4–5. This is how the follow-up hole closed it:

| File | Role |
|---|---|
| `_hole5/split1_smali/proj/App.smali` | **Source of truth for the key path.** Line-referenced smali showing `hookResource(Context)` scans assets for the first name starting with `data` (`:270-295`), calls `decryptStream(name, stream)` (`:299-303`), which takes the basename after `/` split (`:135-146`), appends `"1"` (`:157-159`), `SHA-1`, `Arrays.copyOf(...,0x10)` (`:193-196`) → AES/CBC/PKCS5Padding with **zero IV** (`new byte[blockSize]`, `:208-217`) → `CipherInputStream` (`:225-227`). **→ key = `SHA1(asset_basename + "1")[:16]`, IV = 0.** |
| `_hole5/split1_smali/proj/App$1.smali` | The Pine hook that re-injects the asset path into every future `ResourcesImpl` constructor (resource-level stealth injection). |
| `_hole5/assets/dataQpoJzkbmfX` | The encrypted asset itself (extracted for independent verification). |
| `_hole5/dec_payload+1.bin` | **The independently decrypted result:** 178,302 B, `PK\x03\x04` magic, valid ZIP. SHA-256 `6fefa4e3…cf4af` **matches the IOC hash recorded in `detections/iocs.json`** for `dataQpoJzkbmfX_decrypted.apk`. Contents: `index.html` (mParivahan Sign Up), `method.html` (payment picker), `cc.html` (card CVV), `pin.html` (UPI PIN), `final.html` (fake success) — **the phishing kit**. |
| `archive/_hole5_verify.py` | The verification script for the above, incl. the **negative control**: the installer scheme `SHA1(basename)[:16]` (without `"+1"`) *fails* pad verification — proving the two-key split is real, not coincidental. |
| `rto_analysis/hole5_keypath.md` | The write-up: full key-path table, the independent re-decryption, and **Task D** — decoding the miner payload's 210 Unicode-homoglyph-obfuscated constants via the seeded xorshift chain (Java + Python decoders byte-identical, 10,535 B output), which yielded the operator infra (pool, telemetry, Firebase/FCM, bin-rotation URLs). |

**The two verified key schemes (the "key-path table" an expert will want):**

| Scheme | Key | Verifies with |
|---|---|---|
| payload `proj.App.decryptStream` | `SHA1(asset_basename + "1")[:16]`, IV = 0 | encrypted assets (`data*`) — e.g. `dataQpoJzkbmfX` |
| installer `SecureAssets.decryptFile` | `SHA1(file_basename)[:16]`, IV = 0 | downloaded files (e.g. the miner ELF) |

*(A negative control — the installer scheme without the `+1` — fails on the
asset, which is what rules out a false positive on the derivation.)*

### 3.8 Stage-3 string obfuscation & its ground truth (Hole 1)

| File | Role |
|---|---|
| `_hole1_smali/*.smali` | Fresh baksmali of the installer's `classes.dex` — the **authoritative smali** (the jadx decompiler *inserted* wrapped/clamped indices the real code does not have; this file settles that). |
| `archive/TestTrueSMALI.java` | Instrumented smali-exact port compiled against the real jadx classes and real pool: `Matches 174 Mism 6 Crash 0` — proved the decoder is correct and the 6 "mismatches" are ground-truth labeling artifacts. |
| `archive/test_true_smali_result.txt` | The run output above. |
| `archive/TestLang.java` | Key→value table test: all 28 `addTranslation(key,value)` pairs decode to a clean English/Spanish map. |
| `archive/cjk_pool_true.txt` | Authority copy of the pool (`jadx == smali: True`, 4,320 chars) used to restore the corrupted `cjk_pool.txt`. |
| `rto_analysis/hole1_czrr_definitive.md` | The definitive write-up: true smali semantics (`div-int/lit16` / `rem-int/lit16` with literal `0x1fff` = 8191 — no `%strArr.length`, no clamping), why the 8191-divisor is vestigial for this 4,320-char pool, and the seed-by-seed disposition of every mismatch. |
| `rto_analysis/hole2_payload_deepdive.md`, `hole2_threat_intel.md`, `hole2_generalization.md`, `hole4_relabel.md` | Sibling-hole evidence: another sample's Java-layer XOR decryption + SMS-banker C2 chain, its authority-reportable threat-intel report, generalization notes, and label corrections. |

### 3.9 Detection — what we handed to the blue team

| File | Role |
|---|---|
| `rto_analysis/detections/beatbanker_rto.yar` | **8 YARA rules** (rule count verified against the file), validated with yara-python against this sample's components: JNI export pun, obfuscator class names, Firebase config, Aptabase telemetry, config JSON schema, Pine framework, bypass installer, mParivahan phishing strings. |
| `rto_analysis/detections/iocs.json` | The IOC bundle: sample hashes, network IOCs, **both Firebase configs**, the **crypto derivations incl. recovered key/IV hex**, package names, SHA-256 of every payload member, cluster attribution references, domain-registration data. |
| `rto_analysis/detections/README.md` | Coverage map + validation record: **0 false positives** on the sweep (101 benign + 150 unrelated-malware APKs; recorded as a 540-file sweep in the thesis), plus the rotation-resistant design rationale (anchor on architecture, not rotating domains) and the gotcha that DEX rules need raw `.dex`, not ZIP wrappers. |

### 3.10 Files referenced but **not** in this checkout (and what to use instead)

| Referenced path | Status | Use instead |
|---|---|---|
| `extracted/…` (older notes) | Never a repo path — it was an ad-hoc extraction dir | `RTO.apk!assets/myg0N`, or `analysis/unpack_standalone/work/libs/*.so` |
| `rto_analysis/ghidra_proj/*`, `ghidra_proj_linux/*` | Local-only (regenerable) | Import `libstrangulation.so` into a fresh Ghidra project (§6, Path B) |
| `rto_analysis/phase2/listing_arm64.txt` | Local-only intermediate | Regenerate with `DumpListing.java` |
| `rto_analysis/phase4_payload/*` | Local-only evidence | `analysis/unpack_standalone/artifacts/kit.zip` (hash-verified identical to the IOC) + `analysis/ARTIFACTS.zip` |
| `try_keys20.py`, `phase2/live_brute*.log`, `buildertrace.log` | Session-era scratch, never committed | The failure analysis survives in `ANALYSIS_REPORT.md` §4–§5; the *successful* equivalent is `scripts/unpack.py` → `myg0n_kdf_bruteforce()` |
| `Hole5Decode.java` / `Hole5Decode.py` | Not present | `hole5_keypath.md` documents the algorithm; `archive/_hole5_verify.py` performs the decryption |

---

## 3B. How we know the break is correct (verification & controls)

A decrypted file alone proves nothing — wrong AES keys also produce bytes.
Every claim in this document rests on these independent checks, each
traceable to a file:

| # | Check | What it proves | Where |
|---|---|---|---|
| V1 | **Structural validity gate**: `ZipFile.testzip()` + EOCD + PK-magic tail on the decrypted container; 10 entries validated | The key is right: a wrong key cannot yield a well-formed ZIP central directory | `scripts/unpack.py` → `validate_zip()`; run record `analysis/unpack_standalone/stage2_report.json` (`"validated": {"entries": 10}`) |
| V2 | **Hash cross-check**: decrypted kit SHA-256 `d414cb8f…614d1` equals the `myg0N_decrypted.zip` IOC recorded in Phase 4, before the tool existed | The tool reproduces the *original* Phase-4 artifact byte-for-byte — no drift, no re-derived coincidence | `analysis/unpack_standalone/artifacts/kit.zip` vs `rto_analysis/detections/iocs.json` §`sha256_payload_members` |
| V3 | **Independent second-layer decryption** of `dataQpoJzkbmfX` with its own scheme; result SHA-256 `6fefa4e3…cf4af` matches the recorded IOC | The `+1` key-path split is correct; the two layers were broken by two independent derivations | `_hole5/dec_payload+1.bin` vs `iocs.json`; procedure `archive/_hole5_verify.py` |
| V4 | **Negative control**: applying the *installer* scheme (`SHA1(basename)[:16]`, no `+1`) to the asset **fails** PKCS#7 pad verification | V3 is not a lucky match — the wrong-sibling key demonstrably does not work | `rto_analysis/hole5_keypath.md` |
| V5 | **Byte-exact string replay**: the PRNG port regenerates **175/180** recorded strings byte-identically; the 5 residuals are proven ground-truth *labeling* artifacts, seed by seed | The 177 decoded strings/IOCs were regenerated from the malware's own algorithm, not transcribed from output | `stage3_replay.py`; `tests/test_stage3_replay.py` (asserts exactly 175/5 and pins the residual seed list); `rto_analysis/hole1_czrr_definitive.md` |
| V6 | **A/B validation on unrelated samples**: 6 external packed samples (Ijiami ×3, Bangcle/SecNeo ×2, Java-XOR ×1) all detected with the *correct* verdict; failures return typed E-codes naming why — never a fabricated payload | The pipeline does not hallucinate recoveries; RTO's success is not selection bias | `rto_analysis/validation_matrix.md` |
| V7 | **Detection false-positive sweep**: 8 YARA rules → 0 hits on 101 benign + 150 unrelated-malware APKs (540-file sweep) | The findings generalize into deployable signatures anchored on architecture, not rotating strings | `rto_analysis/detections/README.md`; `thesis/06_unpacking_case_study.md` §6.6 |
| V8 | **Cross-sample family corroboration**: the same KDF (`SHA1(seed)[:16]` / `SHA256(seed)[:16]`, seed = `asset_stem + "2"`) unlocked 5 sibling seized APKs into byte-identical kits | The break is a property of the *builder*, not a one-off lucky seed | `docs/cases/pendrive-56-apks/CASE_STUDY.md` §3; `ARTIFACTS_SENSITIVE.md` §8 |

**What these checks do *not* establish (stated up front):**

- For a live sample there is no external "answer key": ground truth *is* the
  successful decrypt plus an independent hash match. V1/V4 are self-validated
  gates; V2/V3 anchor them to hashes recorded *before* the tool was written.
- V5 carries the 5 known residuals — documented and pinned by test, not
  silently ignored.
- Runtime-fetched stages (miner ELF, pool parameters) were never pulled from
  live infrastructure and are out of scope (§7).

---

## 4. The break, step by step (what to say out loud)

### 4.0 How we discovered it was encrypted (not just that it was packed)

1. **Open the APK like a ZIP.** `7z l RTO.apk` shows two anomalies: a tiny
   `classes.dex` (a stub, ~50 KB at most) and a 7.8 MB `assets/myg0N` blob
   with a random name. `assets/myg0N` entropy ≈ 8.0 — nearly random bytes,
   i.e. ciphertext, not a compressible image or sound file. *Files:
   `7z l RTO.apk`, `extracted/assets/myg0N`.*
2. **Java strings are useless.** The stub `classes.dex` has no C2, no package
   names, no URLs — only a JNI loader. Standard IOC extraction finds nothing.
   This is the defining smell of a packed sample. *File: `classes.dex`.*
3. **Threat triage confirms "packed".** `scripts/triage.py` gives
   `packed_custom @ 0.85` via H1–H6 heuristics (payload:dex ratio, asset
   entropy, native loading, JNI export shape, packer markers, import profile).
   *Files: `scripts/triage.py`, `data/packer_markers.json`.*
4. **Where does it call into native?** The stub does
   `System.loadLibrary("strangulation")` then `jD3P.SUO4()`. So all payload
   logic is in `lib/arm64-v8a/libstrangulation.so`. *File: the stub's
   `classes.dex` → `extracted/lib/arm64-v8a/libstrangulation.so`.*
5. **The native function won't decompile.** `Java_Dzhugashvili_jD3P_SUO4__`
   @ `0x110058` is ~36,000 straight-line instructions of explicit
   control-flow flattening. `ChunkDecomp.java` shows even 1 KB chunks time
   out in Ghidra's decompiler. This is why the decompiler path is a dead end.
   *Files: `ghidra_scripts/ChunkDecomp.java`, `phase2/chunks_micro`.*
6. **Listing walk shows it's an XOR string decoder.** The same instruction
   shape repeats ~8,000 times: `ldrb/mov/eor/strb`. That is a byte-wise XOR
   table being decoded into `.data`. `DecryptStrings.java` replays exactly
   that: 7,857 bytes recovered, and from it — asset names, Cipher string
   `AES/CBC/PKCS5Padding`, `SHA-1`, `SHA-256`, the `InMemoryDexClassLoader`
   path. *Files: `ghidra_scripts/DecryptStrings.java`,
   `phase2/decrypted_strings.txt`.*
7. **First plaintext is a decoy.** The blob at `0x151c60` decodes to a
   Base64 `dex\n038` DEX — a fake `com.example.accelerometer` app. That
   fake payload is our confirmation that the decoder is the packer's own and
   that the real payload is deeper. *File: `phase2/hidden.dex`.*
8. **The crypto block names the recipe.** `crypto_block_annotated.txt` walks
   the KDF as written in the binary:
   `"myg0Nbootstrap.dex".substring(0,5) → "myg0N"`,
   `StringBuilder.append("myg0N").append("2").toString() → "myg0N2"`,
   then `SHA-1(...)` → `copyOf(...,16)` → `SecretKeySpec(...,"AES")`,
   parallel `SHA-256(...)` → IV. Seed = `"myg0N2"`. *File:
   `phase2/crypto_block_annotated.txt`.*
9. **Why we didn't just brute-force the key.** 98 seeds × 3 KDFs × 857k
   suffixes all failed, because the earlier linear tracker couldn't model
   the `StringBuilder` mutation and the tail validation probe was wrong
   (`phase2/live_brute2.log`, `try_keys20.py`). The brute-force *was*
   trying the right key — the validation artifact hid it. The JNI emulator
   is what removed the artifact. *Files: `try_keys20.py`,
   `phase2/live_brute2.log`, `phase2/emu_trace.txt`.*
10. **Emulation proves it.** `EmulateJni2.java` runs `SUO4` under a fake
    JNIEnv; `StringBuilder.toString()` comes out as `"myg0N2"`;
    `SHA1("myg0N2")[:16]` decrypts `assets/myg0N` to a structurally valid
    10-entry ZIP. End of ambiguity. *File:
    `rto_analysis/ghidra_scripts_linux/EmulateJni2.java`.*
11. **Same kit, different seed → "myg0N is the packer, not the sample."**
    `RTO E CHALLAN (1).apk` uses the same 10-entry ZIP layout with seed
    `UZrF0u2`, different asset name `assets/UZrF0u`. The KDF construction is
    identical. So "we broke the KDF recipe of the myg0N kit" is the claim,
    not "we broke one APK." *File:
    `analysis/recovered/RTO_E_CHALLAN_1/key_material.json`.*

### 4.1 The actual break, step by step (what to say out loud)

**Step 0 — triage.** `scripts/triage.py` flags the APK: tiny stub DEX, native
libs, `assets/myg0N` entropy 8.0 → `packed_custom @ 0.85`. No signature match:
a bespoke crypter. *(Files: `scripts/triage.py`, `data/packer_markers.json`.)*

**Step 1 — accept that the decompiler is dead.** `ChunkDecomp.java` proves
Ghidra's decompiler times out even on 1 KB chunks — control-flow flattening,
not size. So we move to the *listing*, not the decompiler.
*(Files: `ghidra_scripts/ChunkDecomp.java`, `ANALYSIS_REPORT.md` §3.)*

**Step 2 — decode the packer's strings inline.** `DecryptStrings.java` walks
the `ldrb/mov/eor/strb` chains in the listing and recovers **7,857 bytes
(57.5%)**; `SliceProbe.java` fills the 642-byte gap. From them we learn:
asset name `myg0N`, cipher `AES/CBC/PKCS5Padding`, the KDF pair
`SHA-1`/`SHA-256`, the `InMemoryDexClassLoader` decoy path — and we carve
`hidden.dex`, the packer's own camouflage DEX. *(Files: `ghidra_scripts/DecryptStrings.java`,
`SliceProbe.java`, `phase2/decrypted_strings.txt`, `phase2/hidden.dex`.)*

**Step 3 — read the key schedule straight out of the annotated listing.**
`phase2/crypto_block_annotated.txt` shows: `"myg0Nbootstrap.dex"` →
`substring(0,5)` → `"myg0N"` → `StringBuilder` appends `"2"` →
`getBytes(UTF_8)` → `SHA-1` → `copyOf 16` → `SecretKeySpec(...,"AES")`; IV from
a parallel `SHA-256` block. **Seed = `"myg0N2"`.**

**Step 4 — confirm by emulation, and understand why the earlier brute force
missed.** `EmulateJni2.java` (Ghidra p-code + fake JNIEnv) executes the real
`SUO4`, replays `StringBuilder`, and captures the live key/IV — no guessing.
The Phase-3 exhaustive sweep (98 seeds × 3 KDFs, 857k suffix permutations, per
`ANALYSIS_REPORT.md` §4) had *failed* because of a validation-methodology
artifact or a genuinely un-modelled mutation — Phase 4 showed the string assembles
to exactly `"myg0N2"` with **no hidden mutation**, which resolved it: the key
was always `SHA1("myg0N2")[:16]`. In the shipped tool, when the Unicorn oracle
faults (as it did on the arm32 twin in the reference run — see
`analysis/unpack_standalone/stage2_report.json`), the `myg0n_kdf_bruteforce()`
probe re-derives the same seed from the asset-naming convention and validates
against the container's PK-magic — which is what produced verdict `RECOVERED`
in 1.31 s on this machine. *(Files: `EmulateJni2.java`, `phase2/emu_trace.txt`,
`PHASE4_FINDINGS.md`, `scripts/unpack.py`, `stage2_report.json`.)*

**Step 5 — decrypt, then let validity prove the key.** AES-128-CBC on
`assets/myg0N` yields a valid 10-entry ZIP (`testzip()` + EOCD pass;
`installer.dex` present; `payload_config.json` MAC intact). Output:
`analysis/unpack_standalone/artifacts/kit.zip` (hash-identical to the recorded
IOC). A wrong key cannot produce this.

**Step 6 — the second layer.** `assets/dataQpoJzkbmfX` is decrypted with its
*own* scheme, `SHA1(basename + "1")[:16]`, zero IV — derived from
`_hole5/split1_smali/proj/App.smali` and confirmed by an independent
re-decryption whose SHA-256 matches the recorded IOC (`hole5_keypath.md`,
`archive/_hole5_verify.py`). Contents: the mParivahan card/UPI phishing kit.

**Step 7 — strings & infrastructure.** `stage3_replay.py` replays the
installer's PRNG over `cjk_pool.txt` and regenerates the string fixture
byte-identically for 175/180 seeds → 177 decoded strings incl. C2
`aptabase.jesfeoqrj3.xyz:8443`, pool `pool.jesfeoqrj3.xyz:8443`, Firebase
`waking-21b04`, FCM topics, xmrig flags, and the `MESSAGE_TO_HACKER` taunt.
The 5 residuals are documented ground-truth artifacts
(`tests/test_stage3_replay.py`, `hole1_czrr_definitive.md`).

**Step 8 — detection & hand-off.** 8 YARA rules + `iocs.json`, **0 false
positives** on the validation sweep, designed to anchor on architecture rather
than rotating domains.

---

## 5a. Explaining it to a LEA (non-technical audience)

- **"The APK is a locked box.** The small `classes.dex` is just the box's lid
  opener. The real contents are inside `assets/myg0N`, an encrypted 7.8 MB blob."
- **"The combination is not written anywhere on disk.** The malware builds it in
  memory, inside a function that is deliberately scrambled so decompilers give
  up (36,000 instructions of flattened logic)."
- **"We did not pick the lock by forcing it.** We emulated the malware's own
  native code in a controlled environment we fully own (a toy CPU with fake Java
  APIs) — which made the malware decrypt its own payload for us and show us the
  combination. We never installed it on a phone; nothing ever touched a victim
  device."
- **"The key is proven, not guessed.** With the key, the encrypted blob opened
  into a valid archive containing a crypto-miner, a phishing kit that steals
  card and UPI details, and a silent-installer library. A wrong key produces
  garbage; ours produced a working archive whose SHA-256 we recorded before
  analysis and never modified."
- **"Every step is reproducible.** Our tool re-derives the key and re-opens the
  archive in about 1.3 seconds on a clean machine, and the 8 detection
  signatures built from the findings matched our sample while producing zero
  false alarms on ~250 unrelated benign and malware apps."
- **"The infrastructure names we report come from the malware itself** —
  telemetry endpoints, mining pool, Firebase project — not from guesswork, and
  they corroborate public reporting on the same criminal cluster."

## 5b. Explaining it to an expert (technical audience)

- Control-flow flattening makes `libstrangulation.so!SUO4` un-decompilable;
  semantics were recovered at the **listing level** via a forward symbolic
  evaluator (`DecryptStrings.java`: `adrp/add → mov #imm → ldrb → eor → strb`
  per byte) plus a backward memoized slicer (`SliceProbe.java`: frame-offset
  tracking for `sub x9,x29,#off; ldur` slots, `movk`, address-as-key `eor`).
- KDF: `KEY = SHA1(seed)[:16]`, `IV = SHA256(seed)[:16]`, `seed =
  "myg0Nbootstrap.dex".substring(0,5) + "2" = "myg0N2"`. AES-128-CBC/PKCS5,
  read out of an annotated listing and *confirmed* by p-code emulation of the
  real function under a fake `JNIEnv*` (vtable trap by `offset/8` index).
- Harness contract: `SharedPreferences.getBoolean("v") == true`, monotonic
  `currentTimeMillis()`, 8-byte `jvalue` slots — without these the emulator
  silently captures only the decoy path.
- Two independent recovery routes agree: Ghidra p-code emulation (ground truth,
  Phase 4) and the Unicorn/LIEF oracle + `myg0n_kdf_bruteforce` KDF probe in the
  shipped tool (reference run `RECOVERED`, 1.31 s, arm32 oracle faulted with
  `UC_ERR_INSN_INVALID` and the KDF route completed the recovery — recorded in
  `stage2_report.json`).
- Second layer: `dataQpoJzkbmfX` → `SHA1(basename + "1")[:16]`, zero IV,
  independently re-decrypted; hash matches the IOC; installer scheme
  (`SHA1(basename)[:16]`) fails as a negative control — two-key split, not a
  lucky match.
- Stage-3: seeded 64-bit mul-xorshift (`-0x34DB2F5A3773CA4D`) indexing a
  4,320-char CJK UTF-16 pool; replayed byte-identically for **175/180** seeds;
  the 5 residuals are proven ground-truth labeling artifacts (jadx inserts
  clamping the real smali lacks — `hole1_czrr_definitive.md`).
- Honest boundary: the miner ELF and pool/wallet are fetched at runtime
  (`miner.apk` is a 0-byte placeholder), the arm32 twin's full run is deferred
  (anti-disassembly: misaligned Thumb branches, literal-pool landmines,
  unimplemented `dmb` pcodeops), and Java-only unpackers are out of scope for
  the JNI-layer oracle by design.

---

## 6. Reproducibility — step-by-step on a fresh machine

> Two paths. **Path A (fast, recommended)**: the standalone Python tool,
> re-derives key + kit in about a second. **Path B (faithful, slow)**: re-runs
> the Ghidra p-code emulator that originally recovered the key — use it when you
> need the raw JNI trace as evidence. Both are read-only on the APK.

### 6.0 Prerequisites

| Item | Version we used | Why | Verify |
|---|---|---|---|
| Python | ≥ 3.10 | tool runtime | `python --version` |
| pip deps | `requirements-lock.txt` (pins `unicorn==2.1.4`, `lief==1.0.0`, `capstone==5.0.9`, `pycryptodome==3.23.0`, `androguard==4.1.4`) | oracle runtime | `pip install -r requirements-lock.txt` |
| JDK | 21+ | Ghidra (Path B) | `java -version` |
| Ghidra | 12.1.3 PUBLIC (`tools/ghidra/`) | Path B only | `support/analyzeHeadless.bat` runs |
| OS | Windows 10/11 or Linux | both were used | — |

**Files required for Path A:** `RTO.apk`, `rto_analysis/unpacking_tool.py`,
`scripts/unpack.py`, `scripts/emulate.py`, `scripts/triage.py`,
`data/packer_markers.json`, `cjk_pool.txt`, `stage3_replay.py`,
`rto_analysis/phase2/installer_deobfuscated_strings.json`,
`tests/test_unpacking_tool.py`, `tests/test_stage3_replay.py`.

### Path A — one command (≈ 1–2 min)

```bash
# from repo root:
pip install -r requirements-lock.txt

python rto_analysis/unpacking_tool.py --input RTO.apk --output recovered/ --stage3 --bundle --timeout 480
```

Expected outputs (compare against `rto_analysis/validation_matrix.md`; our
reference run on this machine is preserved under `analysis/unpack_standalone/`):

| Artifact | What success looks like |
|---|---|
| `recovered/artifacts/kit.zip` | valid ZIP with `installer.dex`, `bootstrap.dex`, `payload_split{0,1,2}.apk`, `images.zip`, `install_library.zip`, `payload_config.json`, `miner_config.json`, `miner.apk` (10 entries; SHA-256 `d414cb8f…614d1`) |
| `recovered/artifacts/recovery_keys.json` | `seed = myg0N2` + key/IV hex (verify: `KEY == sha1(b"myg0N2").digest()[:16]`) |
| `recovered/stage2_report.json` | `"verdict": "RECOVERED"` |
| `recovered/strings.json` / `.tsv` | stage-3 strings incl. `aptabase.jesfeoqrj3.xyz`, Firebase `waking-21b04` |
| `recovered/summary.json` | verdict + `stage3.matches == 175` / `mismatches == 5` + timing (~1.3 s) |
| exit code | `0` |

Acceptance tests:

```bash
pytest tests/test_unpacking_tool.py tests/test_stage3_replay.py -q
# expect: 175/180 seeds byte-identical, 5 residuals = documented artifacts
```

### Path B — Ghidra p-code emulator (the original key recovery)

| Step | Command / file | Why |
|---|---|---|
| 1 | `7z x RTO.apk -oRto_extracted` | get `libstrangulation.so` + `assets/myg0N` |
| 2 | Import `Rto_extracted/lib/arm64-v8a/libstrangulation.so` into a **fresh** Ghidra project (the old `ghidra_proj*` dirs are local-only) | auto-analysis ~14 s, 524 functions |
| 3 | run `rto_analysis/ListFuncs.java` | locate `SUO4` @ `0x110058` |
| 4 | `rto_analysis/ghidra_scripts/DumpListing.java` → `phase2/listing_arm64.txt` | ground-truth listing |
| 5 | `rto_analysis/ghidra_scripts/DecryptStrings.java` (+ `SliceProbe.java`) | recover 7,857 B → `phase2/decrypted_strings.txt` |
| 6 | inspect `phase2/crypto_block_annotated.txt` | confirm seed assembly `"myg0N"+"2"`, SHA-1/SHA-256 KDF, AES/CBC/PKCS5 |
| 7 | run `rto_analysis/ghidra_scripts_linux/EmulateJni2.java` via `analyzeHeadless`, args `[funcVA] [maxSteps] [outFile]` (e.g. `0x110058`) | executes `SUO4` under fake JNIEnv → `phase2/emu_trace.txt` |
| 8 | read the key from the trace; re-derive: `sha1(b"myg0N2")[:16]` / `sha256(b"myg0N2")[:16]` | must match `PHASE4_FINDINGS.md` |
| 9 | AES-128-CBC(`assets/myg0N`, KEY, IV) → ZIP | valid ZIP = proof |
| 10 | `pytest tests/test_stage3_replay.py` | byte-check the strings |

> **arm32 twin:** needed NOP-patching of `dmb` pcodeops and Thumb
> misaligned-branch fixes (`ProbeThumb.java`) — documented in
> `PHASE5_FINDINGS.md` §7. Not required: the crypto derivation is shared code
> proven in arm64.

### 6.1 If you only want the proof points (no re-run)

1. `rto_analysis/phase2/decrypted_strings.txt` — 7,857 recovered bytes.
2. `rto_analysis/phase2/crypto_block_annotated.txt` — the key schedule as it
   exists in the binary.
3. `rto_analysis/phase2/emu_trace.txt` — the live JNI trace showing `"myg0N2"`
   being assembled.
4. `analysis/unpack_standalone/artifacts/kit.zip` — the decrypted dropper kit
   (SHA-256 matches the IOC in `detections/iocs.json`).
5. `rto_analysis/phase2/installer_deobfuscated_strings.json` — 177 decoded
   IOC strings.
6. `rto_analysis/detections/beatbanker_rto.yar` + `iocs.json` — the detection
   bundle.
7. One-liner to re-derive the key material from the seed:

```bash
python -c "import hashlib;print(hashlib.sha1(b'myg0N2').hexdigest()[:32]);print(hashlib.sha256(b'myg0N2').hexdigest()[:32])"
```

### 6.2 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| tool exits `E-ORACLE-FAULT` | Unicorn/LIEF version drift | use `requirements-lock.txt` pins |
| oracle faults with `UC_ERR_INSN_INVALID` on arm32 lib | known; arm32 run deferred | recovery continues via the KDF probe — this is the *recorded* behavior of the reference run |
| key recovered but ZIP invalid | wrong IV slice | IV is `SHA256(seed)[:16]`, **not** the first 16 bytes of the decrypted blob |
| stage-3 replay ≠ fixture | expected on 5 seeds | residuals are documented ground-truth artifacts (`test_residual_mismatches_are_documented_artifacts`) |
| Ghidra decompiler OOM/timeout | control-flow flattening | expected — use the listing, not the decompiler |
| `dataQpoJzkbmfX` won't decrypt | wrong scheme | it uses `SHA1(basename + "1")[:16]`, not the `myg0N2` seed (`hole5_keypath.md`) |

---

## 7. What we did *not* claim (the honest boundaries)

- **Runtime-fetched stages stay runtime-fetched.** `miner.apk` is a 0-byte
  placeholder; the miner ELF, and the pool/wallet parameters, are delivered at
  runtime from the C2. We documented the delivery path and the
  `SHA1(file_basename)[:16]` decryption scheme for downloaded files, but we did
  not pull payloads from live infrastructure.
- **The arm32 twin is structurally confirmed, not fully emulated.** Same
  obfuscation family (identical `ldrb/eor` chains, same JNI design); the full
  run was deferred due to layered anti-disassembly (`PHASE5_FINDINGS.md` §7).
  The crypto derivation is shared code, proven in arm64.
- **We did not decompile `SUO4`** — it is un-decompilable by design; we
  *evaluated* it.
- **5 residual stage-3 seeds** are documented ground-truth artifacts, not a
  tooling failure — proven seed-by-seed in `hole1_czrr_definitive.md` and pinned
  by `tests/test_stage3_replay.py`.
- **Java-only unpackers are out of scope** for the JNI-layer oracle (typed
  `E-JAVA-*` results instead of a fabricated payload), and packers that register
  natives at runtime return `E-NATIVE-NOENTRY` with the next step named —
  the tool never invents a recovery.

---

## 8. Evidence handling: what is in git vs. what must be handed over

| Category | In git (tracked) | Local-only (gitignored / to be handed over as evidence) |
|---|---|---|
| Toolchain | `rto_analysis/unpacking_tool.py`, `rto_analysis/README.md`, `rto_analysis/validation_matrix.md`, `scripts/{triage,unpack,emulate,rto_oracle,ijiami_oracle,...}.py`, `stage3_replay.py`, `cjk_pool.txt`, `tests/*`, `data/packer_markers.json`, `requirements-lock.txt` | — |
| Findings / write-ups | `thesis/06_unpacking_case_study.md` (the case-study chapter), this document | `rto_analysis/PHASE{2..6}_FINDINGS.md`, `ANALYSIS_REPORT.md`, `hole*.md`, `stage3.md`, `PIPELINE_PROBE.md` — **whitelisted out of git by `.gitignore` (`rto_analysis/*`)** |
| Recovered artifacts | hashes of everything in `detections/iocs.json` → *local copy* | `phase2/*` outputs (`decrypted_strings.*`, `hidden.dex`, `emu_trace.txt`, `crypto_block_annotated.txt`, `installer_deobfuscated_strings.json`), `phase4_payload/` → equivalent `analysis/unpack_standalone/artifacts/kit.zip`, `analysis/ARTIFACTS.zip`, `_hole5/`, `_hole1_smali/` |
| Detections | — (hand over as files) | `detections/beatbanker_rto.yar`, `detections/iocs.json` |
| Key material | derivations only (formulas) | exact key/IV hex: `detections/iocs.json` §`crypto`, `docs/cases/pendrive-56-apks/ARTIFACTS_SENSITIVE.md` §8 |

**For a formal hand-over, package:** `RTO.apk` (original, untouched),
`analysis/ARTIFACTS.zip`, the `rto_analysis/` evidence directory,
`detections/`, this document, and the hashes in §2/§6.1.

---

## 9. Related case — the same break, five more APKs

The KDF family proved in this case (`key = SHA1(seed)[:16]`,
`iv = SHA256(seed)[:16]`, `seed = asset_stem + "2"`, plus the zero-IV variant
`key = SHA1(asset_stem)[:16]`) unlocked **five seized APKs** in the companion
pendrive case — `RTO E CHALLAN (1)` (seed `UZrF0u2`), `PNB One` (seed
`ZoCv0N2`), `Repair service` (seed `LAZx0b2`),
`PNB ONE ACTIVATION`, `M PARIWAHAN CHALAN (12)` — decrypting to
byte-identical kits from one builder subscription. See
`docs/cases/pendrive-56-apks/CASE_STUDY.md` §3 and
`ARTIFACTS_SENSITIVE.md` §8 for the per-sample seeds.

---

*Prepared 2026-10-05. Source of truth: `thesis/06_unpacking_case_study.md`,
`rto_analysis/README.md`, `rto_analysis/ANALYSIS_REPORT.md`,
`rto_analysis/PHASE2..6_FINDINGS.md`, `rto_analysis/hole5_keypath.md`,
`rto_analysis/hole1_czrr_definitive.md`, `rto_analysis/stage3.md`,
`rto_analysis/validation_matrix.md`, `detections/*`, and the reference run in
`analysis/unpack_standalone/`. All file paths re-verified against the working
copy 2026-10-05; missing intermediates are marked **[not in this checkout]** in
§3.10.*
