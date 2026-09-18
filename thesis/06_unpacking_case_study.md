# 6. Case Study: Static Unpacking of a Custom Android Packer (RTO.apk / BeatBanker)

> Status: first draft (2026-09-12). Companion artifacts in `rto_analysis/`:
> `PHASE4_FINDINGS.md`, `PHASE5_FINDINGS.md`, `PHASE6_FINDINGS.md`, `ANALYSIS_REPORT.md`,
> `PIPELINE_PROBE.md`, `detections/`. All figures below are drawn from those committed findings.

## 6.1 Abstract

Custom Android packers increasingly defeat signature-based static analysis by keeping
the real payload and its strings encrypted on disk. We present a methodology for
recovering the payload, decryption keys, and string tables of such a packer **without
executing the sample** on a device or emulator. The approach combines (i) listing-level
symbolic evaluation of obfuscated native code that decompilers cannot process, (ii) a
JNI-function shimming oracle that answers "which JNI call is this?" at scale, and
(iii) PRNG-driven string-table reconstruction.

We validate the method end-to-end on `RTO.apk`, a live (2026) fake-e-challan banker
belonging to the public **BeatBanker / BTMOB** cluster. Static analysis recovered:
7,857 decrypted native strings (57.5% of the encrypted blob), a 3 KB decoy DEX
(remotely-loaded `InMemoryDexClassLoader` camouflage), the AES-128-CBC key
$K = \mathrm{SHA1}(\mathrm{"myg0N2"})[:16]$ used to decrypt the 7.8 MB `assets/myg0N`
container into an XMR-miner dropper kit, one **runtime-keyed** asset whose decryption
scheme was derived without its key, and 177 deobfuscated installer strings including
full C2/telemetry/Firebase infrastructure indicators. The recovered artifacts produced
8 YARA rules validated at zero false positives over a 540-file sweep.

The contribution is not a single new unpacker but a **reproducible hybrid blueprint**:
symbolic-evaluation + JNI-oracle + string-table decoding. To our knowledge no
open-source Android unpacker (nor the "run it in an emulator and dump" family) needs
to -- or is able to -- handle RTO's layered custom crypter without this combination.

## 6.2 The Threat Model: Why Static Unpacking Still Matters

Android malware increasingly ships as a small, legitimate-looking stub (a "host"
that installs cleanly and passes Google Play Protect) plus encrypted payload stages
that are decrypted in memory or onto disk at runtime.

Reasoning about such samples has three uncomfortable properties:

1. **Decompilers time out or OOM.** RTO's single native function is ~36,000
   instructions of control-flow-flattened code. Even 1 KB clamped chunks of it
   exceed Ghidra's decompiler budget (`rto_analysis/ANALYSIS_REPORT.md` §3).
2. **Dynamic execution is expensive and often blocked.** Emulators can be detected
   (`Build.CPU_ABI`, `SUPPORTED_ABIS`, `MANUFACTURER` checks were present in RTO);
   Frida/gum is frequently the operational target of anti-instrumentation.
3. **The artifact to share with the community must be evidence, not anecdotes.**
   A recovered key, a decrypted container, and a string table are verifiable claims.

Static unpacking therefore answers the question: *what can be recovered about an
encrypted payload without running it?* For RTO the answer was: nearly everything
except the runtime-keyed stage and the last layer of string obfuscation's live
regeneration.

## 6.3 Sample Overview

| Property | Value |
|---|---|
| Sample | `RTO.apk`, 8.1 MB |
| Stub | `classes.dex` → `System.loadLibrary("strangulation")` |
| Native | `libstrangulation.so` (338 KB, arm64), single flattened function `SUO4` @`0x110058` |
| Encrypted asset | `assets/myg0N` (7.8 MB, entropy 8.0) |
| Host shell | `dApp.binance.Trading.Signalt` (fake Binance branding) |
| Cluster | BeatBanker / BTMOB (FakeChallan family): fake MPVA e-challan phishing, XMR miner, silent install |

Ground truth was established independently (Phase 6): the decrypted blob is a full
dropper kit (miner ELF, phishing HTML kit harvesting MPIN/card/UPI, split-APK
installer, Pine hooking framework), attributed byte-for-byte to the public
BeatBanker cluster via Firebase project id, telemetry protocol, and miner binary
naming (`libmine-arm64.so`/`arm32`).

## 6.4 Methodology (Three Modules)

### M1 — Packing detection

Static signals: tiny stub DEX (<50 KB) + native libs + high-entropy asset (>7.5).
For RTO these tripped but were not consumed by the downstream verdict synthesizer
(`PIPELINE_PROBE.md` root cause #3) -- a pipeline defect fixed by design in M2:
unpacking decisions are driven by the label that *needs* decrypting, not by a binary
"packed?" boolean.

### M2 — Stage-2 DEX and key recovery via inline string decryption

**Observation.** RTO's native code decrypts strings inline, byte-by-byte, with a
uniform pattern that appears 8,000+ times:

```
adrp/add  xN, #page          ; base pointer
mov       wK, #imm           ; per-byte key material
ldrb      wB, [xN, #off]     ; cipher byte
eor       wD, wB, wK         ; decode
strb      wD, [xN, #off]     ; write plaintext in place
```

The control flow is so flat and straight-line that the *decompiler* fails, but each
byte is independent -- which is exactly what a **forward listing-level symbolic
evaluator** can exploit (`ghidra_scripts/DecryptStrings.java`).

**Post-pass.** A backward, frame-offset-aware memoized slicer (`SliceProbe.java`)
resolved the 642/7,857 misses (address-as-key `eor` operands, `movk` composition,
`sub/ldur` frame-slot indirection).

**Result.** 7,857 recovered bytes across `0x151000-0x154500` (57.5% coverage).
The blob at `0x151c60` decoded to a Base64 `dex\n038` DEX (`hidden.dex`, 3,328 B) --
a decoy accelerometer app loaded into `InMemoryDexClassLoader`, i.e. *the packer's own
camouflage*. The crypto block at `0x130xxx` yields the full key schedule for
`assets/myg0N`: key = `SHA1("myg0N2")[:16]`, IV = `SHA256("myg0N2")[:16]`, zero-IV
AES-128-CBC → 7.8 MB dropper kit (`phase4_payload/`).

$K$ was **not** brute-forced: the assembled `"myg0N2"` string defensively mutates via
an un-modelled `StringBuilder` call (`ANALYSIS_REPORT.md` §4), so pure
seed-sweeping (98 seeds × 3 KDFs, 857k suffix permutations) plausibly failed; the
JNI oracle (below) is what made this tractable.

### M3 — JNI shim: answer "which JNI call is this?" instead of building a JNIEnv

Rather than emulate the Android runtime, `EmulateJni2.java` maps the `.so` at
`0x100000`, allocates the stack, installs a fake `JNIEnv*` whose vtable entries trap
to logged stubs, and resolves every `CallObjectMethodA`/`NewStringUTF` site. The
oracle logs the exact method names and string `jstring` payloads in program order.
This recovered the runtime `StringBuilder.toString()` assembly of `"myg0N2"` and, on
siblings, the `RegisterNatives` table of the Ijiami packer's helper libs
(`scripts/ijiami_oracle.py`) -- proof the harness generalizes across packers.

### M3b — Stage-3 installer strings: PRNG-indexed CJK pool

The payload's installer strings are obfuscated via
`CZRR4ZREoGNpLeGZze.NkWaRdJEKEf58YYznc(long)`: a seeded 64-bit hash chain
(two 16-bit rotate/xor rounds; multiply-xorshift hash32) indexing one giant UTF-16
CJK string array (8,191 chars per row). The decoder was reimplemented in Python and
recovered **177 unique strings** including all infrastructure IOCs
(`phase2/installer_deobfuscated_strings.json`):
`aptabase.jesfeoqrj3.xyz:8443` (C2/telemetry), `pool.jesfeoqrj3.xyz:8443` (mining),
Firebase project `waking-21b04`, xmrig flags, FCM topics, and the `MESSAGE_TO_HACKER`
taunt.

**Open stage (documented here to avoid overclaiming).** Live regeneration of this
table from the raw pool is not yet reproducible *from committed artifacts*: the
ad-hoc Kali decoder (`/tmp/opencode/deobf.py`) and the raw pool/seed source were
never committed. The committed evidence (`installer_deobfuscated_strings.json`)
contains the *outputs*; the bytecode-replay step that re-derives the string indices
from the DEX remains the one unfinished module. Section 6.9 records the planned
experiment. This is the honest boundary of the case study.

## 6.5 Runtime-Keyed Assets: Deriving the Scheme Is Already the Win

The phishing kit asset `dataQpoJzkbmfX` (178 KB) is not decryptable with any static
key candidate ({assets, package names, Firebase creds, pool/C2 hosts, MAC bytes} ×
{SHA1[:16], SHA256[:16], SHA256[16:32], MD5} × {IV schemes}). Its scheme was still
derived statically: `proj.App.decryptStream` uses key `SHA1(asset_basename + "1")[:16]`,
but the *key material* is delivered at runtime (`SecureAssets.decryptFile` on the
downloaded file). We therefore documented the scheme and the expected key-hint
pattern -- the same pattern the live C2 deliver would trigger -- and confirmed via
the campaign's own 0-byte `miner.apk` placeholder that runtime delivery is the
intended loading path. Static analysis can bound the problem even when a key never
leaves the network.

## 6.6 Results Summary

| Module | Artifact | Count / detail |
|---|---|---|
| M2 - inline decrypt | `phase2/decrypted_strings.txt` (+`.bin`/`.missing`) | 7,857 B, 57.5% coverage |
| M2 - decoy recovery | `phase2/hidden.dex` | 3,328 B decoy (`dex\n038`) |
| M2 - container key | `myg0N` AES-128-CBC | $K=\mathrm{SHA1}("myg0N2")[:16]$, $IV=\mathrm{SHA256}("myg0N2")[:16]$ |
| M2 - primary payload | `phase4_payload/` | miner dropper kit (installer.dex, split APKs, configs) |
| M2 - runtime shell | `dataQpoJzkbmfX_decrypted.apk` | phishing kit (MPIN/card/UPI flow) |
| M3 - JNI oracle | `EmulateJni2.java` / `ijiami_oracle.py` | dual-arch, reusable across packers |
| M3b - installer strings | `installer_deobfuscated_strings.json` | 177 unique strings, 13 IOCs |
| Detection | `detections/beatbanker_rto.yar`, `iocs.json` | 8 YARA rules; 0 FP / 540 files |

**False positives:** YARA rules validated against 101 benign + 150 unrelated-malware
APKs → 0 hits (architecture-anchored, not string-anchored).

## 6.7 Attribution (Independent Ground Truth)

All claims were corroborated against independent public analysis of the same cluster
(Ostorlab's TV_V_23.apk writeup): Firebase project `waking-21b04`, App-Key format
`SH-*` / `A-SH-*`, miner filename scheme, `output8.mp3` foreground-keepalive, staged
APK architecture. This prevents the "recovered what we then assumed" circularity trap.

## 6.8 Novelty and Relation to Prior Work

Open-source Android unpacking is dominated by emulator/frida dumps (ARTist, FRIDA-DEXDump,
unpackers targeting specific commercial protectors -- Qihoo, Baidu, Tencent, Ijiami).
Two properties differentiate this work:

1. **No execution environment is assumed.** Recovery is done entirely on the binary
   plus a shim's fetch of method names. This is the "offline" region of the
   unpacking spectrum that BYOVD-style emulator dumps cannot reach.
2. **The JNI oracle is packer-agnostic.** The same harness that recovered RTO's
   `StringBuilder` string assembly also enumerated Ijiami's `RegisterNatives` and
   native-reflection helper exports. A new custom packer is a new set of string
   indexes and a new PRNG -- not a new emulator infra.

Known boundary: for the *runtime-keyed* stage, bootstrapping truth requires either
the delivered key or corrupted-key forensics (`MessagesException`-style partial
plaintext). We document this as framing for future work, not a solved problem.

## 6.9 Reproducibility Inventory

**Committing-side (this thesis repo):** all findings MDs, `ghidra_scripts/` +
`ghidra_scripts_linux/` (Ghidra + Python harness scripts), `phase2/` outputs
(`decrypted_strings.*`, `hidden.dex`, `installer_deobfuscated_strings.json`,
`jni_trace.txt`, `crypto_block_annotated.txt`), `detections/`.

**Evidential-side (kept out of the repo):** `phase4_payload/` decrypted artifacts,
the Kali reverse-engineering environment, and the specific hacks (NOP-patching
`dmb` pcodeops for the arm32 twin, Thumb misaligned-branch landmines).

**Open (next experiment -- bytecode replay):** re-derive the 177 installer string
seeds by running the stub's smali/alvik IR in a mini-VM (or `InMemoryDexClassLoader`
under Qiling), feeding `NkWaRdJEKEf58YYznc(long)` the set of `long` constants to
reconstruct the string table from the CJK pool. Success criterion: regenerate
`installer_deobfuscated_strings.json` byte-identically from `phase4_payload`
artifacts. See `thesis/07_families.md` forward pointer from this chapter.

## 6.10 Conclusion

On a live, layered, custom-crypter banker, offline recovery produced the primary
payload, its AES key, a decoy DEX, 7,857 inline strings, 177 obfuscated installer
strings, and 8 clean detection rules -- without running the sample. The method is
the thesis's second claim after Mal/Ben (§5): *signature-based static analysis works
when it can see code, and a hybrid of symbolic evaluation, a JNI oracle, and string
table decoding lets it see code that decompilers and dumpers cannot.*