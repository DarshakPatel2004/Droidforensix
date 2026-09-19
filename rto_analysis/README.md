# Defeating Android Packer Obfuscation: Stage-2 DEX Recovery via JNI Emulation Oracles

> Standalone technical report for a release-ready tool. The complete case study
> with every decision, dead end, and A/B control lives in the thesis chapter
> `thesis/06_unpacking_case_study.md`; this document is self-contained and can
> be read without the thesis. Code: `rto_analysis/unpacking_tool.py`.

---

## 1. What this is

`unpacking_tool.py` recovers the real (stage-2) DEX and embedded payload kit
from a **packed Android APK** without a device, an emulator, or a kernel VM.
Instead, it emulates the packer's own native decoder with **Unicorn** and a
mocked JNI environment, so the sample effectively unpacks itself into a
controlled process where every JNI call and every decrypted blob can be
observed.

The reference target — `RTO.apk`, a live BeatBanker/BTMOB fake e-challan
banker (8.1 MB, 2026) — is unpacked end-to-end: the encrypted 7.8 MB dropper
container is decrypted to a 10-entry kit (miner, phishing kit, split APKs,
hook framework), the AES key is recovered, and 177 unique installer strings
are regenerated from the packer's own PRNG.

## 2. Motivations and threat model

**Problem.** Packed Android malware hides its logic: the on-disk `classes.dex`
is a stub, the real payload is encrypted and rebuilt in memory by a native
unpacker at runtime. Static analysis sees only the stub; classic dynamic
analysis needs to actually run the app, which requires an Android device or
emulator, a working runtime hook, and careful containment of the malware.

**Threat model.** The attacker controls the APK and its native libraries and
can use arbitrary packing. The analyst controls only a Python process and a
copy of the APK. We assume no hardware virtualization, no device, and no
fires off of the analysis machine.

**Positioning.** The contribution is the *hybrid static blueprint*, not a
universal unpacker:

1. listing-level symbolic evaluation for embedded string tables,
2. a JNI *emulation oracle* that drives the packer's own decoder and records
   key material and decrypted blobs,
3. bytecode *replay* of the packer's PRNG to regenerate strings without any
   runtime at all.

"Natives only" is a deliberate boundary: the oracle operates at the JNI layer,
so we do not claim coverage of Java-only unpackers (one such case is
documented and answered honestly by a typed E-code).

## 3. Pipeline: four stages

### 3.1 M1 — structural packer triage (`scripts/triage.py`)

No signature matching: six structural heuristics over the APK.

| heuristic | signal |
|---|---|
| H1 | payload:dex size ratio (suppressed for legit engines) |
| H2 | entropy of `assets/` blobs |
| H3 | native app-class loading |
| H4 | JNI export shape |
| H5 | known packer marker files (`data/packer_markers.json`, 9 brands) |
| H6 | native import profile |

Output is a typed verdict: `clean_static` / `packed_custom` / `packed_known(<brand>)` /
`indeterminate`, with a confidence score and the payload candidates. On RTO.apk:
`packed_custom @ 0.85`. On six external packed samples: all detected
(`Ijiami` 0.95, `Bangcle/SecNeo` 0.95, `packed_custom`), 0 false
negatives — see `validation_matrix.md`.

### 3.2 M2 — listing-level string recovery (Ghidra `DecryptStrings.java`)

The native decoder (`libstrangulation.so`) builds its strings by `sub`/`xor`
with constant tables. A Ghidra script walks the listing's data-flow for the
relevant instruction shapes and resolves **427 embedded strings (~7.9 KB of
plaintext, 57.5% of the table)** before anything is executed. This is the
"surgical slice" that makes later stages cheap.

### 3.3 M3 — the JNI emulation oracle (`scripts/unpack.py` + `scripts/emulate.py`)

The core:

- **Loader:** LIEF parses the ELF (x86_64, ARM32-Thumb, ARM64); a bump
  allocator brings `.text`/`.data` into Unicorn with a sane stack and GOT
  shims.
- **JNIEnv mock:** a 233-slot vtable proxies the JNI API. Every call logs into
  `jni_log` (method, args) and — crucially — **StringBuilder assembly is
  replayed in Python**, so a key built from concatenated fragments is observed
  as plaintext. `getBytes`/`digest` inputs feed the key log that seeds the KDF
  stage.
- **Capture:** any blob the decoder writes (raw DEX, base64 DEX) is swept from
  memory and validated (`dex\n` magic + structural gate) before being
  reported.
- **Gates discovered by fuzzing the target:** `SharedPreferences.getBoolean("v")`
  must return `true` (else only the decoy DEX runs), `currentTimeMillis()` must
  advance, and JNI value args are 8-byte slots. These are part of the oracle
  contract, not heuristics.

**KDF fallback (myg0N-style, what actually cracked RTO).** When the oracle
faults before a clean sweep, the key log plus the packer's naming convention
(`<asset-stem>bootstrap.dex` → substring → `+ "2"`) supplies a seed space. The
tool enumerates every substring candidate, derives `KEY = SHA1(seed)[:16]`,
`IV = SHA256(seed)[:16]`, and uses an AES-CBC PK-magic oracle on the container
prefix. For RTO this nails `seed = "myg0N2"`:

```
KEY = SHA1("myg0N2")[:16]   (hex redacted — key recovered; see ARTIFACTS_SENSITIVE.md)
IV  = SHA256("myg0N2")[:16] (hex redacted)
```

Decrypting `assets/myg0N` (7,714,912 B) yields a 10-entry ZIP kit that passes
the strict validity gate. Recovered kit and key material land in the tool's
artifacts directory.

### 3.4 M3b — PRNG installer-string replay (`stage3_replay.py`)

The installer (stage-3 DEX) derives display strings from a seed with a
low-level PRNG: a 64-bit mul-long xorshift (constant `-0x34DB2F5A3773CA4D`)
over a single 4,320-character CJK pool. Front-smali is replayed **byte-for-byte
in Python** with no emulator. Acceptance bar: `175/180` seeds regenerate the
recorded fixture byte-identically; the 5 residuals are documented
ground-truth artifacts (verified in `tests/test_stage3_replay.py`).

## 4. The standalone tool

```
python rto_analysis/unpacking_tool.py --input RTO.apk --output recovered/ [--stage3] [--bundle] [--timeout SEC]
```

| flag | meaning |
|---|---|
| `--input` | packed APK (required) |
| `--output` | output directory (default `./recovered`) |
| `--stage3` | run PRNG installer-string replay when the recovered kit is myg0N-family |
| `--bundle` | also write an `STEM.zip` of deliverable outputs |
| `--timeout` | stage-2 pipeline budget in seconds (default 480) |

**Outputs:** `artifacts/kit.zip`, `artifacts/recovery_keys.json`,
`strings.json`/`strings.tsv`, `stage2_report.json`, `summary.json`.

**Typed verdicts.** A run always ends in `RECOVERED` (self-validated
artifacts) or a structured E-code:

| ecode | meaning | next step |
|---|---|---|
| `E-JAVA-NO-IOC` | Java-only, no loader/IOC patterns | none |
| `E-JAVA-RUNTIME-DELIVERY` | payload fetched at runtime | IOC collection only |
| `E-NATIVE-NOENTRY` | packer registers natives at runtime, no `Java_*` export | `.init_array` / `JNI_OnLoad` emulation (`scripts/ijiami_oracle.py`) |
| `E-NATIVE-NO-RECOVERY` | oracle ran, produced nothing self-validating | inspect key log / KDF |
| `E-ORACLE-FAULT` | emulation aborted | fault info attached |

**Exit codes:** `0` = recovered (or no native packer), `1` = typed E-code
failure, `2` = usage error.

## 5. Validation

Reference run (`validation_matrix.md`): RTO.apk recovered in 1.3 s — kit,
keys, Firebase project + API key (IOCs redacted — see
`docs/cases/pendrive-56-apks/ARTIFACTS_SENSITIVE.md`), and stage-3 strings at
the 175/5 bar. Six additional packed samples (Ijiami x3,
Bangcle/SecNeo x2, custom/Java-XOR x1) are all detected correctly and fail with
the *right* E-code rather than a fabricated payload. The YARA rules produced
for the family score **0 false positives over 540 files**.

## 6. Dependencies and environment

Python ≥ 3.10. `requirements.txt`/`requirements-lock.txt`, now including the
runtimes the oracle needs: `unicorn==2.1.4`, `lief==1.0.0` (plus the pinned
`capstone`, `pycryptodome`, `androguard`). Tested on Windows and Kali (the
Kali-side artifacts referenced in the deep dives — `/tmp` paths, Ghidra
projects — are superseded by this tool's relative-path, subprocess-based
design). Tests: `tests/test_unpacking_tool.py`, `tests/test_stage3_replay.py`.

## 7. Honest boundaries

- **Not a universal unpacker.** The full chain generalizes via the oracle and
  KDF blueprint; it recovers any sample whose packer exposes a decrypting
  native entry under the mocked JNIEnv. Ijiami/Bangcle-style runtime
  registration requires the JNI_OnLoad oracle that is scoped but not yet wired
  in.
- **Java-only unpackers are out of scope** (M3 is JNI-layer by design).
- **Replay fidelity is per-fixture.** The stage-3 replay reproduces the
  myg0N-family string table; another family needs its own smali port.

## References within this repo

- `thesis/06_unpacking_case_study.md` — full case study (M0–M4, A/B controls).
- `rto_analysis/stage3.md` — replay algorithm spec + acceptance test.
- `rto_analysis/hole1_czrr_definitive.md` — smali semantics, 5-artifact table.
- `rto_analysis/hole2_payload_deepdive.md`, `hole2_generalization.md`,
  `hole5_keypath.md`, `M4_GENERALIZATION.md` — generalization evidence.
- `rto_analysis/PHASE4_FINDINGS.md` / `PHASE5_FINDINGS.md` /
  `PHASE6_FINDINGS.md` — raw evidence for the oracle and KDF stages.
- `analysis/recovered/myg0N_payload/` — the recovered kit.
- `rto_analysis/detections/` — `beatbanker_rto.yar` (8 rules), IOCs.
- `rto_analysis/validation_matrix.md` — this tool's validation run book.