# Packer handling & unpacking

DroidForensix detects and reverses packers **fully statically** — no emulator is
required for identification or master-key recovery. Packer coverage is
**data-driven**: add a marker line to `data/packer_markers.json` and detection
picks it up, no code change.

---

## Detection layers

1. **Structural / entropy** (`analysis/step10_binary_packing.py`, every pipeline run):
   oversized DEX sections, `.text` entropy > 7.0, DEX-in-DEX, missing `classes.dex`,
   oversized native libs, non-standard DEX names. Produces `obfuscation_score` +
   `packing_detected` and feeds the pipeline's `obfuscation_analysis`.
2. **Brand markers** (`data/packer_markers.json` + step 10): zip entry names and the
   first 256 KB of each DEX are scanned for known packer fingerprints. Step 10 now
   emits `packer_brands: [{"name", "markers"}]` alongside the structural verdict.
3. **Deep reversal** (`scripts/unpack.py` master-key dispatcher, `scripts/triage.py`
   heuristic bake-off): routes each APK to the correct recovery strategy and always
   returns either a self-validated payload or a typed E-code.

---

## Supported packer matrix

| Brand | Markers | Notes |
|-------|---------|-------|
| Bangcle/SecNeo | `com.secneo.apkwrapper`, `libsecexe.so`, `libsecmain.so`, `libdexhelper.so`, `classes.dex.bak` | Classic APK-wrapping protection |
| Ijiami | `com.stub.stubapp`, `libexecmain.so`, `ijiami.dat`, `ajm.dat` | Native oracle probing via `scripts/ijiami_oracle.py` |
| Tencent Legu | `com.tencent.stubshell`, `libshella-`, `libshellx-`, `mixz.dex` | Widely deployed shell |
| Qihoo 360 | `com.qihoo.util`, `libjiagu.so`, `libjiagu_art.so`, `libjiagu_x86.so`, `libprotectclass.so` | DEX + native protection |
| NQ Shield | `com.netqin.android.dopt`, `libnqshield.so` | |
| Wanpu (Wangsu) | `libkwsgmain.so`, `libkdp.so` | |
| Ali | `libmobisec.so`, `ali.protect` | Alibaba SecurityGuard |
| Baidu Enhancer | `libbaiduprotect.so`, `libbaiduprotect_x86.so`, `com.baidu.protect` | |
| DexProtector | `com.licel`, `org.licel` | License-based commercial protector |

Markers match case-insensitively against entry names (with `/` ≡ `.` for class paths)
and raw DEX bytes.

---

## Master-key dispatcher (`scripts/unpack.py`)

```
venv/bin/python scripts/unpack.py <apk> [--workdir DIR] [--out JSON]
```

Every run ends with exactly one of:

**Recovered** — self-validated payload artifacts (AES-CBC padding oracle + KDF/domain
chain validation) + `unpack_report.json`.

Or a **typed E-code**:

| Code | Meaning | Next step |
|------|---------|-----------|
| `E-JAVA-RUNTIME-DELIVERY` | Java-only injected trojan; payload fetched at runtime | IOC extraction instead of static recovery |
| `E-JAVA-NO-IOC` | Java-only sample, no loader/IOC patterns | Manual review |
| `E-NATIVE-NOENTRY` | Packer registers JNI at runtime, no `Java_*` export | `.init_array`/`JNI_OnLoad` emulation (`scripts/emulate.py`) |
| `E-HARDENED-VM` | Code-protected (bytecode VM): entries are ciphertext at rest | VM-level emulation / device hook (outside static oracle scope) |
| `E-NATIVE-NO-RECOVERY` | Oracle ran but produced no self-validating payload | Inspect `fault info` + `key_log` |
| `E-ORACLE-FAULT` | Oracle aborted with unhandled fault | Fault info attached; adjust emulation env |
| `E-JAVA-LAYER-HANDOFF` | Soft (statically decodable) shell runs clean but payload DEX is delivered via ART/Java (`dexElements`/`DexClassLoader`), not minted in native memory | Out of scope for the static native oracle; inspect stub-DEX `Application` (`TxAppEntry` → `MultiDex` wrapper) |

---

## Tencent Legu soft-shell boundary (recovery evidence)

Background: `libshell-*` JNI_OnLoad **is not** the DEX delivery path. Emulator
trace: `libshell-super.2019.so`/`libshella-*.so` make only `FindClass('')` calls
(zeroed names — anti-emulation probe, init bails early) and exit clean. The real
handoff runs in **Java**: stub `classes.dex` contains `com/tencent/StubShell/TxAppEntry`
(an `Application`) that drives a multi-dex wrapper (`Ldalvik/system/DexFile`,
`dalvik.system.BaseDexClassLoader`, `dexElementsField`, `MultiDexForMemoryDex`)
against the encrypted payload blob. This is a Java→Java flow inside ART, so the
static native oracle never sees the DEX.

Blob layout for `assets/0OO00l111l1l` (6.6 MB, 2 DEX regions — matches `u32 count=2`):

```
[9-byte sentinel] "dex\n\xff035\x00"   (identical at both region heads, offset 35 and 2361509)
[payload]         high-entropy (H≈7.96), not deflate, not repeating-XOR, not AES(ECB/CBC/CFB) with the
                  shipped o0oooOO0ooOo.dat keys
```

Exhausted static attacks (all negative): 256-byte substitution/permutation table
(rodata/data/text of `libshell-super.2019.so` and `assets/libshellx-super.2019.so`),
repeating-key XOR (autocorrelation falls to noise), raw/zlib inflate scan, AES with
the six 16-byte keys in `o0oooOO0ooOo.dat`. `libshell` exports only `JNI_OnLoad` and
imports `open`/`fread`/`inflate`/`dlopen`/`fopen` — the decrypt is a runtime native
function reached via "open secure data file" (log string adjacent to the blob name in
rodata), i.e. invoked from the Java `Application.attach` path, not JNI_OnLoad.

Conclusion: the table/key is **runtime-derived** (not in static data). Recovery of
the payload DEX is outside the static native oracle; classified `E-JAVA-LAYER-HANDOFF`.

---

## Corpus scan & tier-2 roster outcomes (SOP A3 / B5 — 22–23-Sep-2026)

Static scan (`scripts/find_soft_packers.py`; outputs `evaluation/soft_packers_found*.json`).
Rescanned 23-Sep-2026 after the dispatcher gap-closers: `sniff_family` now
routes **Wangsu / Ali / BaiduEnhancer / DexProtector** (aligned with
`data/packer_markers.json`); the 2 former `SecShell/Baidu` samples are
libbaiduprotect-based and relabel **BaiduEnhancer** (still H2); no Wangsu/Ali/
DexProtector APKs exist in this corpus; the 11 scan-error identities are now
persisted in the output's `errors[]` (7 "not a zip file", 4 "corrupt extra
field"; previously dropped, only derivable as total minus classified).

| Corpus | APKs scanned | Family-classified | Verdicts |
|--------|--------------|-------------------|----------|
| malware | 647 | 33 (+11 scan errors, identities in `errors[]`) | HARD 16, MIXED 14, SOFT 2, NONE 1 |
| goodware | 115 | 3 | SOFT 1, HARD 2 |
| legitimate | 100 | 0 | — |

Malware by family: 360Jiagu 21 (H11/M10), TencentLegu 5 (S2/M3), Bangcle 4
(H2/M1/N1), BaiduEnhancer 2 (H2), Ijiami 1 (H1). Unique SOFT = 2 (TencentLegu:
one malware + one packed benign app; `samples/malware/unknown_0001257e…` is a
duplicate copy of the androzoo sample).

Tier-2 oracle roster (`evaluation/oracle_out/summary.json`): 7 unique samples,
**0 RECOVERED — every run a typed E-code**:

| Scan verdict | Family | Outcome | Time |
|---|---|---|---|
| SOFT | TencentLegu (malware) | E-NATIVE-NO-RECOVERY | 2.7 s |
| SOFT | TencentLegu (goodware control) | E-NATIVE-NO-RECOVERY | 4.0 s |
| HARD | 360Jiagu | E-HARDENED-VM | 2.2 s |
| HARD | Ijiami | E-HARDENED-VM | 2.1 s |
| MIXED | 360Jiagu | E-HARDENED-VM | 1.8 s |
| MIXED | Bangcle/SecNeo | E-NATIVE-NO-RECOVERY | 2.6 s |
| MIXED | TencentLegu | E-NATIVE-NO-RECOVERY | 302.9 s |

Notes: the hardened gate short-circuits HARD/MIXED-hardened samples in ~2 s
(no emulator minutes burned). The SOFT Legu samples carry `libshella-2.10.7.1`
whose JNI_OnLoad clean-exits (Java-layer handoff above). On 22-Sep no handoff
detection existed in code, so they landed `E-NATIVE-NO-RECOVERY`; the
refinement **implemented 23-Sep-2026** now emits `E-JAVA-LAYER-HANDOFF` when
the Legu stub `classes.dex` carries the delivery signature (`TxAppEntry`, or
`DexFile` + `DexClassLoader`/`dexElements`) — verified present in both SOFT
corpus samples (`libshella-2.10.7.1` and `4.1.0.23`). The roster rows above
remain the historical 22-Sep outcomes. Roster ran 8 times / 7 unique
(duplicate corpus copy + within-batch dedupe miss in the throwaway runner
script).

---

## Adding a new packer (no code change)

1. Append to `data/packer_markers.json` → `brands`:
   ```json
   {"name": "MyPacker", "markers": ["com.mypacker.core", "libmypacker.so"]}
   ```
2. Markers should be substrings that appear in zip entry names **or** as dotted
   string constants inside DEX bytes (the most reliable pickup).
3. Add a row to the matrix above and a regression case in `tests/test_step10_packer.py`.
4. Run `python -m pytest tests/test_step10_packer.py -v`.

Schema is enforced by `test_marker_file_schema`: every brand needs a non-empty `name`
and a non-empty list of non-empty string `markers`.

---

## Case study

RTO / BeatBanker (thesis): `stage3_replay.py` ports the Stage-3 smali bytecode
(CZRR/seed pool → LMK/NkWa rotate-multiply digest) to regenerate installer strings
from `cjk_pool.txt`; acceptance test `tests/test_stage3_replay.py`. Full narrative:
`thesis/06_unpacking_case_study.md` + `rto_analysis/`.