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
| `E-NATIVE-NO-RECOVERY` | Oracle ran but produced no self-validating payload | Inspect `fault info` + `key_log` |
| `E-ORACLE-FAULT` | Oracle aborted with unhandled fault | Fault info attached; adjust emulation env |

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