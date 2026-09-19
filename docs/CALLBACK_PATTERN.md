# DEX acquisition callbacks (`scripts/emulate.py`)

Native packers (Ijiami, Bangcle, Tencent Legu, Qihoo 360, …) wrap a real DEX
inside assets or native buffers and hand it to ART only at runtime. Static
extraction fails; the unpacker must **emulate the loader enough to observe the
DEX at the moment the sample calls ART's JNI interfaces** (`DefineClass`,
`RegisterNatives`, …). That observation point is the *DEX acquisition
callback*.

---

## Where the DEX appears

| Interface | Purpose | Where we capture it |
|-----------|---------|---------------------|
| `DefineClass` | ArtMethod receives a raw `const char*` DEX buffer | `self.defined_classes[addr] = bytes` |
| `RegisterNatives` | Methods for a DEX-defined class | `capture_register_natives()` parses JNINativeMethod array |
| `FindClass` / `LoadClass` | Class already registered by name | no DEX bytes, only name |
| `.data` / heap blob | raw `dex\n` magic left in memory | `sweep_blobs()` base64 + magic scans |

Packers that decrypt a DEX on the heap and pass it to `DefineClass` are solved
by the `DefineClass` hook alone. Packers that hit the JNI vtable with a
**buffer callback** (e.g. custom `loadDEso`) need the InMemoryDexClassLoader
pattern instead — see [PACKERS.md](PACKERS.md).

---

## Entry discovery, two tiers

`find_entry()` (emulate.py) picks the emulation bootstrap point:

1. `Java_*` export — the normal JNI entry (preferred; unchanged RTO path).
2. No `Java_*` → **`JNI_OnLoad` fallback** (JIAMI sprint). Signature-compatible
   libs (libexec.so) boot via `JNI_OnLoad`; pure VMP/encrypted exports stay out
   of reach and report `E-NATIVE-NOENTRY`.

The fallback is covered in `tests/test_emulate_ijiami.py`.

---

## The JNI_OnLoad boot sequence

```python
report = emulator.run_jni_oneshot()
```

1. Map LOAD segments (PIE-aware, arch-aware: x86_64 / ARM32 Thumb / ARM64).
2. Build the VM dispatch table + `GetEnv` vtable (`build_vm_table`,
   `vm_hook`) so `JNI_OnLoad`'s `GetEnv(&vm, JNI_VERSION_1_6)` handshake
   succeeds.
3. Run constructors first (`run_ctors`): `DT_INIT` then `.init_array`
   (arch-aware; arm32 relocs applied via `apply_relative_relocs`).
4. Call `JNI_OnLoad`: `arg0 = JavaVM*`, `arg1` reserved; interpose
   `DefineClass`/`RegisterNatives`/`FindClass` on the JNIE Jvtable.
5. Sweep `.data` + heap + objects for `dex\n` magic; return a report dict.

Emulation is **signal-driven**, not complete: enough of libc/JNI is mocked for
the loader to run hot; anything deeper faults and is logged in the report.

---

## The callback API (unified contract)

```python
report = emulator.run_jni_oneshot(sym="JNI_OnLoad",
                                  ctor_timeout_s=120,
                                  run_timeout_s=300)
```

`report` keys:

| Key | Type | Meaning |
|-----|------|---------|
| `entry` | str | name of the entry actually run |
| `entry_addr` | int | based address |
| `arch` | str | `arm64` / `arm` / `x86_64` |
| `status` | str | `recovered` / `clean` / enum of `E-*` faults |
| `fault` | dict | fault info when status `!= recovered/clean` |
| `defined_classes` | dict | addr → captured DEX bytes |
| `blobs` | list | decoded DEX artifacts from sweeps |
| `native_methods` | list | RegisterNatives captures |
| `jni_calls` | list[trace] | interposed JNI calls in order |
| `ctors_run` | int | constructor count executed |
| `last_pcs` | list[int] | recent PCs on hard fault (for triage) |

---

## Adding a packer callback

1. Identify the ART call the packer uses to deliver its DEX
   (`DefineClass` covers most; add a new interposer for others).
2. Ensure the packer's export is discoverable: `Java_*` or `JNI_OnLoad`
   (add new names to `find_entry` fallback list with a test).
3. Extend `sweep_blobs` if the DEX is stored non-`dex\n` (e.g. stored at
   offset, XOR'd — mirror Ijiami's `indl01` container handling).
4. Add a regression test in `tests/test_emulate_ijiami.py` using the
   fake-binary contract (`_make_emulator`), never booting Unicorn in CI.

---

## Hardened Ijiami (Calculator.apk) result

Three Calculator APKs are an identical hardened Ijiami build:

- `libexec.so` exports `JNI_OnLoad` but its **text is encrypted at rest**
  (entropy ~5.75; `disassemble()` yields nothing), so the boot completes with
  0 JNI calls and the real DEX is never assembled in-process.
- `libexecmain.so` exposes `ijiami` (4-byte zero stub in an unmapped VA gap)
  and `getOpCode` (also un-disassemblable); no `JNI_OnLoad`.
- `libijm-emulator.so` exports `JNI_OnLoad` (1600 B, entropy ~6.7) but **hangs**
  under emulation — it expects the ART runtime's InMemoryDexClassLoader
  machinery.
- The wrapped DEX lives in `assets/ijiami.ajm` (magic `indl01`, ~3.7 MB) with
  companion `assets/ijiami.dat` (~8 MB) + `assets/IJMDal.Data`.

This is a *bytecode-protected* (VMP-style) packer; recovery requires driving
`libijm-emulator.so` with a real InMemoryDexClassLoader shim, not `JNI_OnLoad`
bootstrapping. Status: **blocked on sample family** — no soft Ijiami variant or
Bangcle sample exists on disk to pivot the demo.