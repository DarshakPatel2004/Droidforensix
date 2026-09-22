# Phase 1 gate report: `libijm-emulator.so` ART call-graph RE

**Date:** 2026-09-19 (session log)
**Sample:** Calculator.apk hardened Ijiami — `libijm-emulator.so` (arm64 + arm32 ABI)
**Gate question:** *Is Path B (Qiling/Unicorn + ART stubs) worth finishing?*

---

## Verdict: **NO-GO as scoped** — there is no static ART call graph to reverse.

The premise of Path B is: *reverse the ART call sequence (`DexFile::Open`,
`ClassLinker::*`), then stub just enough of it.* That premise failed phase 1.

---

## Evidence

### 1. `JNI_OnLoad` is ciphertext at rest (both ABIs)

| ABI | JNI_OnLoad | decode density @ +0x400 | entropy (first 0x80) |
|-----|-----------|-------------------------|----------------------|
| arm64 | `0xc5c0` | **0/256 (0.0%)** | 6.13 |
| arm32 (armed1) | `0x633d` | **13/512 (2.5%)** | 6.13 |

The bytes at the export don't disassemble as Thumb/ARM64 and sit at high
entropy — i.e. the exported symbol points into an encrypted/bytecode blob, not
into code. This matches the prior session's observation that emulating
`JNI_OnLoad` produced 0 JNI calls and a stuck PC re-fetching ciphertext.

### 2. Not even the constructors are code

arm32 `.init_array` (9 entries, `0x25920`, size 36):
- `init[0] -> 0x67a9` — garbage decode (`itett lt; ldrblt ...`)
- `init[2] -> 0xb695`, `init[4] -> 0x131f9` — **no instructions decode**
- `init[8] -> 0x0` — null pointer

So the whole code payload (imports, ctors, entry) is encrypted; there is no
pre-decryption stage that runs on-disk.

### 3. Imports tell the story: dynamic-only ART resolution

Imports (arm64, 55 total): `dlsym`, `dlopen`, `dl_iterate_phdr`,
`pthread_*`, `malloc/free/realloc/mem*`, file I/O (`open/read/lseek/mmap/...`),
`__system_property_get`.

- **Zero** `DexFile::*`, `ClassLinker::*`, `JNI_*` imported symbols in the ELF
  dynamic table.
- **Zero** plaintext ART strings in image — the only tail strings are
  XOR-obfuscated (`,${deo`, `~imxi`, `|m(im0e,` at file tail).
- **Zero** `bl → dlsym-GOT` call sites found by static scan, because the code
  that performs those calls is itself encrypted.

### 4. Only real "code island" that survives decode is a tiny interpreter

arm64 image (135 KB): sliding-window density finds real code ONLY at the tail:

```
0x20500–0x20d00  (2 KB)   bit/LEB128 decoder loop
0x20d00–0x21200  (1.3 KB) symbol-value patch stub (writes off / post-reloc fix)
```

The 0x20500 island reads a byte stream bit-by-bit (`and w7, w5, #0x7f; lsl w5,
#1; cbnz...`) — a variable-length decode loop. That is the **bytecode/opcode
interpreter** of a code-protector, not an ART-facing loader. Everything else in
the image (including all 0x0..0x20500 below it) is `udf` fill/`ciphertext`.

arm32 has a larger readable swath (0x0–0x5800, ~24 KB) but its `.init_array`
and `JNI_OnLoad` still point into ciphertext, and its readable region contains
no `bl → dlsym` either.

---

## Conclusion + consequence

**Hardened Ijiami is protected in two layers we can't cross with static RE:**

1. **Code-layer encryption** — `JNI_OnLoad`/`.init_array`/payload = ciphertext
   at rest, decrypted only *inside* the 0x20500 interpreter at runtime. There
   is no ART call graph in the file today.
2. **ART-layer indirection** — even post-decrypt, ART functions are resolved
   via `dlsym(fn_name)` where `fn_name` themselves are XOR-encrypted.

Path B as originally scoped assumed we could *read* which ART funcs are called
and stub them. We can't — step 0 is "defeat the code decryptor", which is a
full custom-unpack of a bytecode VM (`libijm-emulator` **is** the emulator; the
DEX synthesis bytecode runs on it). That's the T5/"mini-ART emulation" effort
already flagged, not a 2-week stub-build.

### Options forward (recommendation order)

- **A (pragmatic):** Pivot the extension work to soft packers (Bangcle,
  TencentLegu, non-hardened Ijiami) where `JNI_OnLoad` IS readable ARM code and
  the stubs/oneshot framework applies as-is. Keep hardened Ijiami documented
  as `E-HARDENED-VM` (new E-code), with this report as the blocker proof.
- **B (research-y):** Attack the 0x20500 interpreter to extract its bytecode +
  XOR key, decrypt the real `JNI_OnLoad`, then resume Path B. Weeks, uncertain.
- **C:** Frida-on-device (ArtMethod interception) — ruled out earlier (no
  device-level hooks).

## Artifacts
- `analysis/emulate/calc_ijiami/re_verdict.py` — decode-density gate scan
- `analysis/emulate/calc_ijiami/re_islands.py` — code island locator
- `analysis/emulate/calc_ijiami/re_art_calls.py` — dlsym call-site scan
- `analysis/emulate/calc_ijiami/re_initarray.py` — ctor decode