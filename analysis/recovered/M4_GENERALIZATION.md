# M4 Generalization — Multi-Family Attempt (2026-08-27)

**Goal (plan):** unpack ≥1 more family (Ijiami/Bangcle/360Jiagu), else document E-codes.

## Corpus sweep (triage verdicts on flagged suspects)

| sample | verdict | payload candidate | solibs |
|---|---|---|---|
| 0000237117863e53 | packed_known(Bangcle/SecNeo) | assets/bangcle_classes.jar (1.8 MB) | 6 |
| 0000d3e05cfad4c3 | packed_known(Bangcle/SecNeo) | assets/Main.swf | 8 |
| 000091f2fac1083d | packed_known(Bangcle/SecNeo) | — | 4 |
| 0000a053de676b4d | packed_known(Ijiami) | — | 8 |
| 0000a6d452d58424 | packed_known(360Jiagu) | 2 weak candidates | 3 |
| 000027d1da96332e | **packed_custom** | — | 4 |

## Attempt 1 — Bangcle/SecNeo (`0000237117863e53`)

Structure: `bangcle_classes.jar` (encrypted DEX bundle) + `libsecexe/libsecmain/libsecpreload`
(arm + x86 pairs). Dissection shows **zero exported `Java_*` symbols**.

Oracle run on `libsecexe.so` (arm):
```
RuntimeError: no Java_* export found
```

**E-BANGCLE-NOENTRY** — Bangcle registers JNI at runtime via RegisterNatives;
the oracle's entry discovery only supports statically exported symbols.
*Fix path:* emulate `.init_array` constructors, capture `GetEnv`+`RegisterNatives`
through the mocked vtable, then drive the registered method id directly.

Same root cause applies to: 0000d3e0, 000091f2 (Bangcle variants), and by
construction Ijiami (`libexecmain`) + 360Jiagu (`libjiagu`) loaders, which are
also RegisterNatives-only families. → **E-IJIAMI-NOENTRY**, **E-360JIAGU-NOENTRY**
(documented by family-construction evidence; not individually run).

## Attempt 2 — custom "door_frame / shunpay" packer (`000027d1da96332e`)

Two arm libs carry **static exports** (oracle-compatible):

- `libdnlocal.so`: `Java_com_door_frame_utils_CmmUtils_getSystemRawVar`,
  `Java_com_door_pay_plugin_common_util_DnUtils_stringFromJNI`
- `libshunpay.so`: payment adapter (not packer-relevant)

Runs (after fixing `UC_ARM_REG_R3` import bug in emulate.py):

| entry | status |
|---|---|
| `getSystemRawVar` | `abort` — native sanity check fails inside mock (likely `__system_property_get` or file-path probe unmet) |
| `stringFromJNI` | `UC_ERR_WRITE_UNMAPPED` — **3-arg JNI entries receive uninitialized R2** (`find_entry` seeds only R0/R1) |

**E-ARM32-ENVARGS** — arm32 entry prologue must parse the JNI signature and
seed up to R3 with valid fake Java objects (string/array heap objects), else
third-argument dereferences hit unmapped memory.
*Fix path:* signature-driven arg seeding reusing `new_array`/`make_string`.

## Result

- Family **detection** generalizes (5/6 suspects flagged with correct family).
- Family **unpacking** does not yet: documented E-codes
  E-BANGCLE-NOENTRY, E-IJIAMI-NOENTRY, E-360JIAGU-NOENTRY, E-ARM32-ENVARGS.
- Tooling improvements landed en route: arm32 R3 const import fix,
  `JNI_DEBUG`-gated instrumentation (`_dbg`) for digest/copyOf/ctor/heap-scan.

M4 status: **partial — documented E-codes** per plan's alternative clause.
