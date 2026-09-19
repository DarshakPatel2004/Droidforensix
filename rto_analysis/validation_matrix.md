# Validation Matrix — `unpacking_tool.py`

Reproduced with `rto_analysis/unpacking_tool.py` on this machine (Windows,
Python 3.13, venv `.venv`, unicorn 2.1.4 / lief 1.0.0). Date: 2026-09-19.
Runs complete in 1–3 s per sample thanks to the fully static pipeline.

## Summary

| sample | packer (triage verdict @ conf) | route | tool verdict | ecode | so_count | exit |
|---|---|---|---|---|---|---|
| `RTO.apk` | `packed_custom` @ 0.85 | NATIVE | **RECOVERED** | — | 2 | 0 |
| `Calculator.apk` (Ijiami #1) | `packed_known(Ijiami)` @ 0.95 | NATIVE | FAILED | E-NATIVE-NO-RECOVERY | 22 | 1 |
| `Calculator(1).apk` (Ijiami #2) | `packed_known(Ijiami)` @ 0.95 | NATIVE | FAILED | E-NATIVE-NOENTRY | 14 | 1 |
| `Calculator(2).apk` (Ijiami #3) | `packed_known(Ijiami)` @ 0.95 | NATIVE | FAILED | E-NATIVE-NO-RECOVERY | 22 | 1 |
| `0000237117…dc28.apk` | `packed_known(Bangcle/SecNeo)` @ 0.95 | NATIVE | FAILED | E-NATIVE-NOENTRY | 6 | 1 |
| `000027d1…e7ee.apk` (hole-2, Java-XOR) | `packed_custom` @ 0.45 | NATIVE | FAILED | E-NATIVE-NO-RECOVERY | 4 | 1 |
| `0000d3e05…f037b.apk` | `packed_known(Bangcle/SecNeo)` @ 0.95 | NATIVE | FAILED | E-NATIVE-NOENTRY | 8 | 1 |

## Reference run — RTO.apk (full recovery)

```
$ python rto_analysis/unpacking_tool.py --input RTO.apk --output analysis/unpack_standalone --stage3 --bundle

verdict     : RECOVERED
route       : NATIVE  (native libs: 2)
triage      : packed_custom @ conf 0.85
artifact    : ...\artifacts\kit.zip          # 7.8 MB decrypted dropper kit, 10 entries
kdf         : seed=myg0N2 key=6eada2ac127d60e3c17e4940981c5bc6 iv=d0045d33d393892263a7b43ccac6e578
ioc firebase: mp2026-1efb5-default-rtdb.firebaseio.com
ioc api_key : AIzaSyAD6KONlZNbRpGvMKgxlpBnLmrdT7gNUic
stage3      : matches=175 mismatches=5 over 180 seeds
elapsed     : 1.3s
```

Outputs written: `analysis/unpack_standalone/{summary.json, stage2_report.json,
strings.json, strings.tsv, artifacts/kit.zip, artifacts/recovery_keys.json}`
plus `analysis/ARTIFACTS.zip` (bundle).

## Reproduce the non-recovered rows

```
python rto_analysis/unpacking_tool.py --input <APK> --output <dir>
```

## Interpretation

1. **Detection stage is correct on every packed sample.** All six non-RTO
   samples trip `packed_known` at conf 0.95 (Ijiami x3, Bangcle/SecNeo x2) or
   `packed_custom` (hole-2 Java-XOR sample), matching the committed triage
   locklist and the earlier A/B control run.
2. **RECOVERED is claimed only with self-validated artifacts.** RTO's kit
   passes the strict ZIP validity gate (`testzip()` + EOCD) and its AES key is
   independently verifiable (`SHA1("myg0N2")[:16]`).
3. **E-codes are the honest contract.** Ijiami and Bangcle packers register
   natives at runtime (no `Java_*` export), so the oracle correctly reports
   `E-NATIVE-NOENTRY` / `E-NATIVE-NO-RECOVERY` instead of a fabricated payload.
   The next step for these families is `.init_array`/`JNI_OnLoad` emulation —
   a working JavaVM-table mock already exists at `scripts/ijiami_oracle.py`.
4. **hole-2 sample decrypts in Java, not native code** (XOR keyed by the last
   32 bytes of its asset); it is out of scope for the native oracle. Its full
   manual route is documented in `rto_analysis/hole2_payload_deepdive.md` and
   `_apk2/`.

The tool therefore validates both halves of the claim: it recovers what it can
theoretically recover, and it says precisely *why* when it cannot.