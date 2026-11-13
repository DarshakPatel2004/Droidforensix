# Full Knowledge Transfer — DroidForensix Static Unpacking Oracle
**Date:** 2026-08-28 | **Branch:** `publish/forensics` → `main` | **Status:** Happy path proven, edge cases documented as E-codes

> This is the document that stops blind shots. The Master Key Strategy told you *what* to do. This tells you *why*, *when not to*, and *what to do when it breaks*.

---

## 1. Why blind shots happen

| Blind shot | Root cause |
|---|---|
| Retrying Waydroid / spinning up emulators for days | Guide didn't say *when to stop* fighting VMs |
| Brute-forcing with wrong KDF (sha256 vs sha1) | Guide removed live C2 values for safety; people guess engines |
| Validating only PK magic | Fake ZIP flags `0x2769` make first-block checks fail even with the right key |
| Treating `indeterminate` / `packed_custom` as "not malware" | H1-H6 detect *packing*, not malice. Repacked trojans often score indeterminate |
| Running oracle on `so_count: 0` samples and getting nowhere | Guide originally had no Java branch |
| Trusting mock outputs verbatim | Mocks lie on `substring` args, engine names, `copyOf` lengths |
| Expecting Telegram tokens in every sample | Modern kits use Firebase RTDB, not Telegram, as primary C2 |
| Harvesting victim data from live C2 | Evidence-chain mistake |

Every row below exists because we fired that shot ourselves.

---

## 2. System overview (30-second map)

```
scripts/triage.py      → H1-H6 heuristics, verdict: clean_static / packed_known(*) / packed_custom
scripts/dissect.py     → native libs, Java_* exports, crypto hints (LIEF+capstone)
scripts/emulate.py     → Unicorn oracle: fake libc GOT + 233-slot JNIEnv vtable + heap at 0x0A000000
  └─ run with JNI_DEBUG=1 to see DIGEST / COPYOF / CTOR / HEAP-SCAN
scripts/forensic_pipeline.py → stages 1-2 threat indicators + code review (AC4 gate)
scripts/batch_pendrive.py    → triage 55 pendrive APKs in one sweep
analysis/recovered/    → every decrypted artifact + INTEL docs (local-only)
analysis/ac4/          → baseline vs recovered pipeline reports (AC4 proof)
```

**Repo map:** `venv/` has all deps (androguard, lief, capstone, Unicorn, pycryptodome, tldextract). Don't `pip install` globally. Kernel is vanilla — no binder module needed after Waydroid removal. `/tmp` is tmpfs: anything in `/tmp/opencode` or `/tmp/arm64.so` vanishes on reboot.

---

## 3. Dataset you inherit

- **RTO.apk** — the canonical custom packer. 5-char asset stem `myg0N`, payload `myg0Ninstaller.dex` nested ZIP, final kit 8.9 MB.
- **PENDRIVE DATA/** — 55 real APKs (56 files on disk, 1 is macOS `._` junk). Mix of goodware, Ijiami/360Jiagu/Bangcle/TencentLegu packs, and 3 copies of the myg0N kit.
- **samples/** — AndroZoo/unpacked sets used for triage locklist validation (0% FP on 55-sample locklist, re-verified with A/B controls).

---

## 4. Packer taxonomy (what you'll meet)

**myg0N kit (custom, beaten):**
- Assets named `<stem>` + `bootstrap.dex` literal. True seed = `stem.substring(0,5) + "2"` → e.g. `myg0N2`, `UZrF0u2`, `ZoCv0N2`, `LAZx0b2`.
- `KEY = sha1(seed)[:16]`, `IV = sha256(seed)[:16]`, AES/CBC/PKCS5. Zip flags `0x2769` are fake.
- Payload kit always: `installer.dex` (nested ZIP→classes.dex), `bootstrap.dex`, 3 split APKs, `install_library.zip`, `miner.apk` placeholder. Miner MAC is constant across builds of the same builder subscription.

**Commercial packs (documented as E-codes, not beaten):**
- **Bangcle/SecNeo, Ijiami, 360Jiagu, Tencent Legu** — all `RegisterNatives`-only loaders (no `Java_*` export). Oracle needs `.init_array` emulation to capture their registration. Currently `E-*-NOENTRY`.
- **Door/Pay (custom, `000027d1`)** — has static `Java_*` exports but is arm32 3-arg JNI. Oracle seeds only R0/R1, so R2 is garbage → `E-ARM32-ENVARGS`.
- **Java-only injected repacks (e.g. TurboFly)** — `so_count: 0`. Not a crypter; injected receivers/services do the work. Take the Java path (jadx, manifest diff).

---

## 5. The oracle, honestly

- GOT shims for libc (`getauxval`, `__system_property_get` → fakes Pixel 4a props), full JNIEnv vtable (233 slots). Property serving is hard-coded in `emulate.py` (`PROPS` dict).
- Heap at `0x0A000000`, 16 MB, bump allocator. Objects are tokens; `new_array()` writes bytes to heap *and* registers a `bytes` object. Native code receives the token, not the heap pointer — this is why `read_obj_bytes` can return zeros even though heap holds the real digest. **Always cross-check heap via `[HEAP-SCAN]`.**
- `substring` mock ignores index args. `digest` engine lookup can return `None`. `copyOf` on static calls has an off-by-one. These are *known lies* — the guide tells you to distrust and brute-force.

---

## 6. Canonical walkthrough — RTO end-to-end

```bash
# 1 triage
venv/bin/python scripts/triage.py RTO.apk --out /tmp/t.json
# expect: packed_custom conf 0.85, H2/H6, no payload yet

# 2 dissect
venv/bin/python scripts/dissect.py RTO.apk --workdir analysis/dissect_m1/RTO
# expect: libstrangulation.so arm64, one Java_* export

# 3 emulate (with instrumentation)
# scripts/rto_deep_run.py was deleted 2026-11-12 (see git history). To re-run it, restore it first:
# JNI_DEBUG=1 timeout 900 venv/bin/python -u scripts/rto_deep_run.py 2>&1 | tee log
# expect: [DIGEST] len=20 input_head=... (hex of seed+"bootstrap.dex2")
#         [HEAP-SCAN] digest@ 0xa000d90
# engine strings in JNI trace: SHA-1 then SHA-256

# 4 derive & brute (the substring fix)
# S="myg0Nbootstrap.dex", enumerate S[a:b][c:]+"2" (≈3.4k combos)
# HIT at a=0,b=5,c=0 → P="myg0N2"

# 5 decrypt & validate
P=b"myg0N2"; k=sha1(P)[:16]; iv=sha256(P)[:16]
AES.new(k, AES.MODE_CBC, iv).decrypt(open("assets/myg0N","rb").read())
# validate: pt[:2]==b"PK" AND flags 0x2769 AND last CBC block = valid PKCS7 AND nested ZIP
```

If you skip the brute and use the mock's literal directly, decryption fails. That's the lesson.

---

## 7. Difficulties 1-19 (expanded)

See `MASTER_KEY_STRATEGY.md` table — each row is a real incident with symptom→countermeasure. Highlights for KT:

- **11 /tmp vanishes:** copy `/tmp/arm64.so` and oracle state into `analysis/work/<hash>/` before long runs
- **12 buffered logs die:** always `-u` + `tee`
- **10 checkpoint vs final pkl:** `key_log` lives only in final, not checkpoints; instrument `JNI_DEBUG` prints survive either way

---

## 8. Pendrive batch — what the 55 really are

| Bucket | n | Who |
|---|---|---|
| clean_static | 44 | Banking/gov-named repacked benigns |
| indeterminate | 4 | PNB One, PNB ONE ACTIVATION, Repair service, M PARIWAHAN CHALAN (12) — all *actually malicious* myg0N-kit droppers, under-flagged |
| packed_known(Ijiami) | 3 | Calculator ×3 |
| packed_custom | 1 | RTO E CHALLAN (1) — myg0N kit |
| triage error (ZipCrypto) | 3 | Tubi-inin, Google Video, MediaPlayer2 — runtime-password zips |

3 myg0N-kit samples cracked (seeds UZrF0u2 / ZoCv0N2 / LAZx0b2), each yields identical `bootstrap.dex` and miner MAC — same builder. See `PENDRIVE_MASTER_KEY_INTEL.md` (local-only) for full table, C2s, and oracle notes. Calculators + ZipCrypto set are preserved for follow-up with E-codes.

---

## 9. IOCs, C2s, and the registry

**C2 type in this corpus is Firebase RTDB, not Telegram.** `TelegramBotUtils` classes exist but tokens are runtime-configured via the DB. Typical schemas:
- `clients`/`messages` (RTO) or `Users`/`All_Users`/`login`/`guard` (PNB) — `login` holds harvested creds, `All_Users` enumerates capabilities (`sms`, `CallForwarding`, `SmsForwarding`, `Data`, `simDetails`).

**Live C2s were shallow-probed only** (`?shallow=true`, key names + counts, no victim data harvest) to prove exposure. Full victim records are law-enforcement-only.

**Registry workflow:** `analysis/recovered/toreport.csv` — **local-only, gitignored.** One row per APK: apk_name, artifacts_found, telegram_token, bot_name, c2_link, api_for_c2. Append + commit per sample. Never push; abuse reports use redacted excerpts.

---

## 10. Tooling reference (when to use what)

| Script | Purpose | Gotcha |
|---|---|---|
| `triage.py` | Heuristics H1-H6 | `packed_custom` with `so_count:0` → Java path, not native |
| `dissect.py` | Native report | May report `extractor/rc` warnings; .shstr errors on some arm libs are harmless |
| `emulate.py` | Oracle | Needs `--so` + `--sym`; arm32 needs R2/R3 seeding for 3-arg JNI |
| `forensic_pipeline.py` | Stages 1-2 gate (AC4) | LLM is optional (Ollama fallback); `indeterminate` ≠ benign |
| `batch_pendrive.py` | 55-sample sweep | Writes `reports/pendrive_*.csv` + `analysis/triage_pendrive/` |
| `unpack.py` | **Master dispatcher** (2026-08-28): routes JAVA/NATIVE, family sniffing, typed E-codes, self-validating outputs, myg0N KDF brute | Every run ends in artifacts or a typed E-code — never a blank |
| `retry_pendrive_timeouts.py` | Re-runs timeouts | Don't re-run ZipCrypto trio blindly |
| `rto_deep_run.py` *(deleted 2026-11-12, see git history)* | Deep oracle with checkpoints | Needs `/tmp/arm64.so` to exist; run with `JNI_DEBUG=1` + `-u` |

---

## 11. Environment & setup (the boring stuff that bites)

- Use `venv/bin/python` always. `requirements.txt` + `requirements-lock.txt` are the source of truth.
- `/tmp/opencode` is your scratch — gitignored, tmpfs. Promote anything worth keeping to `analysis/`.
- File perms can flip to root after sudo tooling (`RTO.apk` did). `sudo chown/chmod` back.
- `pkill -f '[w]aydroid'` bracket trick — plain `pkill -f 'waydroid'` kills your own shell.
- No Waydroid/emulator needed anymore. If someone revives that path, read `postmortem-rto-blocker.md` first.

---

## 12. Reproducing results

- **A/B triage:** `scripts/triage.py` on `0023DB21…` (goodware) vs `00002371…` (Bangcle) — expected `clean_static` vs `packed_known`.
- **AC4:** `scripts/forensic_pipeline.py` on `RTO.apk` (benign) vs `payload_split1.apk` (malicious, T1003/T1005). Reports in `analysis/ac4/`.
- **Decryption:** recompute `sha1("myg0N2")[:16]` / `sha256("myg0N2")[:16]`, AES-CBC over `assets/myg0N`, check `PK` + `0x2769`.

---

## 13. Reading order for a new joiner

1. This file
2. `docs/MASTER_KEY_STRATEGY.md` (the 7 steps)
3. `docs/MAFIA_v2.1.md` (methodology)
4. `analysis/recovered/RTO_INTEL.md` → SOLVED section (the canonical crack)
5. `analysis/recovered/M4_GENERALIZATION.md` (honest limits)
6. `PENDRIVE_MASTER_KEY_INTEL.md` + `myg0N_IOC.md` + `toreport.csv` — **local only, ask the owner**

---

## 14. What's next / open work

- ~~`E-ARM32-ENVARGS` fix~~ — **RESOLVED 2026-08-28**: Thumb start + ARM
  interworking + relocation pass now in `emulate.py`; door packer runs clean.
- `E-*-NOENTRY` fix (`.init_array` + RegisterNatives capture)
- Java-path automation for `so_count:0` repacks → **DONE**: `scripts/unpack.py`
  dispatcher (JAVA/NATIVE routes, family sniffing, typed E-codes, self-validating
  outputs, autonomous myg0N KDF brute).
- Miner split follow-up (payload's `miner.apk` is 0 B placeholder, fetched live)

## 15. Mission-critical triage matrix (2026-08-28; reproduced 2026-10-04/05)

Original claim (2026-08-28 run; run artifacts were excluded at the publish
commit `be31a2d` "sensitive artifacts excluded" — several originals survived
as local leftovers and were recovered 2026-10-05, see findings 2–3):

| ground truth | clean | packed-detected | suspect | FP / FN |
|---|---|---|---|---|
| goodware (100) | 95 | 3 brand-matched + 2 sha256-allowlisted | 0 | **0 FP** |
| malware (32) | 13 unpacked (semantics OK) | 19 flagged (all packed kits detected) | 4 dropper-shape suspects | **0 FN** |

**Reproduction (2026-10-04/05):** `python scripts/triage_matrix.py` →
`analysis/ac4/triage_matrix.json` (gitignored; regenerate any time). Sample set:
`samples/goodware/benign_eval` (100) + locklist buckets `gt_packed_suspect` /
`gt_malware_unpacked` / `reserve_realworld` (14) + pendrive rows from
`ground_truth_all.csv` (18) = 32 malware; `RTO.apk` excluded (AC1 calibration
positive). 132/132 triaged, 0 missing, 0 errors.

| ground truth | clean | packed-detected | suspect | FP / FN |
|---|---|---|---|---|
| goodware (100) | 95 | 3 brand-matched + 2 sha256-allowlisted | 0 | **0 FP** |
| malware (32) | 21 non-flagged (semantics OK) | 8 flagged | 3 dropper-shape suspects (PNB One, PNB ONE ACTIVATION, Repair service) | **0 FN** |

Reproduced exactly: every goodware cell (95 / 5 / 0 FP), the malware total (32)
and both headline claims (**0 FP**, **0 FN**). Not reproduced: malware internals
(clean +8, flagged −11, suspect −1) — the JSON records
`doc_claim_reproduced: NO` with the full delta. Findings behind the delta:

1. **Allowlist reconstruction.** `sha256_allowlist` was excluded at publish and
   was restored 2026-10-04: the claim's arithmetic (95 clean + 3 brand + 2
   remaining of 100) uniquely identifies `000160700ddab…` and `0021399f0bd9…`;
   both are ground-truthed `confirmed_external` benign with 0 VT detections
   (`ground_truth_check_all.csv`). Reconstruction provenance is recorded in
   `data/engine_allowlist.json`.
2. **The "encrypted" members were a flag-lie, now read.** Three pendrive
   droppers (Tubi-inin, Google Video, MediaPlayer2) set encryption bit 0x1
   on plaintext, CRC-valid entries, so `zipfile` refused every member — the
   published code crashed on them, and the original 2026-08-29 sweep
   recorded `triage_error` for all three (finding 3). Corroborated by the
   local case report `analysis/recovered/TOREPORT_READABLE.md` ("ZipCrypto
   trio was never encrypted — fake flag bits; all 1722 entries plaintext &
   CRC-valid"). Triage now defuses the flag and lets zlib/CRC decide
   (`triage._open_member`): zero members skipped, all three triage on real
   evidence — MediaPlayer2's high-entropy payload scores H1+H2 →
   `packed_custom`, evidence the skip logic used to discard.
3. **Original-run artifacts recovered: the malware cells overreached.**
   The original pendrive sweep survived locally and is committed as
   `data/triage_pendrive_v2_summary_20260829.csv` (2026-08-29, 56 rows):
   - **15/15** of the matrix's pendrive samples with original verdicts
     match the reproduction exactly; the 3 remaining original rows are the
     trio's `triage_error`, now triaged;
   - the original suspects were **exactly 3 — the same three** (also
     tabulated in the local-only `analysis/recovered/PENDRIVE_MASTER_KEY_INTEL.md`:
     "`indeterminate(suspect:dropper-shape)` | 3 | PNB One + Repair service
     … PNB ONE ACTIVATION"). The claim says 4. The likely source of the
     fourth is `M PARIWAHAN CHALAN (12)`: `indeterminate` in both runs,
     noted "under-flagged: this is fully malicious" in the same intel doc
     but never escalated under the documented rule;
   - the claim's malware cells are internally inconsistent (13 + 19 + 4 = 36
     > 32), and `13 / 19 / 4` appears nowhere else in the repository.
   Two alternative readings were tested, not tuned for: the locklist's GT
   expectations give 6 `expect_flag` (not 19); counting ≥1 heuristic hit
   gives 14/18 (not 19/13), and 16 benign samples carry heuristic hits,
   which would break the exactly-reproducing goodware row. Code drift is
   excluded as well: H1–H6 are unchanged across all git history, and the
   A/B of the dropper-signal fixes shows **0 verdict differences**
   (`analysis/ac4/ab_fcm_fix.json`: fcm same=79 / new-only=53 / old-only=0,
   parse-guard diffs=1, verdict diffs=0; regenerate with
   `python scripts/ab_fcm_fix.py`).

Semantics: triage detects **packing**; malice adjudication is `forensic_pipeline.py`
(AC4 layer). `indeterminate` is never benign — dropper-shaped manifests escalate to
`suspect`. Known-benign custom-packed apps are sha256-allowlisted in
`data/engine_allowlist.json`.
