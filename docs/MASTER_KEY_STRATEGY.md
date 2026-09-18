# The Master Key Strategy — plain-words playbook

How we beat RTO.apk with no phone, no emulator, no internet risk.
Use this as the checklist for every new packed sample.

---

## The one-line idea

> **Don't run the malware. Make it run itself inside a fake world, then
> write down every secret it touches.**

The malware carries its own keys and does its own crypto. We don't break
the lock — we watch the thief unlock it, and copy the key.

---

## The 7 steps

### 1. Triage — "is it wearing a mask?"
`python scripts/triage.py <apk>`
Heuristics H1–H6 look for tiny code + high-entropy blobs + compute-only
libraries. Verdict examples: `clean_static`, `packed_known(Bangcle)`,
`packed_custom`.

### 2. Dissect — "what's inside the box?"
`python scripts/dissect.py <apk>`
Lists native libraries, exported JNI functions, crypto constants.
You want: which `.so` file does the unpacking, and does it have a
`Java_...` export we can start from?

**Branch point — `so_count: 0`?** Then the "packer" is pure Java
(injected trojan repack, not a crypter). Skip to **Step 2.5**.

### 2.5 Java path — "no native libs, no oracle needed"
1. `jadx -d out/ classes.dex` (quietly; ignore the game/cover classes)
2. Diff the manifest against the cover app: randomized receivers/
   services with names like `je.mnvs.uyr.jgf` that hook
   `USER_PRESENT` / `CONNECTIVITY_CHANGE` are the injected payload.
3. Read those classes. Typical finds: silent download managers,
   `startActivity(INSTALL)`, `pathUrl`-style intent extras, hardcoded
   WAP proxies. The "C2" is often just a URL the operator pushes —
   expect **no encrypted payload on disk** (E-RUNTIME-DELIVERY).

### 3. Emulate — "a fake Android in a jar"
`python scripts/emulate.py --so <lib.so> --sym <entry>`
Our Unicorn oracle pretends to be Android: fake JNI table, fake
properties (Pixel 4a), fake heap. The native unpacker runs happily,
never knowing it's alone in a sandbox. Nothing touches a real device.

### 4. Instrument — "put a recorder on everything"
Run with `JNI_DEBUG=1`. The oracle prints:
- `[DIGEST]` — every hash input (this is where keys are born)
- `[COPYOF]` — the trimmed key bytes
- `[CTOR]` — keys/IVs handed to SecretKeySpec / IvParameterSpec
- `[HEAP-SCAN]` — where the bytes really live in emulated memory

### 5. Trust nothing blindly — "the mock will lie to you"
The fake Android is helpful but imperfect. In RTO's case the fake
`substring()` ignored its arguments and showed us the WRONG key
password. Fix: when the space of possibilities is small, brute-force
it and let the file itself tell you the truth.

**Validation rules (never skip):**
- Decrypted payload must start with `PK\x03\x04` (ZIP) or `dex\n` (DEX)
- ZIP flags must match the malware's fake value (RTO used `0x2769`)
- Use the IV-independent padding check (last CBC block) when IV unknown

### 6. Extract — "open the kit, write it down"
Save every decrypted file under `analysis/recovered/<name>/`,
record SHA-256 of each artifact, and note what each piece does
(loader? miner? SMS reader? call-forwarder?).

### 7. Report — "turn findings into action"
Append one row per APK to `analysis/recovered/toreport.csv`
(apk_name, artifacts_found, telegram_token, bot_name, c2_link,
api_for_c2). Then: Firebase/Google abuse report for live C2,
national cybercrime portal + bank fraud team for financial cases.

---

## The RTO case in 15 seconds

```
RTO.apk (packed, looked "benign" to scanners)
  → oracle runs libstrangulation.so
  → it builds a string: "myg0Nbootstrap.dex".substring(0,5) + "2"
  → key  = sha1("myg0N2")[:16]
  → iv   = sha256("myg0N2")[:16]
  → decrypts myg0N → ZIP → installer.dex → Binance-signals spyware
  → C2: live Firebase database, 30+ victims, no password needed
```

---

## Pitfalls that cost us time (so they cost you none)

1. **Don't fight VMs.** Waydroid/emulator graphics + networking eat days.
   The oracle already answered the question.
2. **Mocks lie.** Always brute-force small unknowns; magic bytes never lie.
3. **Digest inputs ≠ keys.** Engines can differ per call (sha1 for key,
   sha256 for IV in RTO). Capture both.
4. **No Telegram token? Normal.** Modern kits configure bots at runtime
   through C2 databases — go find the database, not the token.
5. **Never harvest victim data.** Shallow probes only; keep the evidence
   chain clean for law enforcement.

---

## Encrypted-APK difficulties & how to not be bothered

Every difficulty below was actually hit during this project. Symptom →
what to do instead of panicking.

| # | Difficulty | Symptom | Countermeasure |
|---|-----------|---------|----------------|
| 1 | Key looks device-bound | No constant string decrypts the asset | Don't assume device state. Trace the string-builder calls in the JNI log; the "device state" is often just `literal.substring(a,b) + "x"`. Brute-force small index spaces (~3k combos) against magic bytes |
| 2 | Mock returns wrong strings | Digest input looks plausible but decryption fails | Mock helpers can ignore arguments (RTO's substring did). Reproduce the transformation yourself from the call order, then brute-force the missing indices |
| 3 | Key/IV use different algorithms | sha256(key-material) fails everywhere | Engines differ per call (RTO: sha1→key, sha256→IV). Match each digest call to its `getInstance` string in the JNI trace |
| 4 | Byte arrays arrive as zeros | `[COPYOF]`/`[CTOR]` print 0000... | Mock object plumbing loses bytes on static-call off-by-one. Read truth from emulated heap (`[HEAP-SCAN]`) or recompute the digest yourself — input bytes are already captured |
| 5 | Decrypted blob fails magic check | No `PK`/`dex\n` at offset 0 | Payload may be *nested* (RTO: `installer.dex` was a ZIP containing the dex). Run `file`/magic check on every layer |
| 6 | Fake ZIP flag bits | Naive ZIP parsers reject the payload | Kits set bogus flag bits (RTO: `0x2769`). Whitelist the malware's flags when validating; don't trust generic strictness |
| 7 | No `Java_*` export anywhere | `RuntimeError: no Java_* export found` | RegisterNatives-only packers (Bangcle/Ijiami/360Jiagu). Needs `.init_array` emulation to capture RegisterNatives — currently **E-*-NOENTRY**. Cheaper: try the x86 variant of the lib, or a sibling sample of the same family |
| 8 | arm32 3-arg JNI crashes | `UC_ERR_WRITE_UNMAPPED` on entry | `find_entry` seeds only R0/R1. 3-arg entries need fake objects in R2/R3 (signature-driven seeding) — currently **E-ARM32-ENVARGS** |
| 9 | Native `abort()` mid-run | status: abort | A probe failed (property, file path, signature check). Check what the code read last in the JNI/libc log; serve the expected answer in the mock and re-run |
| 10 | Run dies before writing results | timeout kill, empty log | Use `python -u` (unbuffered), checkpoint pickle every N insns, and remember checkpoint format ≠ final format — persist `key_log` in BOTH |
| 11 | /tmp artifacts vanish after reboot | `.so`/state.pkl gone (tmpfs) | Copy oracle inputs into the repo (`analysis/work/<hash>/`) before long runs; /tmp is scratch, not storage |
| 12 | Log output lost on crash | python buffered stdout dies with process | Always `-u` + redirect to file; grep-able logs are your lab notebook |
| 13 | Sample file perms flip to root | `PermissionError` on your own APK | Some tooling chowns what it touches. `sudo chown` back and `chmod 644`; never run analysis as root |
| 14 | `pkill` kills your own shell | Command dies instantly, no output | Pattern matches your own command line. Use `pkill -f '[w]aydroid'` bracket trick |
| 15 | Decoy execution paths | Packer exits early, "clean" status | Anti-analysis (RTO: x86 ABI check → decoy exit). Serve the expected arch/props from the mock (`ro.product.cpu.abi=arm64-v8a`) before first run |
| 16 | Commercial packers (Bangcle/360/Ijiami/TencentLegu) | VMP/OLLVM-flattened natives, runtime-registered JNI, cert-bound keys | Expected territory of E-codes; the oracle wins on *custom* packs first. Don't burn days before documenting the E-code and moving to a sibling sample |
| 17 | Nothing decrypts, all checks pass | Both right key *and* right file, still garbage | Re-verify ciphertext source: assets can be split across entries (`payload_split*`), zipped twice, or XOR'd *after* AES. Diff first plaintext block across candidate keys — correct key shows structured bytes, wrong shows noise |
| 18 | Triage says packed_custom but `so_count: 0` | Native oracle has nothing to run | It's an injected trojan repack, not a crypter. Take the Java path (Step 2.5): diff manifest receivers against the cover app's package lineage, decompile the injected classes. Payload usually arrives at runtime (E-RUNTIME-DELIVERY) — extract IOCs, not a kit |
| 19 | Triage bucket "indeterminate" (flagged=False) on real spyware | Under-flagged fully-malicious sample (PNB One case) | Treat `indeterminate` as suspect, never benign: no launcher + FCM receiver + REQUEST_INSTALL_PACKAGES = dropper shape regardless of triage score. Deep-check before dismissing |

### Standing rule

> Every difficulty becomes either a **fix** or an **E-code** the same day.
> Never leave a failure undocumented — the E-code list is the guide's
> honest map of where the oracle currently stops.
