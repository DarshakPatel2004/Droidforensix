# Issues — Pendrive Hunt (2026-08-28)

## 1. Ijiami (Calculator ×3) — E-VMP ceiling

- **Samples:** `Calculator.apk` (8030086 B, header `8caaa101...`), `Calculator(1).apk` (7734285 B, `cc091402...c0fac742e91f...`), `Calculator(2).apk` (6871023 B, `80de7d01...`)
- **Stub:** `s.h.e.l.l.S` → `N.al/b2b/l/m/r/ra` + `DETool.loadDEso`, cover `ch.deletescape.lawnchair.App`
- **Assets:** `ijiami.dat` (header `04000000` + 32-hex key), `ijiami.ajm` (`696e646c3031` "indl01"), `ijiami_beaver.VData` (`69766d70 0a3032` "ivmp\n02" VMProtect, 33633 B)
- **Native:** `libexec.so` (563004 B) + `libexecmain.so` (258508 B) — `JNI_OnLoad 0x64e6c` / `ijiami 0x64834` disasm to SME `st1d {za7h}` (VMP), `r2 afl` = 4 B stubs, `DT_INIT 0x76048` valid but 32 ctors leave `0x64e6c` unchanged (`c2ce4fc6...`)
- **Oracle:** `scripts/ijiami_oracle.py` (VM triple-deref `0xd020000→0xd020040→ret`, relocs, ctors, RegisterNatives capture) — helpers `libnrb: NativeReflectionBypass` + `libcalc: IOUtils` ok, main loaders still `UC_ERR_EXCEPTION`
- **Static brute:** AES-CBC/ECB/RC4/XOR with seeds `com.hidenipure.calculat`, `ch.deletescape…`, `c0fac742…`, `ijiami` → no `dex\n`/`PK`; `zlib` fail; `beaver` also no hit. Entropy 7.93.
- **Playbook:** `docs/MASTER_KEY_STRATEGY.md:136` row 16 + `plans/2026-08-26:80` P7 — VMP out-of-scope, E-code expected. Ghidra `analyzeHeadless /tmp/ghidra_ijiami:2s` + `r2` confirm VMP.
- **Next without Frida:** Ghidra devirt of `DT_INIT 0x76048` (valid loop `ldrb; lsl`) or sibling `x86` variant (also `no Java_*` `emulate.py:652`).

## 2. Native-keyed (M PARIWAHAN / PNB ONE ACTIVATION) — E-JNI-SHIM

- **Libs:** `libldltt.so` (M) `2.9 MB`, `libcater.so` (PNB) `1.0 MB` — 5 Java exports each, `attachBaseContext` + 3 `Runnable.run` + `onCreate`
- **Oracle:** `ijiami_oracle.py` now handles `JavaVM` triple-deref, relocs, ctors, `RegisterNatives` capture — helpers `libnrb`/`libcalc` ok, but main libs hit `WRITE_UNMAPPED pc 0xd030910` (SHIM slot 145 `GetStaticObjectField`) after ~9 `FindClass` (`java/lang/String`, `android/content/Context`, `Build`). `SHIM 0xd000000-0xd03ffff perms 7` is RWX and `mem_write 0xd030910` succeeds in isolation, but under emulation the `stp xzr,[x0]` at `0x3689c4` with `x0=0x14000040` triggers lazy-map storm (0x14000000, 0x3c..., 0xb4..., 0x12fc...) then final `pc 0xd030910` `c0035fd6` RET still faults as `WRITE_UNMAPPED` (hook not triggered, bytes still RET). Root: small-ID `jobject` handles (`0x500`) vs heap pointers, plus JNI table overwrite attempt.
- **Static brute:** `dKcSeAyvsM` etc. `+ "2"` KDF `sha1/sha256` no hit; package-name seeds also no hit.
- **Next without Frida:** enlarge heap to 256M (overlaps `FAKE_JENV 0xb000000`), or make `new_obj` return heap-backed `jclass` structs, and whitelist SHIM writes in `emulate.py:239`.

## 3. ZipCrypto containers (MediaPlayer2 / Tubi-inin / Google Video) — E-SOCIALLY-DELIVERED

- **Files:** `MediaPlayer2.apk` (147/147 entries encrypted, no native libs), `Tubi-inin.apk`/`Google Video.apk` share `ce0*/mcb*` container family, `mp2_classes.zip` 4 KB hash `fe2*2048*7d5c6a21`
- **Cracking:** `rockyou` 14.4M 0 hits `11567Kc/s`, `case_cands+Best64` 0, `?d×6` 0, `?d×8` 0, `9?d×9` 0 (20–50 s each). `hashcat` no OpenCL. 10-digit Indian mobile `10e9` candidates @ 3.7M p/s ≈44 min, likely not numeric (social word).
- **Verdict:** Delivery containers, password shared via WhatsApp/SMS to victim — offline brute likely futile without complainant-supplied password. Preserve `mini.john` hashes for LEA.

## 4. Gov/Banking OTP/SMS forwarder sweep — completed

- **SMS-capable:** `BreakInB/SW_m4582hsz` (10 numbers `+917000770007…`), `Customer Support..`, `dream11_1`, `157500`, `Tivo`, `youtube-revanced`, `J&K Bank kyc Update`, `PM AWAS 2024` (`+917488986307`), `प्रधानमंत्री…` (`+918310299942/+918217376195`), `AmazonFlex` — all `WebView+loadUrl` also true (phishing overlay + SMS exfil)
- **WebView-only (no SMS):** `Bank of India` (nested `output.apk` dropper), `Batwin/Goplay/MatkaPoint` (gambling `47.107.186.111` hotUpdate), `CBI HRMS` (legit `hrms.centralbankofindia.co.in`), `DELHI JAL BOARD` (16 entries, **zero** SMS/WebView C2 — clean lure)
