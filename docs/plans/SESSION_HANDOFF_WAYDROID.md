# Session Continuity: RTO Payload Extraction (Waydroid Tier-5)

> ## ⚠️ SUPERSEDED 2026-08-27 — DO NOT EXECUTE
>
> Waydroid was removed after this plan failed on four independent layers
> (binder, vmwgfx/GBM crash-loop, auto-freeze, container networking). The
> blocker it targeted was later solved **statically** — see
> `2026-08-27-waydroid-postmortem-rto-blocker.md` and
> `analysis/recovered/RTO_INTEL.md` (SOLVED section).
> Kept for the record only. Credentials below redacted; do not restore.

**Paste this file into a new chat to resume exactly where we left off.**

---

## Who you are

You are assisting with **DroidForensix**, an Android malware forensics pipeline
(thesis project, Kali VM). Read `AGENTS.md` at session start — it governs your
behavior. Follow its four-voice council discipline for decisions.

## What happened last session (branch `wip/static-unpacking-oracle`, 4 commits)

A plan was written, reviewed, and executed through M0–M4 to break a packed APK
(`RTO.apk`) **statically without any Android runtime**, using Unicorn emulation:

1. **M0** — `scripts/triage.py`: structural triage (heuristics H1–H6).
   55-sample locklist (`data/triage_locklist_m0.csv`), 0% FP, AC1 pass:
   RTO → `packed_custom` conf 0.85 in <5 s.
2. **M1** — `scripts/dissect.py`: LIEF+capstone native dissection,
   crypto constants scan, RegisterNatives hunt. Ghidra installed at `tools/ghidra`.
3. **M2/M3b** — `scripts/emulate.py`: generic Unicorn oracle (libc GOT shims +
   full 233-slot JNIEnv vtable). **RTO stage-2 DEX recovered**
   (`analysis/recovered/RTO_recovered.dex`, 3328 B, jadx-clean; sha256 `48486337…bc74`).
4. **Intel extracted** (see `analysis/recovered/RTO_INTEL.md`): the packer is a
   custom XOR-decryptor with Stalin-themed randomized names. Recipe:
   AES/CBC/PKCS5 + SHA-256 key derived from device state → decrypts
   `assets/myg0N` (7.8 MB) → ZipInputStream("myg0Ninstaller.dex") →
   InMemoryDexClassLoader → `com.lqbczc.szubinocgulatizofn.App` +
   `.TerminizeReceiver`. FCM receiver confirmed in manifest.
   Anti-analysis: x86 ABI check → decoy exit; fake zip flag bits 0x2769.

## Where we got stuck

The myg0N AES key is **derived from live device state**; static captures of the
digest pre-image were polluted by our own reflection-mock bugs (`sha256(b"SHA-1")`
and `sha256("")` artifacts). Two candidates tried and failed against PK/dex magic:
the exact seed formula needs *real* Android execution.

Decision made: escalate to **Tier-5 = Waydroid inside this Kali VM** (NOT host
MEmu — user worried about host risk; agreed Waydroid-in-VM is storage-efficient
(~2 GB) and fully contained).

## Environment changes already made

- New kernel **7.1.5+kali-amd64** installed (image + headers).
- GRUB updated: default boots 7.1.5 with cmdline
  `android-binder.devices=binder,hwbinder,vndbinder`.
- Waydroid 1.6.3 package installed (`sudo apt install waydroid` done).
- Old kernel binder module loaded but wedged single-device ("busy"); after reboot
  all three nodes appear.
- Everything committed on branch `wip/static-unpacking-oracle`. Unrelated edits
  (frontend/, ground-truth CSVs) intentionally left uncommitted.

## YOUR FIRST TASKS in the new session (in order)

1. **Verify reboot state:**
   ```bash
   uname -r                       # expect 7.1.5+kali-amd64
   ls /dev/binder /dev/hwbinder /dev/vndbinder   # all three must exist
   ```
   If nodes missing: check `/proc/cmdline` contains the devices= param;
   fallback `sudo modprobe -r binder_linux && sudo modprobe binder_linux
   devices="binder,hwbinder,vndbinder"` BEFORE anything else touches /dev/binder.

2. **Initialize Waydroid:**
   ```bash
   sudo waydroid init                # pulls LineageOS image (~700 MB)
   sudo systemctl start waydroid-container
   waydroid session start            # may need WAYLAND_DISPLAY / weston if X11
   ```

3. **Spoof ARM ABI (critical — packer checks x86 and bails to decoy):**
   ```bash
   sudo waydroid shell -- getprop ro.product.cpu.abi      # will say x86_64
   sudo waydroid shell -- resetprop persist.ro.product.cpu.abi arm64-v8a
   sudo waydroid shell -- resetprop ro.product.cpu.abi arm64-v8a
   sudo waydroid shell -- resetprop ro.product.cpu.abilist arm64-v8a,armeabi-v7a
   ```
   Also consider `ro.product.cpu.abilist` variants + `ro.build.fingerprint`.

4. **Install the sample & tooling inside container:**
   ```bash
   # copy RTO.apk into shared path or use adb over TCP
   sudo waydroid app install RTO.apk    # if it installs as app
   # push frida-server-android-x86_64 binary into container via waydroid shell
   # run frida-server, hook from Kali side: frida -H 127.0.0.1
   ```
   Network: container NATs through Kali by default = isolated from home LAN.
   Confirm before detonation: no port-forwards, no bridged Wi-Fi passthrough.

5. **Detonate & capture the key:**
   Hook these constructors/strings at minimum:
   - `javax.crypto.spec.SecretKeySpec.<init>([B, String)` → dump [B = KEY
   - `javax.crypto.spec.IvParameterSpec.<init>([B)` → dump [B = IV
   - `Cipher.getInstance("AES/CBC/PKCS5Padding")`
   - `AssetManager.open("myg0N")` → note InputStream object
   Then either let the payload unpack naturally, or after dumping KEY+IV do the
   decryption offline in Python against `assets/myg0N` bytes:
   ```python
   pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
   # expect PK\x03\x04 zip containing "myg0Ninstaller.dex"
   ```

6. **After success:** pull final dex(es), save under
   `analysis/recovered/`, update `RTO_INTEL.md`, commit on same WIP branch.

## Acceptance criteria remaining

- AC4: rerunning stages 1–2 of `scripts/forensic_pipeline.py` on recovered
  artifacts flips RTO verdict away from confident-benign toward its GT label.
- M4 generalization: ≥1 more family (Ijiami/Bangcle/360Jiagu) unpacked, else
  documented E-codes.
- AC5 was already satisfied statically.

## Files you'll want open immediately

- `docs/superpowers/plans/2026-08-26-static-unpacking-pipeline-plan.md` (the master plan)
- `analysis/recovered/RTO_INTEL.md` (crypto chain evidence)
- `scripts/emulate.py` (contains working JNIEnv mock semantics)
- `data/triage_locklist_m0.csv`

## Warnings

- Never detonate outside the Waydroid container; never enable shared folders
  between container and Kali beyond what's needed.
- The sample has FCM command-receiver capability; keep network restricted even
  inside the VM (container NAT is default-isolated but verify with ip route).
- User password on this box: (redacted — was committed here in error; ask the
  user directly if sudo is needed)

---
*Generated automatically at end of prior session so the next chat can resume
without loss.*
