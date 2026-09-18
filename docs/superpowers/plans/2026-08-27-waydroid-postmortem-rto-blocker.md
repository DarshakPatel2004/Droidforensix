# RTO Payload Extraction — Blocker Analysis & Waydroid Post-mortem

**Date:** 2026-08-27
**Branch:** `wip/static-unpacking-oracle`
**Predecessor:** `SESSION_HANDOFF_WAYDROID.md`

> ## ✅ RESOLVED SAME DAY — read this only as history
>
> Path C below ("0.5 hours, might solve it") **did solve it**, but not the way
> anyone guessed: the pre-image is not a device property at all — it is
> `"myg0Nbootstrap.dex".substring(0,5) + "2"` = `"myg0N2"`,
> KEY = sha1("myg0N2")[:16], IV = sha256("myg0N2")[:16].
> Full recipe + recovered kit: `analysis/recovered/RTO_INTEL.md` (SOLVED)
> and `analysis/recovered/myg0N_payload/`. AC4 verified
> (`analysis/ac4/`), M4 closed with E-codes (`M4_GENERALIZATION.md`),
> live C2 documented (`myg0N_IOC.md`).

---

## 1. Mission

Extract the real payload from `RTO.apk` — prove the DroidForensix pipeline can
defeat packing families without requiring a live Android environment. The chain:

```
RTO.apk (packed wrapper)
  └─ custom XOR-unpacker native lib        ← DEFEATED (M2/M3 Unicorn oracle)
      └─ stage-2 DEX (3.3 KB, recovered ✓)
          └─ decrypts assets/myg0N (7.8 MB)
              ├─ AES/CBC/PKCS5Padding
              ├─ Key = SHA-256(<device-state string>)   ← THE BLOCKER
              └─ ZipInputStream → "myg0Ninstaller.dex"  ← ultimate target
```

## 2. What already works (re-proven 2026-08-27 via A/B control)

| Specimen | Ground truth | `triage` verdict |
|---|---|---|
| `0023DB21…` goodware | must_not_flag | `clean_static` @ conf 1.0 ✓ |
| `0000689b…` unpacked malware | observe only | `clean_static` @ 1.0 ✓ (correct semantics) |
| `0000237117…` packed malware | expect_flag Secapk | `packed_known(Bangcle/SecNeo)` @ 0.95 — H1+H2+H6 fired, payload isolated ✓ |

Also working:
- **Static pipeline end-to-end** (`triage` → `dissect` → `emulate`) on goodware:
  clean verdicts at every stage, no fabricated payload recovery.
- The Unicorn JNI emulation stack defeated the XOR unpacker and produced the
  stage-2 DEX plus full crypto intel (`analysis/recovered/RTO_INTEL.md`).

**Tooling is not the problem.**

## 3. The core blocker

The stage-2 DEX computes its AES key as `SHA-256(pre-image)` where the pre-image
is derived from **live device state** (candidates: `ANDROID_ID`, build fields,
similar). Two complications:

1. Guessing fails: early static attempts were polluted by our own
   reflection-mock artifacts (`sha256(b"SHA-1")`, `sha256("")`); neither
   candidate decrypted to valid PK/dex magic.
2. Therefore we must *observe* key material at creation time — hooking
   `javax.crypto.spec.SecretKeySpec.<init>` / `IvParameterSpec.<init>` inside a
   real Android process exactly once (~15 min of work once any runtime exists),
   then decrypting `myg0N` offline in Python.

## 4. Why Tier-5 (Waydroid in this Kali VM) failed

Each fix unmasked another layer; removed entirely afterwards.

| # | Failure | Resolution |
|---|---|---|
| L0 | Binder kernel module not loaded at boot despite GRUB cmdline | Fixed: modprobe + `/etc/{modules-load.d,modprobe.d}` |
| L1 | VMware `vmwgfx` + forced GBM/MESA gralloc → SurfaceFlinger crash-loop ("Invalid handle") → boot never completed | Fixed: SwiftShader + default gralloc; root cause was Waydroid only blacklisting NVIDIA in `unsupported = ["nvidia"]`; fix via `waydroid_base.prop` (regenerated per boot) |
| L2 | Container auto-froze whenever idle mid-flow (freeze-thaw killed DHCP & processes) | Patched `freeze()` to no-op in container_manager.py |
| L3 | Networking black hole: DHCP lease never renewed post-churn; `/proc/sys/net/ipv4` missing inside netns; ARP requests arrived but were never answered even with static IPs and permanent host ARP entries | Unfixable in reasonable time — final straw |
| Meta | Headless CLI-only usage fights the tool's design assumptions at every step | Full removal |

Environment note: VM is Kali on VMware SVGA II (`vmwgfx`), no nested
virtualization enabled (`no /dev/kvm`, no vmx/svm flags).

## 5. Cleanup state (post-teardown)

Removed: waydroid, weston, lxc, adb, dnsmasq + 55 autoremoved deps,
all waydroid state dirs, frida-server binary, frida venv, hook scripts,
askpass helper.
Residue: `binder_linux` module is `[permanent]` — inert char nodes until next
reboot clears them.

## 6. Current position

Zero Android runtime available. Entire problem reduces to:

> **We have nowhere to execute Android code yet.**

## 7. Paths forward

- **A (recommended):** Enable *"Virtualize Intel VT-x/EPT"* for this VM in the
  VMware host settings → reboot VM → stand up stock Android Emulator AVD under
  KVM (~10 min). `adb root` makes ABI spoofing trivial; frida flow standard;
  reusable for AC4/M4 generalization later.
- **B (zero host changes):** Same AVD purely emulated (QEMU TCG): boots 10–20
  min, sluggish runtime, but fully self-contained; one-shot capture realistic.
- **C (free parallel track):** Read `analysis/recovered/stage2_jadx/` sources to
  identify exact prop fields feeding SHA-256. If it uses the classic
  emulator-default `ANDROID_ID` (`9774d56d682e549c`), B collapses into an
  offline decrypt without any emulator at all.

**Suggested order:** start C immediately; user decides between A and B.

---
*Authored at session 2026-08-27 after A/B pipeline validation.*
