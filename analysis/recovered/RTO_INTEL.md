# RTO.apk — decrypted-layer intelligence (static oracle, no device)

## SOLVED 2026-08-27: myg0N AES key derivation (was the Tier-5 blocker)

Oracle instrumentation (deep-run + heap scan) exposed the exact recipe:

```
base   = "myg0Nbootstrap.dex".substring(0,5)      # -> "myg0N"
preimg = base + "2"                               # -> "myg0N2"   (19B decoy 'dex2' string was a mock artifact)
KEY    = Arrays.copyOf( SHA-1 (preimg), 16 )      # AES-128 key
IV     = Arrays.copyOf( SHA-256(preimg), 16 )
Cipher AES/CBC/PKCS5Padding (CipherInputStream over assets/myg0N)
```

- key hex `6eada2ac127d60e3c17e4940981c5bc6` = sha1("myg0N2")[:16]
- iv  hex `d0045d33d393892263a7b43ccac6e578` = sha256("myg0N2")[:16]
- Decryption verified: plaintext = PK\\x03\\x04 ZIP containing the full payload kit.

## Recovered payload kit (analysis/recovered/myg0N_payload/)

| file | size | note |
|---|---|---|
| installer.dex | 201,330 B | nested ZIP -> classes.dex (final stage, dex 035, sha256 2735c50f…) |
| bootstrap.dex | 13,184 B | dex 035, sha256 35b48528… |
| payload_split0.apk / 1 / 2 | 1.5 MB / 3.7 MB / 245 KB | split-APK payload parts |
| install_library.zip | 2.6 MB | native installer library |
| images.zip | 737 KB | resources |
| payload_config.json | — | splits list, subscriptionEndMillis=1782968017708, MAC=1YNvFYz2Q8RhDbm4gbUVsg== |
| miner_config.json | — | splits=["myg0Nminer.apk"], MAC=eVAmHju3UqrVWR56gOMaUQ== |
| miner.apk | 0 B | placeholder (miner split fetched at runtime) |

## AC4 — VERIFIED 2026-08-27 (evidence: analysis/ac4/)

Same pipeline (`scripts/forensic_pipeline.py`, stages 1–2):

| input | classification | stage-1 verdict | notes |
|---|---|---|---|
| `RTO.apk` (packed shell) | **benign** (risk 2) | is_malicious=False | "no YARA matches, no suspicious APIs" — packer hides everything |
| `myg0N_payload/payload_split1.apk` (recovered) | **malicious** | is_malicious=True conf=high | YARA hits, MITRE **T1003** (Credential Dumping), **T1005** (Data from Local System), FP-likelihood low |

Verdict flips away from confident-benign toward GT malware label once the
decrypted artifacts are analyzed → **AC4 satisfied**.

## Unpacking chain (confirmed by emulation)
stub dex -> loadLibrary("strangulation")
        -> native XOR loops decrypt .data config strings (~8.5 KB, 224 strings)
        -> base64 blob (.data:0x151c60, 4440 chars) = stage-2 DEX
        -> stage-2 "AccelerometerEventListener" decoy class
        -> AES/CBC/PKCS5; KEY=sha1("myg0N2")[:16], IV=sha256("myg0N2")[:16] (SOLVED)
        -> AssetManager.open("myg0N") -> CipherInputStream
        -> ZipInputStream("myg0Ninstaller.dex") -> InMemoryDexClassLoader
        -> invokeExternalInit -> com.lqbczc.szubinocgulatizofn.App / .TerminizeReceiver

## Anti-analysis observed
- Build.CPU_ABI == x86/x86_64 check -> decoy path (sandbox exit)
- fake ZIP "encrypted" flag bits 0x2769 in local+central headers
- randomized class/asset/lib names (Dzhugashvili/*, myg0N, libstrangulation)

## Key derivation trace (from Unicorn JNIEnv capture)
- getBytes("myg0Nbootstrap.dex") -> MessageDigest(SHA-1) input candidate
- copyOf(hash,16) -> SecretKeySpec(key,"AES"); IV observed = 16 zero bytes
- NOTE (2026-08-27): superseded — capture was a mock artifact (substring() ignored
  index args, returning the full 19-char string). True pre-image is
  sha1("myg0N2")[:16] — see SOLVED section above; the key IS static.

## Verdict-relevant artifacts
- RTO_recovered.dex = RTO_stage2.dex (sha256 4848633769faeaf9cb3be087308a3f4afb13fd6027b929e371dd2771c3f7bc74)
- Full decompiled sources under jadx_out/
- Manifest: pkg com.lqbczc.szubinocgulatizofn ("Vedic"), FCM receiver ViolinistsReceiver,
  BOOT receiver EphramReceiver, Service TailleurService; QUERY_ALL_PACKAGES + INSTALL perms.
