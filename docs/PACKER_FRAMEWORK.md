# Static Packer Oracle Framework

A reusable, execution-free methodology for recovering Android packer keys and
payloads. Seeded by the RTO.apk / BeatBanker "myg0N" case study (thesis ch. 6).

## Layers

```
Layer 1  classify()         -> which PackerFamily?
Layer 2  extract_kdf_pattern(so) -> KDFScheme (hash, key len, IV rule, cipher)
Layer 3  recover_seed(apk)  -> seed string (asset stem, hardcoded literal, ...)
Layer 4  derive_key(seed)   -> (key, iv) via derive_key()
Layer 5  verify_unpack(pt)  -> Verdict (ZIP / DEX / reject)
```

Layers 4 and 5 are shared (`packers/framework.py`). Only layers 1–3 are
family-specific.

## Adding a new packer

1. Create `packers/<name>.py` subclassing `PackerOracle`.
2. `classify`: structural triage signal (asset names, native lib names, DEX shape).
3. `extract_kdf_pattern`: from the listing walk / JNI trace, fill in a `KDFScheme`
   (`key_hash`, `key_len`, `iv_hash`, `iv_len`, `cipher`, `seed_rule`). If the
   key is runtime-fetched, document that and return the scheme as
   "derived-but-not-satisfiable" — do **not** force a fit.
4. `recover_seed`: apply the family's seed rule (asset-name stem, hardcoded
   literal, DEX string). Return the exact seed string.
5. Decrypt your container asset, then confirm with `oracle.verify_unpack`
   (structural: ZIP magic + CRCs, or `dex\n` + size gate). A passing verdict on
   real samples is the acceptance test.

## Scope boundaries

Works when the seed is statically present and the cipher is a standard one
(AES/CBC, etc.). Out of scope: runtime-keyed payloads (e.g. Firebase-fetched
material), custom ciphers, and VM-based bytecode packers (needs device hooks or
ART runtime). Record those outcomes as explicit negative verdicts
(`E-RUNTIME-KEYED`, `E-HARDENED-VM`).

## Reference implementation

`packers/myg0n.py` — RTO.apk / myg0N:

    seed = asset_stem + "2"           # asset "assets/myg0N" -> "myg0N2"
    KEY  = SHA1(seed)[:16]            # 6eada2ac127d60e3c17e4940981c5bc6
    IV   = SHA256(seed)[:16]          # d0045d33d393892263a7b43ccac6e578
    AES/CBC/PKCS5Padding -> assets/myg0N -> ZIP

## Tests

    pytest tests/test_framework.py

Covers KDF derivation against the captured RTO ground truth, ZIP/DEX
validators, entropy gates, and a full end-to-end unpack of `RTO.apk`
(skipped if the sample is absent).
