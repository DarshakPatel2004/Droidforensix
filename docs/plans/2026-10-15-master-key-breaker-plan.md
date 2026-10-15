# Master Key Breaker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `packers/breaker/` + `scripts/breaker.py` — a budgeted, self-validating, provider-based engine that recovers encrypted APK payloads whose keys are statically derivable, with typed honest misses.

**Architecture:** A package with four focused modules (`blobs` = what gets attacked, `seeds` = candidate seed material, `schemes` = KDF/cipher enumeration, `engine` = search + validation + outputs) plus a thin CLI that batch-runs a folder and writes `hit.json` / `coverage.json` / `summary.csv`. Priors (known-family recipes) run first; a bounded matrix sweeps after.

**Tech Stack:** Python 3.13 (repo `.venv`), pycryptodome (`Crypto.Cipher.AES`, matching `scripts/unpack.py`), stdlib `zipfile`/`hashlib`/`zlib`/`struct`/`json`, pytest. No new dependencies, no network.

**Spec:** `docs/plans/specs/2026-10-15-master-key-breaker-design.md` (read it — the plan argues from it)

## Global Constraints

- No new dependencies. Imports: `from Crypto.Cipher import AES` (pycryptodome, already pinned). Never import `Cryptodome` (only `analysis/step20_payload_kdf_crack.py` uses it).
- Reuse `packers/framework.py`: `derive_key(seed: str, scheme: KDFScheme) -> tuple[bytes, bytes]` (iv `None` → `b""`), `validate_zip(data) -> tuple[bool, str|dict]` (strict: magic + `ZipFile` + `testzip()`), `validate_dex(data) -> bool` (`dex\n` + len > 112), `shannon_entropy(data) -> float`.
- Untouched in this effort: `scripts/unpack.py`, `analysis/step0_master_key.py`, `analysis/step20_payload_kdf_crack.py`, `packers/framework.py`, `packers/myg0n.py`, `packers/__init__.py`.
- Determinism: blobs sorted by `(-len(data), member)`; provider and matrix order pinned below; candidate dedupe key `(cipher, key_bytes, iv_bytes)` applied **before** an attempt is counted; `space_size` counts enumerated (pre-dedupe), `attempts` counts probed (post-dedupe).
- Budget defaults: `--attempts-cap 200000` per blob, `--budget-s 300` per APK, `--depth 3`, `--max-strings 2000`, `--jobs 1`.
- Evidence policy: `key_hex` / `iv_hex` appear **only** in `hit.json`. `coverage.json`, `summary.csv`, and stdout must contain no key material.
- Output root for acceptance runs: `analysis/master_key_breaker/` (added to `.gitignore`, Task 1).
- Run everything through the repo venv: `.venv\Scripts\python.exe -m pytest ...`. Windows: `pathlib` only; corpus paths contain spaces and parentheses.
- Attribution mapping (spec §5): `E-KDF-EXHAUSTED` = provider space fully searched; `E-KDF-BUDGET` = stopped by `--attempts-cap` (`truncation="attempts"`) or `--budget-s` (`truncation="time"`).

## Review Focus

1. **Genuine-ZipCrypto vs lying-flag discrimination** — a member flagged encrypted whose data is actually plain must be read via raw local-header + inflate (`crc32(inflated) == central CRC`); a genuinely ZipCrypto member must be typed `SKIPPED_ZIPCRYPTO`, never attacked. Tests in **Task 3**.
2. **Payloads in DEFLATE members must be inflated before attacking** — attacking the compressed bytes silently misses every such payload. Pinned by the flag-lie e2e test in **Task 3** and the MediaPlayer2 fixture in **Task 6**.
3. **Probe false positives** — 48-byte magic matches that fail strong validation must increment `probe_false_positives` and never appear as hits. Tests in **Task 5** and **Task 6**.
4. **Truncation is not exhaustion** — cap with `--attempts-cap` must produce `E-KDF-BUDGET` with identical `attempts` across runs, never `E-KDF-EXHAUSTED`. Test in **Task 6**.
5. **Numeric stems** — decimal stems must yield `n, n±1, n+0xFFFF, n−0xFFFF, n+0x10000, n&0xFFFFFFFF` masked to signed 64-bit, and LCG must be reachable for them. Tests in **Task 4** and **Task 6**.

---

### Task 1: Package skeleton, output ignore rule, JavaRandom

**Files:**
- Create: `packers/breaker/__init__.py`
- Create: `packers/breaker/schemes.py`
- Modify: `.gitignore` (insert after line 256, `analysis/recovered/`)
- Test: `tests/test_breaker.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `packers.breaker.schemes.JavaRandom(seed_int: int)` with `.next(bits: int) -> int`, `.next_int() -> int`, `.keystream(length: int) -> bytes`; module constants `LCG_MULTIPLIER = 0x5DEECE66D`, `LCG_ADDEND = 0xB`, `LCG_MASK = (1 << 48) - 1`.

- [ ] **Step 1: Write the failing test**

```python
"""Tests for the master key breaker (packers/breaker/)."""
from packers.breaker.schemes import JavaRandom

MEDIAPLAYER2_SEED = 3664888858717910997


class TestJavaRandom:
    def test_jdk_reference_values(self):
        assert JavaRandom(0).next_int() == -1155484576
        assert JavaRandom(42).next_int() == -1170105035

    def test_next_matches_signed_int_bits(self):
        r = JavaRandom(0)
        assert r.next(32) == JavaRandom(0).next_int() & 0xFFFFFFFF

    def test_mediaplayer2_keystream_vector(self):
        # Derived from the shipped sample: asset 3664888858717845462, seed = n + 0xFFFF,
        # keystream = nextInt() as 4-byte little-endian. Verified against the real APK.
        ks = JavaRandom(MEDIAPLAYER2_SEED).keystream(16)
        assert ks == bytes.fromhex("504d43fdabb00fc6c208299d8a4bd69a")

    def test_keystream_prefix_stability(self):
        r = JavaRandom(MEDIAPLAYER2_SEED)
        assert r.keystream(8) == JavaRandom(MEDIAPLAYER2_SEED).keystream(16)[:8]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python.exe -m pytest tests/test_breaker.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'packers.breaker'`

- [ ] **Step 3: Implement**

Add `.gitignore` line `analysis/master_key_breaker/` right after `analysis/recovered/`.
Create `packers/breaker/__init__.py` (package docstring, no re-exports yet).
In `packers/breaker/schemes.py`, implement `JavaRandom` per spec §4.7: constructor scrambles `seed ^ LCG_MULTIPLIER` masked to 48 bits; `next(bits)` advances `(s * LCG_MULTIPLIER + LCG_ADDEND) & LCG_MASK` and returns `s >> (48 - bits)`; `next_int()` returns the signed 32-bit value of `next(32)`; `keystream(length)` concatenates `next(32).to_bytes(4, "little")` truncated to `length`.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv\Scripts\python.exe -m pytest tests/test_breaker.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add .gitignore packers/breaker/__init__.py packers/breaker/schemes.py tests/test_breaker.py
git commit -m "breaker: package skeleton, ignore outputs, JavaRandom with pinned vectors"
```

---

### Task 2: Scheme model, derivations, priors, matrix, cipher layer

**Files:**
- Modify: `packers/breaker/schemes.py`
- Test: `tests/test_breaker.py`

**Interfaces:**
- Consumes: `JavaRandom` (Task 1); `packers.framework.derive_key` / `KDFScheme`.
- Produces (all in `packers/breaker/schemes.py`):
  - `@dataclass(frozen=True) class Scheme` with `seed: str`, `cipher: str`, `key_hash: str = ""`, `key_len: int = 0`, `iv: str = "none"`, `xor_mode: str | None = None`, `provenance: str = ""`. `cipher` ∈ `{"aes-cbc", "aes-ecb", "xor", "rc4", "java-lcg"}`; `iv` ∈ `{"zeros", "none", "sha1", "sha256", "md5", "sha512"}`; `xor_mode` ∈ `{"digest16", "digest", "seed", "byte", None}`.
  - `HASH_ORDER = ("sha1", "sha256", "md5", "sha512")`, `KEY_LENGTHS = (16, 20, 24, 32)`, `IV_ORDER = ("zeros", "sha1", "sha256", "md5", "sha512")`
  - `derive(scheme: Scheme) -> tuple[bytes, bytes]` (key, iv; `"zeros"` → `b"\x00" * 16`, `"none"` → `b""`)
  - `decrypt(scheme: Scheme, data: bytes) -> bytes`
  - `prior_schemes(stem: str) -> list[Scheme]`
  - `matrix_schemes(seed: str, provenance: str) -> Iterator[Scheme]`
  - `single_byte_xor_schemes() -> Iterator[Scheme]`

- [ ] **Step 1: Write the failing tests**

```python
from packers.breaker.schemes import (
    KEY_LENGTHS, Scheme, decrypt, derive, matrix_schemes, prior_schemes,
    single_byte_xor_schemes,
)

RTO_KEY_HEX = "6eada2ac127d60e3c17e4940981c5bc6"  # tests/test_framework.py
RTO_IV_HEX = "d0045d33d393892263a7b43ccac6e578"   # tests/test_framework.py


class TestSchemeModel:
    def test_myg0n_prior_derives_rto_reference_key(self):
        priors = prior_schemes("myg0N")
        assert priors[0].seed == "myg0N2"
        key, iv = derive(priors[0])
        assert key.hex() == RTO_KEY_HEX and iv.hex() == RTO_IV_HEX

    def test_prior_order_covers_all_known_families(self):
        provs = [s.provenance for s in prior_schemes("UZrF0u")]
        assert provs[0] == "prior:myg0n" and "prior:gen2-zero-iv" in provs
        assert "prior:step20-matrix" in provs and "prior:rto-substring" in provs

    def test_rto_substring_prior_is_capped(self):
        # window count for literal "UZrF0ubootstrap.dex" (len 20) is 1540
        assert len([s for s in prior_schemes("UZrF0u") if s.provenance == "prior:rto-substring"]) == 1540
        assert not [s for s in prior_schemes("x" * 40) if s.provenance == "prior:rto-substring"]

    def test_matrix_count_is_pinned(self):
        assert len(list(matrix_schemes("seed", "test"))) == 79

    def test_matrix_uses_framework_key_truncation_rules(self):
        schemes = list(matrix_schemes("seed", "test"))
        md5_lens = {s.key_len for s in schemes if s.key_hash == "md5"}
        assert md5_lens == {16}   # md5 digest is 16 bytes
        assert {s.key_len for s in schemes if s.key_hash == "sha256"} == set(KEY_LENGTHS)

    def test_single_byte_xor_is_256_seed_independent_candidates(self):
        schemes = list(single_byte_xor_schemes())
        assert len(schemes) == 256
        assert all(s.cipher == "xor" and s.xor_mode == "byte" for s in schemes)


def _rc4_reference(key: bytes, data: bytes) -> bytes:
    """Independent pure-Python RC4 (KSA + PRGA), used only to cross-check decrypt()."""
    s = list(range(256)); j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray(); i = j = 0
    for byte in data:
        i = (i + 1) & 0xFF; j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(byte ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


class TestCipherLayer:
    def test_aes_cbc_roundtrip(self):
        from Crypto.Cipher import AES
        scheme = Scheme(seed="s", cipher="aes-cbc", key_hash="sha1", key_len=16, iv="sha256")
        key, iv = derive(scheme)
        pt = b"PK\x03\x04" + bytes(range(44))
        assert decrypt(scheme, AES.new(key, AES.MODE_CBC, iv).encrypt(pt)) == pt

    def test_aes_ecb_roundtrip(self):
        from Crypto.Cipher import AES
        scheme = Scheme(seed="s", cipher="aes-ecb", key_hash="sha256", key_len=32)
        key, _ = derive(scheme)
        pt = b"PK\x03\x04" + bytes(range(44))
        assert decrypt(scheme, AES.new(key, AES.MODE_ECB).encrypt(pt)) == pt

    def test_xor_byte_mode_roundtrip(self):
        scheme = Scheme(seed="7", cipher="xor", xor_mode="byte")
        pt = b"PK\x03\x04" + b"\xaa" * 12
        assert decrypt(scheme, bytes(b ^ 7 for b in pt)) == pt

    def test_xor_digest_and_seed_modes_roundtrip(self):
        for scheme in (
            Scheme(seed="s", cipher="xor", key_hash="sha1", key_len=16, xor_mode="digest16"),
            Scheme(seed="s", cipher="xor", key_hash="sha1", key_len=16, xor_mode="digest"),
            Scheme(seed="s", cipher="xor", xor_mode="seed"),
        ):
            key, _ = derive(scheme)
            pt = b"PK\x03\x04" + b"\x11" * 28
            assert decrypt(scheme, bytes(b ^ key[i % len(key)] for i, b in enumerate(pt))) == pt

    def test_rc4_roundtrip(self):
        scheme = Scheme(seed="s", cipher="rc4", key_hash="sha1", key_len=16)
        key, _ = derive(scheme)
        pt = b"PK\x03\x04" + b"\x11" * 28
        assert decrypt(scheme, _rc4_reference(key, pt)) == pt

    def test_java_lcg_roundtrip_uses_verified_convention(self):
        scheme = Scheme(seed=str(MEDIAPLAYER2_SEED), cipher="java-lcg")
        pt = b"PK\x03\x04" + bytes(range(60))
        ct = bytes(a ^ b for a, b in zip(pt, JavaRandom(MEDIAPLAYER2_SEED).keystream(len(pt))))
        assert decrypt(scheme, ct) == pt
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv\Scripts\python.exe -m pytest tests/test_breaker.py -v`
Expected: FAIL — `Scheme` / `derive` / `prior_schemes` not defined.

- [ ] **Step 3: Implement**

- `derive`: map `Scheme` → `KDFScheme(key_hash, key_len, iv_hash=None if iv in ("none", "zeros") else iv, iv_len=16)`, call `framework.derive_key(seed, kdf)`; post-process `iv="zeros"` → 16 zero bytes. For `cipher == "xor"`: `xor_mode=="digest16"` → `hashlib.new(key_hash, seed)[:16]`; `"digest"` → full digest; `"seed"` → `seed.encode("utf-8")`; `"byte"` → `bytes([int(seed)])`. For `"rc4"`: digest `[:16]`. For `"java-lcg"`: `int(seed).to_bytes(8, "big")`, iv `b""`.
- `decrypt`: AES-CBC/ECB via `AES.new(...)`; `xor` repeats the derived key; `rc4` = pure-Python KSA/PRGA; `java-lcg` = `JavaRandom(int(seed)).keystream(len(data))` XOR (matches verified MediaPlayer2 vector).
- `prior_schemes(stem)` returns, in this order: `prior:myg0n` (`seed=stem+"2"`, sha1/16, iv sha256); `prior:gen2-zero-iv` (`seed=stem`, sha1/16, zeros); `prior:step20-matrix` (seeds `[stem+"1", stem] + [stem+d for d in "0123456789"]` × variants `[(sha1,sha256),(sha1,zeros),(sha256,zeros),(sha1,sha1)]`, dedupe against earlier priors); `prior:rto-substring` (literal `stem+"bootstrap.dex"`, all `(a,b,c)` windows → `literal[a:b][c:]+"2"` with the myg0N KDF; emits nothing when `len(literal) > 24`).
- `matrix_schemes(seed, provenance)`: for `key_hash` in `HASH_ORDER`, `key_len` in `KEY_LENGTHS` filtered to `<= digest size`: AES-CBC for each `iv` in `IV_ORDER` (55), AES-ECB once per key (11), then XOR (`digest16`, `digest` per hash + `seed` = 9), then RC4 (4).
- `single_byte_xor_schemes()`: 256 schemes, `seed=str(byte)`, `xor_mode="byte"`, `provenance="xor:single-byte"`.
- The `prior:rto-substring` provider emits **every** window, duplicates included (the engine's key-level dedupe removes repeats); it must not dedupe internally, so the window count stays a property of the literal.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python.exe -m pytest tests/test_breaker.py -v`
Expected: PASS (all JavaRandom + scheme + cipher tests)

- [ ] **Step 5: Commit**

```bash
git add packers/breaker/schemes.py tests/test_breaker.py
git commit -m "breaker: scheme model, priors, matrix enumeration, cipher layer"
```

---

### Task 3: Blob collector — filters, flag-lie handling, sniffing

**Files:**
- Create: `packers/breaker/blobs.py`
- Test: `tests/test_breaker.py`

**Interfaces:**
- Consumes: `packers.framework.shannon_entropy`.
- Produces (all in `packers/breaker/blobs.py`):
  - `PLAINTEXT_MAGICS: tuple[tuple[bytes, str], ...]` = `((b"PK\x03\x04", "zip"), (b"dex\n", "dex"), (b"\x7fELF", "elf"), (b"\x1f\x8b", "gzip"), (b"\x00\x01\x00\x00", "ttf"))`
  - `PROBE_MAGICS: tuple[tuple[bytes, str], ...]` = `PLAINTEXT_MAGICS + ((b"{", "json"),)`
  - `SKIP_DIRS = ("res/", "META-INF/", "lib/", "dexopt/")`; `SKIP_EXTENSIONS` = media/font/package/text set (pin at least: `png jpg jpeg gif webp bmp ico mp3 ogg flac m4a wav mp4 3gp ttf otf woff woff2 arsc dex so xml html htm js css txt json properties yml yaml csv md`)
  - `MIN_BLOB_SIZE = 512`
  - `@dataclass(frozen=True) class Blob`: `member: str`, `data: bytes`, `content: str` (`"stored"`|`"inflated"`), `depth: int`
  - `@dataclass class MemberRecord`: `name: str`, `size: int`, `outcome: str`, `depth: int`, `entropy: float`, `detail: str = ""`, `attempts: int = 0`, `space_size: int = 0`, `truncation: str = "none"`, `probe_false_positives: int = 0`
  - `@dataclass class BlobCollection`: `blobs: list[Blob]`, `records: list[MemberRecord]`, `plaintext: list[tuple[str, bytes]]`, `recurse: list[tuple[str, bytes]]`, `members_total: int`, `members_ignored_dirs: int`
  - `collect_from_zip(data: bytes, *, depth: int, prefix: str = "") -> BlobCollection`
  - `collect_apk(path) -> BlobCollection` (= `collect_from_zip(path.read_bytes(), depth=0)`)
  - Module outcome constants: `RECOVERED`, `E_KDF_EXHAUSTED`, `E_KDF_BUDGET`, `SKIPPED_PLAINTEXT`, `SKIPPED_ZIPCRYPTO`, `SKIPPED_FILTER`, `SKIPPED_SIZE` (module-level strings, also re-exported by `engine`).

- [ ] **Step 1: Write the failing tests**

```python
import struct
import zipfile

from packers.breaker.blobs import (
    BlobCollection, collect_apk, collect_from_zip,
    E_KDF_EXHAUSTED, SKIPPED_PLAINTEXT, SKIPPED_SIZE, SKIPPED_ZIPCRYPTO,
)


def _make_apk(path, members: dict) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)


def _set_encrypted_flag(path, member: str) -> None:
    """Flip bit 0 of the flag field in both the local header and central directory."""
    raw = bytearray(path.read_bytes())
    with zipfile.ZipFile(path) as zf:
        lfh = zf.getinfo(member).header_offset
    raw[lfh + 6] |= 0x1
    cd = raw.rindex(b"PK\x01\x02")
    raw[cd + 8] |= 0x1
    path.write_bytes(raw)


class TestBlobCollector:
    def test_filters_and_ordering(self, tmp_path):
        apk = tmp_path / "a.apk"
        _make_apk(apk, {
            "assets/small": b"\x00" * 100,        # SKIPPED_SIZE
            "assets/big": b"\xab" * 4096,         # attacked
            "assets/bigger": b"\xcd" * 8192,      # attacked, ordered first
            "assets/icon.png": b"\x89PNG" + b"\x00" * 600,  # SKIPPED_FILTER
            "res/raw/thing": b"\xef" * 900,       # ignored dir (counted, no row)
            "classes.dex": b"dex\n035\x00" + b"\x00" * 900,  # SKIPPED_FILTER (.dex)
        })
        c = collect_apk(apk)
        assert [b.member for b in c.blobs] == ["assets/bigger", "assets/big"]
        outcomes = {r.name: r.outcome for r in c.records}
        assert outcomes["assets/small"] == SKIPPED_SIZE
        assert outcomes["assets/icon.png"] == "SKIPPED_FILTER"
        assert c.members_ignored_dirs == 1

    def test_plaintext_magic_member_is_skipped_and_offered_for_recursion(self, tmp_path):
        apk = tmp_path / "b.apk"
        inner = tmp_path / "inner.bin"
        _make_apk(inner, {"assets/x": b"\xaa" * 1024})
        _make_apk(apk, {"assets/nested": inner.read_bytes(), "assets/ct": b"\xbb" * 1024})
        c = collect_apk(apk)
        assert {r.name: r.outcome for r in c.records}["assets/nested"] == SKIPPED_PLAINTEXT
        assert [n for n, _ in c.recurse] == ["assets/nested"]
        assert [b.member for b in c.blobs] == ["assets/ct"]

    def test_flag_lie_deflate_member_is_read_as_inflated_content(self, tmp_path):
        apk = tmp_path / "c.apk"
        _make_apk(apk, {"assets/payload": b"PK\x03\x04" + b"\x42" * 2000})
        _set_encrypted_flag(apk, "assets/payload")
        with zipfile.ZipFile(apk) as zf:
            try:
                zf.read("assets/payload")
                raise AssertionError("zipfile should refuse flagged members")
            except RuntimeError:
                pass
        c = collect_apk(apk)
        blob = c.blobs[0]
        assert blob.content == "inflated" and blob.data.startswith(b"PK\x03\x04")

    def test_genuine_zipcrypto_member_is_typed_not_attacked(self, tmp_path):
        apk = tmp_path / "d.apk"
        _make_apk(apk, {"assets/real": b"\x99" * 1024})
        _set_encrypted_flag(apk, "assets/real")
        # Real ZipCrypto members carry a 12-byte encryption header, so the stored stream no
        # longer inflates. Overwrite its first 12 bytes with zeros (length unchanged, so the
        # central directory stays valid) to reproduce that deterministically.
        raw = bytearray(apk.read_bytes())
        with zipfile.ZipFile(apk) as zf:
            info = zf.getinfo("assets/real")
        name_len, extra_len = struct.unpack("<HH", raw[info.header_offset + 26:info.header_offset + 30])
        data_at = info.header_offset + 30 + name_len + extra_len
        raw[data_at:data_at + 12] = b"\x00" * 12
        apk.write_bytes(bytes(raw))
        c = collect_apk(apk)
        assert c.blobs == []
        assert {r.name: r.outcome for r in c.records}["assets/real"] == SKIPPED_ZIPCRYPTO

    def test_stored_flag_lie_member_is_kept(self, tmp_path):
        apk = tmp_path / "e.apk"
        with zipfile.ZipFile(apk, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("assets/plainstored", b"\x7f" * 1024)
        _set_encrypted_flag(apk, "assets/plainstored")
        c = collect_apk(apk)
        assert c.blobs and c.blobs[0].content == "stored"

    def test_collect_from_zip_prefixes_nested_paths(self, tmp_path):
        inner = tmp_path / "kit.zip"
        _make_apk(inner, {"assets/deep": b"\x01" * 700})
        c = collect_from_zip(inner.read_bytes(), depth=1, prefix="kit.zip!")
        assert c.blobs[0].member == "kit.zip!assets/deep" and c.blobs[0].depth == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv\Scripts\python.exe -m pytest tests/test_breaker.py -v -k BlobCollector`
Expected: FAIL — `packers.breaker.blobs` does not exist.

- [ ] **Step 3: Implement**

Walk `zipfile.ZipFile(io.BytesIO(data)).infolist()`; for each member decide: ignored dir (count in `members_ignored_dirs`, no row) / row + optional blob. Member content rule: `flag_bits & 0x1` → parse the local header from the raw bytes (signature check, `fnlen`/`exlen` from bytes 26–30), slice `compress_size` bytes, then method 8 → `zlib.decompressobj(-15)`; if inflate raises or `zlib.crc32(content) != info.CRC` → row `SKIPPED_ZIPCRYPTO` with detail; else content accepted (`"inflated"`). Method 0 → slice is content (`"stored"`) accepted only when `crc32 == info.CRC`, else `SKIPPED_ZIPCRYPTO`. No flag → `zipfile.read(name)` (`"inflated"` when `compress_type != 0`, else `"stored"`); unreadable member → `SKIPPED_ZIPCRYPTO`. Then, in this fixed order: extension in `SKIP_EXTENSIONS` → row `SKIPPED_FILTER`; size `< MIN_BLOB_SIZE` → row `SKIPPED_SIZE`; plaintext magic (`PLAINTEXT_MAGICS`) → row `SKIPPED_PLAINTEXT` plus append to `plaintext` (and to `recurse` when the magic is `zip`); else append `Blob` + row `"pending"` (engine overwrites with the final outcome) and record `entropy=shannon_entropy(data[:65536])`. Sort `blobs` by `(-len(data), member)` and records by name. Row inclusion rule: `name.startswith("assets/")` or `"/" not in name` or flagged member.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python.exe -m pytest tests/test_breaker.py -v -k BlobCollector`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add packers/breaker/blobs.py tests/test_breaker.py
git commit -m "breaker: blob collector with flag-lie and ZipCrypto discrimination"
```

---

### Task 4: Seed providers — name variants, mined strings, extra seeds, numeric deltas

**Files:**
- Create: `packers/breaker/seeds.py`
- Test: `tests/test_breaker.py`

**Interfaces:**
- Consumes: `blobs.BlobCollection`.
- Produces (all in `packers/breaker/seeds.py`):
  - `MAX_STRINGS_DEFAULT = 2000`
  - `@dataclass(frozen=True) class SeedCandidate`: `material: str`, `provenance: str`, `numeric: bool = False`
  - `mine_strings(data: bytes, *, min_len: int = 4, max_len: int = 96) -> list[bytes]`
  - `name_variants(stem: str) -> list[SeedCandidate]`
  - `numeric_candidates(stem: str) -> list[SeedCandidate]`
  - `load_extra_seeds(path) -> list[SeedCandidate]`
  - `@dataclass class SeedPlan`: `mined: list[SeedCandidate]`, `extra: list[SeedCandidate]`, `add_strings(self, data: bytes, *, cap: int = MAX_STRINGS_DEFAULT) -> None`
  - `plan_from_collection(collection, *, extra_path=None, max_strings=MAX_STRINGS_DEFAULT) -> SeedPlan`

- [ ] **Step 1: Write the failing tests**

```python
import json

from packers.breaker.seeds import (
    SeedCandidate, load_extra_seeds, mine_strings, name_variants,
    numeric_candidates, plan_from_collection,
)

MEDIAPLAYER2_STEM = "3664888858717845462"


class TestSeedProviders:
    def test_mine_strings_dedupes_orders_and_bounds(self):
        data = b"\x00hello\x00world\x00hello\x00ab\x00" + b"\xff" * 200
        assert mine_strings(data) == [b"hello", b"world"]  # 2-char run dropped
        assert mine_strings(b"\x00" + b"y" * 200 + b"\x00") == []  # run longer than max_len dropped
        assert mine_strings(b"\x00password123\x00", min_len=4) == [b"password123"]

    def test_name_variants(self):
        provs = {c.provenance for c in name_variants("AbC")}
        assert {"name:stem", "name:lower", "name:upper", "name:+0", "name:+9"} <= provs
        assert SeedCandidate("AbC", "name:stem") in name_variants("AbC")

    def test_numeric_candidates_include_verified_mediaplayer2_delta(self):
        vals = {c.material: c.provenance for c in numeric_candidates(MEDIAPLAYER2_STEM)}
        assert vals["3664888858717910997"] == "numeric:+0xffff"
        assert vals[MEDIAPLAYER2_STEM] == "numeric:n"
        assert all(c.numeric for c in numeric_candidates(MEDIAPLAYER2_STEM))
        assert numeric_candidates("not-a-number") == []

    def test_numeric_candidates_mask_to_signed_64(self):
        v = {c.material for c in numeric_candidates("18446744073709551615")}
        assert "-1" in v  # 2**64-1 masked to signed 64-bit

    def test_load_extra_seeds_all_three_formats(self, tmp_path):
        a = tmp_path / "a.json"; a.write_text(json.dumps(["seedA", "seedB"]))
        b = tmp_path / "b.json"; b.write_text(json.dumps({"seeds": ["seedC"]}))
        c = tmp_path / "c.json"
        c.write_text(json.dumps({"key_log": [["getBytes", "seedD"], ["digest", "seedE"], ["junk", 5]]}))
        assert [s.material for s in load_extra_seeds(a)] == ["seedA", "seedB"]
        assert [s.material for s in load_extra_seeds(b)] == ["seedC"]
        assert [s.material for s in load_extra_seeds(c)] == ["seedD", "seedE"]
        assert all(s.provenance.startswith("extra") for s in load_extra_seeds(c))

    def test_plan_mines_collection_plaintext_with_cap(self, tmp_path):
        import zipfile
        apk = tmp_path / "p.apk"
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" + b"thePassword123" + b"\x00" * 100)
            zf.writestr("assets/ct", b"\xcc" * 1024)
        from packers.breaker.blobs import collect_apk
        plan = plan_from_collection(collect_apk(apk), max_strings=10)
        assert any(s.material == "thePassword123" for s in plan.mined)
        assert len(plan.mined) <= 10

    def test_add_strings_respects_cap(self):
        from packers.breaker.seeds import SeedPlan
        plan = SeedPlan(mined=[], extra=[])
        plan.add_strings(b"\x00aaa\x00bbb\x00ccc\x00", cap=2)
        assert len(plan.mined) == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv\Scripts\python.exe -m pytest tests/test_breaker.py -v -k SeedProviders`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement**

- `mine_strings`: `re.finditer(rb"[\x20-\x7e]{4,}", data)` to get maximal printable runs, keep runs with `len <= max_len`, decode latin-1, ordered dedupe.
- `name_variants`: `stem`, `stem.lower()`, `stem.upper()`, `stem + d for d in 0..9` (provenance `name:+<d>`).
- `numeric_candidates`: `[]` unless `stem.isdigit()`; variants `n, n+1, n-1, n+0xFFFF, n-0xFFFF, n+0x10000, n & 0xFFFFFFFF`, each masked through `_signed64(v)` then `str()`; provenance `numeric:n`, `numeric:+1`, `numeric:-1`, `numeric:+0xffff`, `numeric:-0xffff`, `numeric:+0x10000`, `numeric:u32`; ordered dedupe.
- `load_extra_seeds`: accept a JSON list of strings, `{"seeds": [...]}`, or `{"key_log": [[kind, value], ...]}` (keep `kind in ("getBytes", "digest")`; `value` str or list-of-int bytes → utf-8 decode; skip anything else).
- `SeedPlan.add_strings`: mine and append unseen candidates until `cap`.
- `plan_from_collection`: mine every `(name, data)` in `collection.plaintext` (cap = `max_strings`) plus `load_extra_seeds(extra_path)` when given.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python.exe -m pytest tests/test_breaker.py -v -k SeedProviders`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add packers/breaker/seeds.py tests/test_breaker.py
git commit -m "breaker: seed providers (name, mined, extra, numeric deltas)"
```

---

### Task 5: Validation layer — probe, strong evidence, false-positive accounting

**Files:**
- Create: `packers/breaker/engine.py` (validation parts only; search loop lands in Task 6)
- Test: `tests/test_breaker.py`

**Interfaces:**
- Consumes: `schemes.decrypt` / `Scheme`; `blobs.PROBE_MAGICS`; `framework.validate_zip` / `validate_dex`.
- Produces (in `packers/breaker/engine.py`):
  - `PROBE_LEN = 48`
  - `@dataclass(frozen=True) class Validation`: `kind: str`, `evidence: str` (`evidence` ∈ `{"zip-strict", "zip-eocd", "dex-header", "dex-magic", "gzip", "elf", "json", "ttf-magic"}`)
  - `probe_matches(scheme: Scheme, data: bytes) -> bool`
  - `validate_payload(data: bytes) -> Validation | None`

- [ ] **Step 1: Write the failing tests**

```python
import io
import zipfile

from packers.breaker.engine import probe_matches, validate_payload
from packers.breaker.schemes import Scheme, decrypt, derive


def _encrypt_scheme(scheme, plaintext: bytes) -> bytes:
    """Encrypt with the scheme's own key/iv — the inverse of the engine's decrypt()."""
    from Crypto.Cipher import AES
    key, iv = derive(scheme)
    pad = 16 - len(plaintext) % 16
    padded = plaintext + bytes([pad]) * pad
    if scheme.cipher == "aes-ecb":
        return AES.new(key, AES.MODE_ECB).encrypt(padded)
    return AES.new(key, AES.MODE_CBC, iv).encrypt(padded)


class TestValidation:
    def test_probe_uses_16_aligned_prefix(self):
        scheme = Scheme(seed="s", cipher="aes-cbc", key_hash="sha1", key_len=16, iv="zeros")
        pt = b"PK\x03\x04" + b"\x00" * 44
        assert probe_matches(scheme, _encrypt_scheme(scheme, pt))
        assert not probe_matches(scheme, b"\x00" * 48)

    def test_probe_false_positive_is_detectable(self):
        # PK prefix in the first block, garbage after: probe matches, strong validation must not
        scheme = Scheme(seed="s", cipher="aes-cbc", key_hash="sha1", key_len=16, iv="zeros")
        ct = _encrypt_scheme(scheme, b"PK\x03\x04" + b"\x00" * 44 + b"\x77" * 4096)
        assert probe_matches(scheme, ct)
        assert validate_payload(decrypt(scheme, ct)) is None

    def test_zip_strict_evidence(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 200)
        v = validate_payload(buf.getvalue())
        assert v is not None and v.kind == "zip" and v.evidence == "zip-strict"

    def test_zip_eocd_fallback_evidence(self):
        payload = b"PK\x03\x04" + b"\x00" * 200 + b"PK\x05\x06" + b"\x00" * 18
        v = validate_payload(payload)
        assert v is not None and v.evidence == "zip-eocd"

    def test_dex_header_evidence_upgrades_magic(self):
        body = b"dex\n035\x00" + b"\x00" * 24 + (400).to_bytes(4, "little") + b"\x00" * (400 - 36)
        assert validate_payload(body).evidence == "dex-header"
        assert validate_payload(b"dex\n035\x00" + b"\x00" * 300).evidence == "dex-magic"

    def test_gzip_and_elf_evidence(self):
        import gzip
        assert validate_payload(gzip.compress(b"x" * 100)).evidence == "gzip"
        assert validate_payload(b"\x7fELF\x02\x01" + b"\x00" * 100).evidence == "elf"

    def test_plaintext_garbage_is_not_validated(self):
        assert validate_payload(b"\x9e\x11\x33" * 100) is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv\Scripts\python.exe -m pytest tests/test_breaker.py -v -k Validation`
Expected: FAIL — `packers.breaker.engine` does not exist.

- [ ] **Step 3: Implement**

`probe_matches`: decrypt the first `PROBE_LEN` bytes when `len(data) >= PROBE_LEN`, else the largest 16-aligned prefix `>= 16`; return True when the plaintext starts with any `PROBE_MAGICS` signature. `validate_payload`: `validate_zip` → `zip-strict`; else `PK\x03\x04` prefix + `PK\x05\x06` found in `data[-65557:]` → `zip-eocd`; `validate_dex` + `struct.unpack("<I", data[32:36])[0] == len(data)` → `dex-header`; `validate_dex` → `dex-magic`; `zlib.decompress(data, 16 + zlib.MAX_WBITS)` OK → `gzip`; ELF magic + `len > 64` + `data[4] in (1, 2)` → `elf`; `data[:1] == b"{"` + `json.loads(data)` OK → `json`; `b"\x00\x01\x00\x00"` → `ttf-magic`; else `None`. No exception may escape.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python.exe -m pytest tests/test_breaker.py -v -k Validation`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add packers/breaker/engine.py tests/test_breaker.py
git commit -m "breaker: two-stage validation with honest evidence levels"
```

---

### Task 6: Search engine — attack loop, budgets, outputs (no recursion yet)

**Files:**
- Modify: `packers/breaker/engine.py`
- Modify: `packers/breaker/__init__.py`
- Test: `tests/test_breaker.py`

**Interfaces:**
- Consumes: everything from Tasks 1–5.
- Produces (in `packers/breaker/engine.py`, re-exported from `packers/breaker/__init__.py`):
  - `@dataclass class Hit`: `member: str`, `content: str`, `seed: str`, `provenance: list[str]`, `scheme: dict`, `key_sha256: str`, `key_hex: str`, `iv_hex: str | None`, `payload_sha256: str`, `validation: str`, `artifacts: list[dict]`, `artifacts_total: int`, `children: list[Hit]`
  - `@dataclass class ApkResult`: `apk: str`, `sha256: str`, `hits: list[Hit]`, `members: list[MemberRecord]`, `scheme_count: int`, `wall_s: float`, `outcome: str`, `ciphertext_members: int`, `attempts_total: int`, `truncated: str`
  - `break_apk(apk_path, out_dir, *, attempts_cap=200_000, budget_s=300.0, depth=3, seeds_extra=None, max_strings=2000) -> ApkResult`
  - `__init__.py` re-exports: `break_apk`, `ApkResult`, `Hit`, `Blob`, `BlobCollection`, `Scheme`

- [ ] **Step 1: Write the failing tests**

```python
import hashlib
import io
import json
import zipfile
from pathlib import Path

from Crypto.Cipher import AES

from packers.breaker import break_apk
from packers.breaker.blobs import E_KDF_BUDGET, E_KDF_EXHAUSTED, RECOVERED


def _kit_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("bootstrap.dex", b"dex\n035\x00" + b"\x00" * 500)
        zf.writestr("config.json", b"{}")
    return buf.getvalue()


def _encrypt_prior(plaintext: bytes, stem: str) -> bytes:
    seed = (stem + "2").encode()
    key, iv = hashlib.sha1(seed).digest()[:16], hashlib.sha256(seed).digest()[:16]
    pad = 16 - len(plaintext) % 16
    return AES.new(key, AES.MODE_CBC, iv).encrypt(plaintext + bytes([pad]) * pad)


def _write_apk(path: Path, members: dict, method=zipfile.ZIP_DEFLATED) -> Path:
    with zipfile.ZipFile(path, "w", method) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return path


def _write_bytes_zip(members: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


class TestBreakApk:
    def test_recovers_myg0n_prior_and_writes_outputs(self, tmp_path):
        apk = _write_apk(tmp_path / "m.apk", {"assets/UZrF0u": _encrypt_prior(_kit_bytes(), "UZrF0u")},
                         method=zipfile.ZIP_STORED)
        res = break_apk(apk, tmp_path / "out")
        assert res.outcome == RECOVERED and len(res.hits) == 1
        hit = res.hits[0]
        assert hit.member == "assets/UZrF0u" and hit.provenance == ["prior:myg0n"]
        assert hit.validation == "zip-strict" and hit.content == "stored"
        assert hit.artifacts_total == 2
        assert hit.payload_sha256 == hashlib.sha256(_kit_bytes()).hexdigest()
        hit_json = json.loads((tmp_path / "out" / res.sha256[:16] / "hit.json").read_text())
        assert hit_json["hits"][0]["key_hex"] == hit.key_hex        coverage = (tmp_path / "out" / res.sha256[:16] / "coverage.json").read_text()
        assert "key_hex" not in coverage and json.loads(coverage)["scheme_count"] > 0

    def test_recovers_lumolight_zero_iv_prior(self, tmp_path):
        stem = "bhtn0kbg"
        key = hashlib.sha1(stem.encode()).digest()[:16]
        pt = _kit_bytes()
        pad = 16 - len(pt) % 16
        ct = AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(pt + bytes([pad]) * pad)
        apk = _write_apk(tmp_path / "l.apk", {f"assets/sub/{stem}": ct}, method=zipfile.ZIP_STORED)
        res = break_apk(apk, tmp_path / "out")
        assert res.hits[0].provenance == ["prior:gen2-zero-iv"]

    def test_mined_string_seed_is_found(self, tmp_path):
        seed = "thePassword123"
        pt = _kit_bytes()
        key = hashlib.sha1(seed.encode()).digest()[:16]
        pad = 16 - len(pt) % 16
        ct = AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(pt + bytes([pad]) * pad)
        apk = _write_apk(tmp_path / "p.apk", {
            "classes.dex": b"dex\n035\x00" + b"\x00" * 20 + seed.encode() + b"\x00" * 200,
            "assets/pwblob": ct,
        }, method=zipfile.ZIP_STORED)
        res = break_apk(apk, tmp_path / "out")
        assert res.hits and res.hits[0].provenance == ["mined"]

    def test_extra_seeds_file_is_found(self, tmp_path):
        seed = "traceKey42"
        pt = _kit_bytes()
        key = hashlib.sha1(seed.encode()).digest()[:16]
        pad = 16 - len(pt) % 16
        ct = AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(pt + bytes([pad]) * pad)
        extra = tmp_path / "extra.json"
        extra.write_text(json.dumps({"seeds": [seed]}))
        apk = _write_apk(tmp_path / "e.apk", {"assets/traceblob": ct}, method=zipfile.ZIP_STORED)
        res = break_apk(apk, tmp_path / "out", seeds_extra=extra)
        assert res.hits[0].provenance == ["extra"]

    def test_lcg_numeric_delta_recovers_and_is_deterministic(self, tmp_path):
        stem = "123456789012345"
        seed = int(stem) + 0xFFFF
        pt = _kit_bytes()
        from packers.breaker.schemes import JavaRandom
        ks = JavaRandom(seed).keystream(len(pt))
        ct = bytes(a ^ b for a, b in zip(pt, ks))
        apk = _write_apk(tmp_path / "n.apk", {f"assets/{stem}": ct}, method=zipfile.ZIP_STORED)
        res = break_apk(apk, tmp_path / "out")
        assert res.hits[0].provenance == ["numeric:+0xffff"]
        assert res.hits[0].scheme["cipher"] == "java-lcg"
        res2 = break_apk(apk, tmp_path / "out2")
        assert res2.hits[0].seed == res.hits[0].seed

    def test_attempts_cap_marks_budget_not_exhaustion(self, tmp_path):
        import os
        apk = _write_apk(tmp_path / "x.apk", {"assets/randomblob": os.urandom(2048)}, method=zipfile.ZIP_STORED)
        res = break_apk(apk, tmp_path / "out", attempts_cap=25)
        assert res.outcome == E_KDF_BUDGET
        assert res.members[0].outcome == E_KDF_BUDGET
        assert res.members[0].truncation == "attempts" and res.members[0].attempts == 25
        res2 = break_apk(apk, tmp_path / "out2", attempts_cap=25)
        assert res2.members[0].attempts == 25  # prefix-stable determinism

    def test_runtime_keyed_blob_is_exhausted_not_recovered(self, tmp_path):
        import os
        apk = _write_apk(tmp_path / "y.apk", {"assets/rt": os.urandom(1024)}, method=zipfile.ZIP_STORED)
        res = break_apk(apk, tmp_path / "out")
        assert res.hits == [] and res.outcome in (E_KDF_EXHAUSTED, E_KDF_BUDGET)

    def test_probe_false_positive_is_counted_not_reported(self, tmp_path):
        scheme_pt = b"PK\x03\x04" + b"\x00" * 44 + b"\x77" * 4096  # PK prefix, invalid zip
        apk = _write_apk(tmp_path / "fp.apk", {"assets/fpblob": _encrypt_prior(scheme_pt, "fpblob")},
                         method=zipfile.ZIP_STORED)
        res = break_apk(apk, tmp_path / "out")
        assert res.hits == []
        assert res.members[0].probe_false_positives >= 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv\Scripts\python.exe -m pytest tests/test_breaker.py -v -k BreakApk`
Expected: FAIL — `break_apk` not defined.

- [ ] **Step 3: Implement**

`break_apk`: read bytes, `sha256`; `collect_apk`; `plan_from_collection`; attack each blob in order. Candidate stream per blob: `prior_schemes(stem)` → `matrix_schemes` × `name_variants(stem)` → `matrix_schemes` × `plan.mined` → `matrix_schemes` × `plan.extra` → `single_byte_xor_schemes()` → LCG (`Scheme(seed=c.material, cipher="java-lcg", provenance=c.provenance)` for numeric candidates). `stem = member.rsplit("!", 1)[-1].rsplit("/", 1)[-1]`. Per candidate: derive key/iv; skip if `(cipher, key, iv)` seen; count `space_size` at enumeration and `attempts` at probe; check the wall clock each attempt (set `truncation="time"`, stop); stop at `attempts_cap` (`truncation="attempts"`). `probe_matches` → `validate_payload(decrypt(scheme, blob.data))`; on success build `Hit` (`payload_sha256` = sha256 of the full decrypted payload; artifacts = first 50 file members as `{"file", "sha256", "size"}`; `artifacts_total`; `key_sha256=sha256(key).hexdigest()`; LCG key bytes = `int(seed).to_bytes(8,"big")`), mark `RECOVERED`, stop the blob. Probe match without validation → `probe_false_positives += 1`. Record `E_KDF_EXHAUSTED` when the stream drains, `E_KDF_BUDGET` on truncation; on time truncation, remaining blobs get `E_KDF_BUDGET` with `attempts=0`. `scheme_count` = total candidates enumerated. Write `hit.json` (`{"apk", "sha256", "hits": [...]}`) and `coverage.json` (`{"apk", "sha256", "wall_s", "scheme_count", "members_total", "members_ignored_dirs", "members": [rows]}`) under `out_dir / sha256[:16] /`. `outcome` = `RECOVERED` if any hit, else `E_KDF_BUDGET` if truncated, else `E_KDF_EXHAUSTED`. Update `__init__.py` re-exports.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python.exe -m pytest tests/test_breaker.py -v -k BreakApk`
Expected: PASS (8 tests)

- [ ] **Step 5: Commit**

```bash
git add packers/breaker/engine.py packers/breaker/__init__.py tests/test_breaker.py
git commit -m "breaker: search engine with budgets, typed misses, and hit/coverage outputs"
```

---

### Task 7: Recursion into recovered containers + decrypted-string harvest

**Files:**
- Modify: `packers/breaker/engine.py`
- Test: `tests/test_breaker.py`

**Interfaces:**
- Consumes: Task 6 `break_apk` internals; `blobs.collect_from_zip`; `seeds.SeedPlan.add_strings`.
- Produces: `ApkResult.hits[].children` populated for nested recoveries; recursive collection attacked at `depth + 1` up to `depth` parameter; decrypted plaintext mined into the shared `SeedPlan`.

- [ ] **Step 1: Write the failing tests**

```python
class TestRecursion:
    def test_nested_container_is_attacked_up_to_depth(self, tmp_path):
        inner_pt = _kit_bytes()
        inner_stem = "inner7"
        inner_ct = _encrypt_prior(inner_pt, inner_stem)  # prior:myg0n inside the outer kit
        outer_pt = _write_bytes_zip({"assets/" + inner_stem: inner_ct})
        apk = _write_apk(tmp_path / "r.apk", {"assets/outer": _encrypt_prior(outer_pt, "outer")},
                         method=zipfile.ZIP_STORED)
        res = break_apk(apk, tmp_path / "out", depth=2)
        assert len(res.hits) == 1 and len(res.hits[0].children) == 1
        assert res.hits[0].children[0].member.endswith("assets/inner7")

    def test_depth_one_does_not_recurse(self, tmp_path):
        inner_ct = _encrypt_prior(_kit_bytes(), "inner7")
        outer_pt = _write_bytes_zip({"assets/inner7": inner_ct})
        apk = _write_apk(tmp_path / "r1.apk", {"assets/outer": _encrypt_prior(outer_pt, "outer")},
                         method=zipfile.ZIP_STORED)
        res = break_apk(apk, tmp_path / "out", depth=1)
        assert res.hits and res.hits[0].children == []

    def test_decrypted_strings_enable_sibling_recovery(self, tmp_path):
        # sibling blob keyed by a string that only exists inside the first recovered kit
        secret = "harvestedSecret9"
        sib_key = hashlib.sha1(secret.encode()).digest()[:16]
        sib_pt = _kit_bytes()
        pad = 16 - len(sib_pt) % 16
        sib_ct = AES.new(sib_key, AES.MODE_CBC, bytes(16)).encrypt(sib_pt + bytes([pad]) * pad)
        inner = _write_bytes_zip({"assets/dexish": b"dex\n035\x00" + secret.encode() + b"\x00" * 200})
        apk = _write_apk(tmp_path / "h.apk", {
            "assets/first": _encrypt_prior(inner, "first"),
            "assets/sibling": sib_ct,
        }, method=zipfile.ZIP_STORED)
        res = break_apk(apk, tmp_path / "out", depth=2)
        recovered = {h.member for h in res.hits} | {c.member for h in res.hits for c in h.children}
        assert any("sibling" in m for m in recovered)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv\Scripts\python.exe -m pytest tests/test_breaker.py -v -k Recursion`
Expected: FAIL — no nested hits (`children == []`).

- [ ] **Step 3: Implement**

On a validated ZIP hit with `blob.depth < depth`: `collect_from_zip(plaintext, depth=blob.depth + 1, prefix=hit.member + "!")`, `plan.add_strings(data)` for each `collection.plaintext` entry, then attack the child collection's blobs with the same candidate stream, attaching resulting hits to `hit.children` (recursively). Attack order: process the queue in discovery order (FIFO) so runs are deterministic; per-blob budget accounting continues from the APK's single wall clock.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python.exe -m pytest tests/test_breaker.py -v -k Recursion`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add packers/breaker/engine.py tests/test_breaker.py
git commit -m "breaker: recursive container attack and decrypted-string harvest"
```

---

### Task 8: CLI — batch runs, summary.csv, jobs

**Files:**
- Create: `scripts/breaker.py`
- Test: `tests/test_breaker.py`

**Interfaces:**
- Consumes: `packers.breaker.break_apk`.
- Produces: CLI `--input <apk|dir> --out <dir> [--attempts-cap N] [--budget-s N] [--depth N] [--seeds-extra FILE] [--max-strings N] [--jobs N]`; `summary.csv` columns exactly `apk_path,sha256,ciphertext_members,recovered,attempts_total,truncated,wall_s,outcome`; stdout JSON `{"apks_input", "apks_deduped", "recovered", "miss", "budget", "out"}`; always exit 0.

- [ ] **Step 1: Write the failing test**

```python
import subprocess
import sys


def test_cli_batch_writes_summary_and_exits_zero(tmp_path):
    import hashlib as _h
    from Crypto.Cipher import AES as _AES
    good = _write_apk(tmp_path / "good.apk",
                      {"assets/UZrF0u": _encrypt_prior(_kit_bytes(), "UZrF0u")},
                      method=zipfile.ZIP_STORED)
    import os
    _write_apk(tmp_path / "dead.apk", {"assets/rt": os.urandom(1024)}, method=zipfile.ZIP_STORED)
    out = tmp_path / "out"
    proc = subprocess.run(
        [sys.executable, "scripts/breaker.py", "--input", str(tmp_path), "--out", str(out),
         "--attempts-cap", "50"],
        cwd=str(Path(__file__).resolve().parent.parent), capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    summary = json.loads(proc.stdout)
    assert summary["apks_deduped"] == 2 and summary["recovered"] == 1
    lines = (out / "summary.csv").read_text().strip().splitlines()
    assert lines[0] == "apk_path,sha256,ciphertext_members,recovered,attempts_total,truncated,wall_s,outcome"
    assert len(lines) == 3
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python.exe -m pytest tests/test_breaker.py -v -k cli`
Expected: FAIL — `scripts/breaker.py` missing (non-zero exit).

- [ ] **Step 3: Implement**

Mirror `scripts/unpack.py` bootstrap: `sys.path.insert(0, ".")` before importing `packers.breaker` (`# noqa: E402`). `--input` file → single APK; dir → `sorted(input.rglob("*.apk"))`, skip names starting with `._`, dedupe by sha256. `--jobs > 1` → `ProcessPoolExecutor(max_workers=jobs)`; collect results in input order for the CSV regardless of completion order. Outcome per APK: `recovered` if hits, else `budget` if any member truncation, else `miss`. `truncated` column: `time` if any member used time truncation, else `attempts` if any used cap, else `none`. Print the stdout JSON with `json.dumps`.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv\Scripts\python.exe -m pytest tests/test_breaker.py -v -k cli`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scripts/breaker.py tests/test_breaker.py
git commit -m "breaker: batch CLI with summary.csv"
```

---

### Task 9: Corpus acceptance tests and acceptance run

**Files:**
- Create: `tests/test_breaker_corpus.py`
- Local-only artifact: `analysis/master_key_breaker/REPORT.md` (gitignored — never committed)

**Interfaces:**
- Consumes: `packers.breaker.break_apk`.
- Produces: opt-in acceptance suite (`@pytest.mark.slow`, gated by `DFX_BREAKER_ACCEPTANCE=1`), skipping cleanly when samples are absent.

Pinned ground truth (verified 2026-10-15 against the real samples):

| Artifact | Member | sha256 |
|---|---|---|
| RTO.apk kit | `assets/myg0N` | `d414cb8fe9fa87441200412f8608210cb2ff87ed161b4976d66e586453b614d1` |
| E CHALLAN kit | `assets/UZrF0u` | `51040a408a581db79c6d5909c4c3c1d764427fff9ac1324a665b69cd76f1fb31` |
| PNB ONE ACTIVATION kit | `assets/wyvhtvmqlcbfmi9w/bhtn0kbg` | `66d0aff7053b27aa7a0347dca75335d9bd939045c66a6bb7b3a64ead4016fcfb` |
| M PARIWAHAN kit | `assets/cmg5ro16lp7g1fvt/kesaj3fo` | `b38e620cba177e22fc67d857f5633e0bbafc6acbc952e6a5a789c25834be6489` |
| MediaPlayer2 zip | `assets/3664888858717845462` | `5b5697c9a04c3ff1fab618abaf1002af68244ac7b39dc6ff17fdaa41b0139b5e` |

`bootstrap.dex` inside every myg0N kit: `35b4852821b26aa1ce71eddf43e24e5b094b754705071cfd61b534ed2e017110`.
`classes.dex`: PNB ONE ACTIVATION `1049fdaa00583352c09623a86434dd9fd3a8f44dde083a116a1979e8cf934af7` (622,896 B);
M PARIWAHAN `65efa65709c5a06a391e6937396a690457ecdc0bacdc65cdab7c11a759977d01` (633,128 B);
MediaPlayer2 `6babf08ae30f4ac54bf7f6cc46ed44634cc495316a80f43bbec3ef95de98e9a3` (5,684,096 B).

- [ ] **Step 1: Write the acceptance suite**

```python
"""Corpus acceptance for the master key breaker (opt-in, slow).

Run with:  $env:DFX_BREAKER_ACCEPTANCE=1; .venv\Scripts\python.exe -m pytest tests/test_breaker_corpus.py -v
"""
import os
from pathlib import Path

import pytest

from packers.breaker import break_apk

ROOT = Path(__file__).resolve().parent.parent
PENDRIVE = ROOT / "PENDRIVE DATA" / "PENDRIVE DATA"
OUT = ROOT / "analysis" / "master_key_breaker"

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(os.environ.get("DFX_BREAKER_ACCEPTANCE") != "1",
                       reason="set DFX_BREAKER_ACCEPTANCE=1 to run corpus acceptance"),
]

BOOTSTRAP_DEX = "35b4852821b26aa1ce71eddf43e24e5b094b754705071cfd61b534ed2e017110"

# (apk, member, recovered-payload sha256; None = not pinned)
MYG0N_CASES = [
    (ROOT / "RTO.apk", "assets/myg0N",
     "d414cb8fe9fa87441200412f8608210cb2ff87ed161b4976d66e586453b614d1"),
    (PENDRIVE / "apk fraud" / "21" / "RTO E CHALLAN (1).apk", "assets/UZrF0u",
     "51040a408a581db79c6d5909c4c3c1d764427fff9ac1324a665b69cd76f1fb31"),
    (PENDRIVE / "new apk files" / "PNB One.apk", "assets/ZoCv0N", None),
    (PENDRIVE / "new apk files" / "Repair service.apk", "assets/LAZx0b", None),
]

# (apk, member, payload sha256, dex member, dex size, dex sha256)
LUMOLIGHT_CASES = [
    (PENDRIVE / "apk fraud" / "21" / "PNB ONE ACTIVATION.apk",
     "assets/wyvhtvmqlcbfmi9w/bhtn0kbg",
     "66d0aff7053b27aa7a0347dca75335d9bd939045c66a6bb7b3a64ead4016fcfb",
     "classes.dex", 622896,
     "1049fdaa00583352c09623a86434dd9fd3a8f44dde083a116a1979e8cf934af7"),
    (PENDRIVE / "apk fraud" / "Central bank india" / "M PARIWAHAN CHALAN (12).apk",
     "assets/cmg5ro16lp7g1fvt/kesaj3fo",
     "b38e620cba177e22fc67d857f5633e0bbafc6acbc952e6a5a789c25834be6489",
     "classes.dex", 633128,
     "65efa65709c5a06a391e6937396a690457ecdc0bacdc65cdab7c11a759977d01"),
]

MEDIAPLAYER2 = (
    PENDRIVE / "apk fraud" / "Black mail" / "MediaPlayer2.apk",
    "assets/3664888858717845462",
    "5b5697c9a04c3ff1fab618abaf1002af68244ac7b39dc6ff17fdaa41b0139b5e",
    "classes.dex", 5684096,
    "6babf08ae30f4ac54bf7f6cc46ed44634cc495316a80f43bbec3ef95de98e9a3",
)


def _artifact(hit, name: str) -> dict:
    return next(a for a in hit.artifacts if a["file"] == name)


@pytest.mark.parametrize("apk,member,payload_sha", MYG0N_CASES)
def test_myg0n_family_recovers_from_scratch(apk, member, payload_sha):
    if not apk.exists():
        pytest.skip(f"sample absent: {apk}")
    result = break_apk(apk, OUT / apk.stem)
    hit = next((h for h in result.hits if h.member == member), None)
    assert hit is not None, [h.member for h in result.hits]
    assert hit.provenance == ["prior:myg0n"]
    assert hit.validation == "zip-strict"
    if payload_sha:
        assert hit.payload_sha256 == payload_sha
    assert _artifact(hit, "bootstrap.dex")["sha256"] == BOOTSTRAP_DEX


@pytest.mark.parametrize("apk,member,payload_sha,dex_name,dex_size,dex_sha", LUMOLIGHT_CASES)
def test_lumolight_family_recovers_from_scratch(apk, member, payload_sha, dex_name, dex_size, dex_sha):
    if not apk.exists():
        pytest.skip(f"sample absent: {apk}")
    result = break_apk(apk, OUT / apk.stem)
    hit = next((h for h in result.hits if h.member == member), None)
    assert hit is not None, [h.member for h in result.hits]
    assert hit.provenance == ["prior:gen2-zero-iv"]
    assert hit.payload_sha256 == payload_sha
    artifact = _artifact(hit, dex_name)
    assert artifact["sha256"] == dex_sha and artifact["size"] == dex_size


def test_mediaplayer2_lcg_recovers_autonomously():
    apk, member, payload_sha, dex_name, dex_size, dex_sha = MEDIAPLAYER2
    if not apk.exists():
        pytest.skip(f"sample absent: {apk}")
    result = break_apk(apk, OUT / "MediaPlayer2")
    hit = next((h for h in result.hits if h.member == member), None)
    assert hit is not None, [h.member for h in result.hits]
    assert hit.scheme["cipher"] == "java-lcg"
    assert hit.seed == "3664888858717910997"
    assert hit.provenance == ["numeric:+0xffff"]
    assert hit.validation == "zip-strict"
    assert hit.payload_sha256 == payload_sha
    artifact = _artifact(hit, dex_name)
    assert artifact["sha256"] == dex_sha and artifact["size"] == dex_size


def test_ijiami_dead_ends_produce_no_hits():
    samples = sorted(PENDRIVE.rglob("Calculator*.apk"))
    if not samples:
        pytest.skip("no Ijiami Calculator* samples on this machine")
    for apk in samples:
        result = break_apk(apk, OUT / ("ijiami_" + apk.stem))
        assert result.hits == [], [h.member for h in result.hits]
        assert result.attempts_total > 0
```

Extra hits on a sample beyond the expected member are not failures here, but they are findings: record every recovery in the report (Step 4) and confirm each is authentic. Zero-false-positive coverage comes from the unit probe tests plus the Ijiami negative case.

- [ ] **Step 2: Run to verify the gate skips by default**

Run: `.venv\Scripts\python.exe -m pytest tests/test_breaker_corpus.py -v`
Expected: SKIP (env gate) — the default developer experience.

- [ ] **Step 3: Run the acceptance suite (the acceptance run)**

Run: `$env:DFX_BREAKER_ACCEPTANCE="1"; .venv\Scripts\python.exe -m pytest tests/test_breaker_corpus.py -v`
Expected: PASS for all present samples; SKIP for absent ones. A failure here is a real finding — record it in the report; do **not** weaken a pinned value.

- [ ] **Step 4: Write the local evidence report**

`analysis/master_key_breaker/REPORT.md` (local-only, untracked): per-sample outcome, attempts, wall time, truncation, recovered hashes, the Ijiami negative result (or why it was skipped), any extra recoveries, and an honest summary of misses. Cover spec §11 acceptance points 1–4 explicitly.

- [ ] **Step 5: Commit the suite (the report stays untracked)**

```bash
git add tests/test_breaker_corpus.py
git commit -m "breaker: corpus acceptance suite with pinned ground truth"
```

---

## Self-Review

**Spec coverage:** §4.1–4.2 approach/reuse → Tasks 1–2 and the framework constraints; §4.3 providers → Tasks 2 (`prior_schemes`) and 4; §4.4 matrix → Task 2; §4.5 blob collection incl. flag-lie → Task 3; §4.6 order → Tasks 6–7; §4.7 LCG → Tasks 1, 6; §4.8 recursion/harvest → Task 7; §5 validation/evidence/outcomes → Tasks 3, 5, 6; §6 budgets/determinism → Task 6; §7 files → Tasks 1–9 (`.gitignore` in Task 1, everything else mapped 1:1); §8 data contracts → Tasks 6, 8; §9 CLI → Task 8; §10 tests → each task; §11 acceptance → Task 9; §12 risks → the five Review Focus items; §13 follow-ups → explicitly out of scope (no task, by design).

**Step scan:** every step names a file plus its signature or assertion; no "handle edge cases" lines; no transcripts of function bodies except where the spec fixes the algorithm (the LCG constants and keystream convention) — AES/XOR/RC4 behavior is standard and left to the implementer.

**Type consistency:** `Scheme`/`derive`/`decrypt` (Task 2) are the only types Tasks 3–7 use for crypto; `MemberRecord` fields (`attempts`, `space_size`, `truncation`, `probe_false_positives`) are defined in Task 3 and written in Task 6; `MemberRecord` is imported by Task 6's `ApkResult`; CLI (Task 8) reads only `ApkResult`/`Hit` fields defined in Task 6; `SeedPlan.add_strings` (Task 4) is the harness Task 7 calls.

**Review Focus:** each of the five items names the task whose tests exercise it (Tasks 3, 3+6, 5+6, 6, 4+6).

**Proportion:** ~9 tasks for one package + CLI + two test files; no task carries code the tests already determine.
