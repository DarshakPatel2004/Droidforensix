"""Tests for the master key breaker (packers/breaker/)."""
import hashlib
import io
import json
import os
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from Crypto.Cipher import AES

from packers.breaker.blobs import (
    E_KDF_BUDGET,
    E_KDF_EXHAUSTED,
    PENDING,
    RECOVERED,
    SKIPPED_FILTER,
    SKIPPED_PLAINTEXT,
    SKIPPED_SIZE,
    SKIPPED_ZIPCRYPTO,
    collect_apk,
    collect_from_zip,
)
from packers.breaker.engine import break_apk, probe_matches, validate_payload
from packers.breaker.schemes import (
    AES_KEY_LENGTHS,
    JavaRandom,
    Scheme,
    decrypt,
    derive,
    matrix_schemes,
    prior_schemes,
    single_byte_xor_schemes,
)
from packers.breaker.seeds import (
    SeedCandidate,
    SeedPlan,
    load_extra_seeds,
    mine_strings,
    name_variants,
    numeric_candidates,
    plan_from_collection,
)

MEDIAPLAYER2_SEED = 3664888858717910997
MEDIAPLAYER2_STEM = "3664888858717845462"
# The RTO reference key/IV are published in tests/test_framework.py; this file pins their sha256
# instead of the raw bytes so no real key material is duplicated into another tracked file.
RTO_KEY_SHA256 = "2887ee7cfb89eca8c65db19f9b3314090e2317f800269e2292afd0a4ad2257b8"
RTO_IV_SHA256 = "a82f1cd1b3be3503002d3c68a3f9beeff1909bdc93437101fcac0a0b3a629308"


class TestJavaRandom:
    def test_jdk_reference_values(self):
        assert JavaRandom(0).next_int() == -1155484576
        assert JavaRandom(42).next_int() == -1170105035

    def test_next_matches_signed_int_bits(self):
        r = JavaRandom(0)
        assert r.next(32) == JavaRandom(0).next_int() & 0xFFFFFFFF

    def test_mediaplayer2_keystream_vector(self):
        # Derived from the shipped sample: asset 3664888858717845462, seed = n + 0xFFFF,
        # keystream = nextInt() as 4-byte little-endian. The member lies about being
        # encrypted; inflating its stored bytes yields the ciphertext, and XORing that with
        # this keystream yields a ZIP whose sha256 is the pinned ground truth
        # 5b5697c9a04c3ff1fab618abaf1002af68244ac7b39dc6ff17fdaa41b0139b5e.
        ks = JavaRandom(MEDIAPLAYER2_SEED).keystream(16)
        assert ks == bytes.fromhex("e04ccdce1cdaf4a619c669831f8034b2")

    def test_keystream_prefix_stability(self):
        r = JavaRandom(MEDIAPLAYER2_SEED)
        assert r.keystream(8) == JavaRandom(MEDIAPLAYER2_SEED).keystream(16)[:8]


class TestSchemeModel:
    def test_myg0n_prior_derives_rto_reference_key(self):
        priors = prior_schemes("myg0N")
        assert priors[0].seed == "myg0N2"
        key, iv = derive(priors[0])
        assert hashlib.sha256(key).hexdigest() == RTO_KEY_SHA256
        assert hashlib.sha256(iv).hexdigest() == RTO_IV_SHA256

    def test_prior_order_covers_all_known_families(self):
        provs = [s.provenance for s in prior_schemes("UZrF0u")]
        assert provs[0] == "prior:myg0n" and "prior:gen2-zero-iv" in provs
        assert "prior:step20-matrix" in provs and "prior:rto-substring" in provs

    def test_gen2_zero_iv_prior_uses_bare_stem_and_zero_iv(self):
        priors = prior_schemes("bhtn0kbg")
        gen2 = next(s for s in priors if s.provenance == "prior:gen2-zero-iv")
        assert gen2.seed == "bhtn0kbg"
        key, iv = derive(gen2)
        assert key.hex() == hashlib.sha1(b"bhtn0kbg").digest()[:16].hex()
        assert iv == bytes(16)

    def test_rto_substring_prior_window_count_matches_probe_precedent(self):
        # scripts/unpack.py:85 enumerates a<=b<=len, c<=len(mid) over stem+"bootstrap.dex".
        # For "UZrF0u" that literal is 19 chars -> 1540 seeds.
        windows = [s for s in prior_schemes("UZrF0u") if s.provenance == "prior:rto-substring"]
        assert len(windows) == 1540
        assert windows[0].seed == "2"  # a==b==0 -> empty mid -> seed "" + "2"

    def test_rto_substring_prior_is_bounded_by_literal_cap(self):
        assert not [s for s in prior_schemes("x" * 40) if s.provenance == "prior:rto-substring"]

    def test_matrix_count_is_pinned(self):
        assert len(list(matrix_schemes("seed", "test"))) == 61

    def test_matrix_never_emits_structurally_impossible_aes_keys(self):
        # AES accepts 128/192/256-bit keys only. A 20-byte candidate would raise inside the
        # cipher: pure budget waste that also inflates the reported space_size.
        for scheme in matrix_schemes("seed", "test"):
            if scheme.cipher.startswith("aes"):
                assert scheme.key_len in (16, 24, 32)

    def test_matrix_uses_framework_key_truncation_rules(self):
        schemes = list(matrix_schemes("seed", "test"))
        assert {s.key_len for s in schemes if s.key_hash == "md5"} == {16}  # md5 digest is 16 bytes
        assert {s.key_len for s in schemes if s.key_hash == "sha256"} == set(AES_KEY_LENGTHS)

    def test_matrix_carries_provenance_and_covers_every_cipher(self):
        schemes = list(matrix_schemes("seed", "mined"))
        assert {s.provenance for s in schemes} == {"mined"}
        assert {s.cipher for s in schemes} == {"aes-cbc", "aes-ecb", "xor", "rc4"}
        assert all(s.seed == "seed" for s in schemes)

    def test_single_byte_xor_excludes_the_identity_key(self):
        # 255 keys, not 256: key 0 is the identity - "decrypting" with it returns the
        # ciphertext, which is how an already-plaintext JSON member was reported as a
        # recovery. A no-op is not a candidate (phase-1 plan, weak-class hardening).
        schemes = list(single_byte_xor_schemes())
        assert len(schemes) == 255
        assert all(s.cipher == "xor" and s.xor_mode == "byte" for s in schemes)
        assert {int(s.seed) for s in schemes} == set(range(1, 256))


def _rc4_reference(key: bytes, data: bytes) -> bytes:
    """Independent pure-Python RC4 (KSA + PRGA), used only to cross-check decrypt()."""
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
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
        ct = bytes(a ^ b for a, b in zip(pt, JavaRandom(MEDIAPLAYER2_SEED).keystream(len(pt)), strict=True))
        assert decrypt(scheme, ct) == pt


def _make_apk(path, members: dict, method=zipfile.ZIP_DEFLATED) -> None:
    with zipfile.ZipFile(path, "w", method) as zf:
        for name, data in members.items():
            zf.writestr(name, data)


def _write_bytes_zip(members: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _kit_bytes() -> bytes:
    return _write_bytes_zip({
        "bootstrap.dex": b"dex\n035\x00" + b"\x00" * 500,
        "config.json": b"{}",
    })


def _encrypt_prior(plaintext: bytes, stem: str) -> bytes:
    """The prior:myg0n recipe: seed = stem + \"2\", SHA1[:16] key, SHA256[:16] IV, AES-CBC."""
    from Crypto.Cipher import AES
    seed = (stem + "2").encode()
    key, iv = hashlib.sha1(seed).digest()[:16], hashlib.sha256(seed).digest()[:16]
    pad = 16 - len(plaintext) % 16
    return AES.new(key, AES.MODE_CBC, iv).encrypt(plaintext + bytes([pad]) * pad)


def _set_encrypted_flag(path, member: str) -> None:
    """Flip bit 0 of the flag field in both the local header and the central directory."""
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
            "assets/small": b"\x00" * 100,                    # below MIN_BLOB_SIZE
            "assets/big": b"\xab" * 4096,                     # attacked
            "assets/bigger": b"\xcd" * 8192,                  # attacked, ordered first
            "assets/icon.png": b"\x89PNG" + b"\x00" * 600,    # extension filter
            "res/raw/thing": b"\xef" * 900,                   # ignored dir: counted, no row
            "classes.dex": b"\xaa" * 900,                     # extension filter (.dex)
            "kotlin/builtins": b"\x11" * 900,                 # out of scope: nested non-asset
        })
        c = collect_apk(apk)
        assert [b.member for b in c.blobs] == ["assets/bigger", "assets/big"]
        outcomes = {r.name: r.outcome for r in c.records}
        assert outcomes["assets/small"] == SKIPPED_SIZE
        assert outcomes["assets/icon.png"] == SKIPPED_FILTER
        assert outcomes["classes.dex"] == SKIPPED_FILTER
        assert c.members_ignored_dirs == 1
        assert c.members_out_of_scope == 1
        assert "kotlin/builtins" not in outcomes
        assert c.members_total == 7
        assert c.members_total == len(c.records) + c.members_ignored_dirs + c.members_out_of_scope

    def test_plaintext_magic_member_is_skipped_and_offered_for_recursion(self, tmp_path):
        apk = tmp_path / "b.apk"
        inner = tmp_path / "inner.bin"
        _make_apk(inner, {"assets/x": b"\xaa" * 1024})
        _make_apk(apk, {"assets/nested": inner.read_bytes(), "assets/ct": b"\xbb" * 1024})
        c = collect_apk(apk)
        assert {r.name: r.outcome for r in c.records}["assets/nested"] == SKIPPED_PLAINTEXT
        assert [n for n, _ in c.recurse] == ["assets/nested"]
        assert [n for n, _ in c.plaintext] == ["assets/nested"]
        assert [b.member for b in c.blobs] == ["assets/ct"]

    def test_flag_lie_deflate_member_is_read_as_inflated_content(self, tmp_path):
        apk = tmp_path / "c.apk"
        payload = bytes(range(256)) * 8  # 2048 bytes, no plaintext magic
        _make_apk(apk, {"assets/payload": payload})
        _set_encrypted_flag(apk, "assets/payload")
        with zipfile.ZipFile(apk) as zf:
            with pytest.raises(RuntimeError):
                zf.read("assets/payload")
        c = collect_apk(apk)
        blob = c.blobs[0]
        assert blob.content == "inflated" and blob.data == payload

    def test_genuine_zipcrypto_member_is_typed_not_attacked(self, tmp_path):
        apk = tmp_path / "d.apk"
        _make_apk(apk, {"assets/real": os.urandom(1024)})  # incompressible: room to damage it
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

    def test_encrypted_member_survives_deflate_and_crc_round_trip(self, tmp_path):
        # The MediaPlayer2 shape, reduced: stored bytes are plaintext DEFLATE data wearing the
        # encrypted flag; the central CRC covers the inflated bytes.
        import zlib
        payload = b"PK\x03\x04" + bytes(range(256)) * 8
        apk = tmp_path / "f.apk"
        with zipfile.ZipFile(apk, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("assets/mp2shaped", payload)
        _set_encrypted_flag(apk, "assets/mp2shaped")
        with zipfile.ZipFile(apk) as zf:
            info = zf.getinfo("assets/mp2shaped")
        assert info.CRC == zlib.crc32(payload)
        c = collect_apk(apk)
        assert not c.blobs, "payload starts with a ZIP magic -> plaintext, not a blob"
        assert {r.name: r.outcome for r in c.records}["assets/mp2shaped"] == SKIPPED_PLAINTEXT


class TestSeedProviders:
    def test_mine_strings_dedupes_orders_and_bounds(self):
        data = b"\x00hello\x00world\x00hello\x00ab\x00" + b"\xff" * 200
        assert mine_strings(data) == [b"hello", b"world"]
        assert mine_strings(b"\x00" + b"y" * 200 + b"\x00") == []
        assert mine_strings(b"\x00password123\x00") == [b"password123"]

    def test_name_variants_cover_case_and_digits(self):
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
        assert "-1" in {c.material for c in numeric_candidates("18446744073709551615")}

    def test_load_extra_seeds_accepts_three_formats(self, tmp_path):
        array = tmp_path / "array.json"
        array.write_text(json.dumps(["seedA", "seedB"]))
        wrapped = tmp_path / "wrapped.json"
        wrapped.write_text(json.dumps({"seeds": ["seedC"]}))
        key_log = tmp_path / "keylog.json"
        key_log.write_text(json.dumps({"key_log": [["getBytes", "seedD"], ["digest", "seedE"], ["junk", 5]]}))
        assert [s.material for s in load_extra_seeds(array)] == ["seedA", "seedB"]
        assert [s.material for s in load_extra_seeds(wrapped)] == ["seedC"]
        assert [s.material for s in load_extra_seeds(key_log)] == ["seedD", "seedE"]
        assert [s.provenance for s in load_extra_seeds(key_log)] == ["extra:getBytes", "extra:digest"]
        assert [s.provenance for s in load_extra_seeds(wrapped)] == ["extra"]

    def test_load_extra_seeds_decodes_byte_arrays(self, tmp_path):
        path = tmp_path / "bytes.json"
        path.write_text(json.dumps({"key_log": [["getBytes", [115, 101, 101, 100]]]}))
        assert [s.material for s in load_extra_seeds(path)] == ["seed"]

    def test_plan_mines_collection_plaintext_with_cap(self, tmp_path):
        apk = tmp_path / "p.apk"
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 20 + b"thePassword123" + b"\x00" * 200)
            zf.writestr("assets/ct", b"\xcc" * 1024)
        plan = plan_from_collection(collect_apk(apk), max_strings=10)
        assert any(s.material == "thePassword123" for s in plan.mined)
        assert len(plan.mined) <= 10
        assert all(s.provenance == "mined" for s in plan.mined)

    def test_plan_adds_extra_seeds_file(self, tmp_path):
        extra = tmp_path / "extra.json"
        extra.write_text(json.dumps(["traceKey42"]))
        apk = tmp_path / "q.apk"
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("assets/ct", b"\xcc" * 1024)
        plan = plan_from_collection(collect_apk(apk), extra_path=extra)
        assert [s.material for s in plan.extra] == ["traceKey42"]

    def test_add_strings_respects_cap(self):
        plan = SeedPlan(mined=[], extra=[])
        plan.add_strings(b"\x00aaaa\x00bbbb\x00cccc\x00", cap=2)
        assert len(plan.mined) == 2
        assert [s.material for s in plan.mined] == ["aaaa", "bbbb"]


def _encrypt_scheme(scheme: Scheme, plaintext: bytes) -> bytes:
    """Encrypt with the scheme's own key/iv - the inverse of the engine's decrypt()."""
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

    def test_probe_refuses_short_or_unalignable_input(self):
        scheme = Scheme(seed="s", cipher="aes-cbc", key_hash="sha1", key_len=16, iv="zeros")
        assert not probe_matches(scheme, b"PK\x03\x04")
        assert not probe_matches(scheme, b"PK\x03\x04" + b"\x00" * 7)

    def test_probe_false_positive_is_detectable(self):
        # PK prefix in the first block, garbage after: the probe matches, strong validation must not.
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
        # The strict parse fails: the EOCD claims one entry and a 46-byte central directory at
        # offset 0, where there is a local-file header instead. Both ZIP signatures are present,
        # which is exactly what the weaker evidence level asserts.
        eocd = (
            b"PK\x05\x06"
            + (0).to_bytes(2, "little") + (0).to_bytes(2, "little")
            + (1).to_bytes(2, "little") + (1).to_bytes(2, "little")
            + (46).to_bytes(4, "little") + (0).to_bytes(4, "little")
            + (0).to_bytes(2, "little")
        )
        payload = b"PK\x03\x04" + b"\x00" * 200 + eocd
        v = validate_payload(payload)
        assert v is not None and v.evidence == "zip-eocd"

    def test_broken_zip_without_eocd_is_rejected(self):
        assert validate_payload(b"PK\x03\x04" + b"\x00" * 200) is None

    def test_dex_header_evidence_upgrades_magic(self):
        body = b"dex\n035\x00" + b"\x00" * 24 + (400).to_bytes(4, "little") + b"\x00" * (400 - 36)
        assert validate_payload(body).evidence == "dex-header"
        assert validate_payload(b"dex\n035\x00" + b"\x00" * 300).evidence == "dex-magic"

    def test_gzip_and_elf_evidence(self):
        import gzip
        assert validate_payload(gzip.compress(b"x" * 100)).evidence == "gzip"
        assert validate_payload(b"\x7fELF\x02\x01" + b"\x00" * 100).evidence == "elf"
        assert validate_payload(b"\x7fELF\x02\x01" + b"\x00" * 10) is None  # too short

    def test_json_and_ttf_evidence(self):
        assert validate_payload(b'{"a": 1}').evidence == "json"
        assert validate_payload(b"{not json") is None
        assert validate_payload(b"{\x00\xff not json") is None
        assert validate_payload(b"\x00\x01\x00\x00" + b"\x00" * 100).evidence == "ttf-magic"

    def test_validator_never_raises_on_hostile_input(self):
        # A hostile payload must yield None, not an exception that would abort a whole batch.
        deep = b'{"a":' + b"[" * 200_000 + b"]" * 200_000 + b"}"
        assert validate_payload(deep) is None
        assert validate_payload(b"\x1f\x8b" + os.urandom(64)) is None

    def test_gzip_validation_does_not_materialise_a_bomb(self):
        import gzip
        import tracemalloc
        bomb = gzip.compress(b"\x00" * (64 * 1024 * 1024))  # ~64 KiB in, 64 MiB out
        tracemalloc.start()
        validation = validate_payload(bomb)
        _current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        assert validation is not None and validation.evidence == "gzip"
        assert peak < 8 * 1024 * 1024
        # Truncated streams are still rejected, so the bounded probe did not weaken the evidence.
        truncated = gzip.compress(os.urandom(50_000))[:2000]  # cut mid-stream, not at the end
        assert validate_payload(truncated) is None

    def test_plaintext_garbage_is_not_validated(self):
        assert validate_payload(b"\x9e\x11\x33" * 100) is None


class TestBreakApk:
    def test_recovers_myg0n_prior_and_writes_outputs(self, tmp_path):
        kit = _kit_bytes()
        apk = tmp_path / "m.apk"
        _make_apk(apk, {"assets/UZrF0u": _encrypt_prior(kit, "UZrF0u")},
                  method=zipfile.ZIP_STORED)
        res = break_apk(apk, tmp_path / "out")
        assert res.outcome == RECOVERED and len(res.hits) == 1
        hit = res.hits[0]
        assert hit.member == "assets/UZrF0u" and hit.provenance == ["prior:myg0n"]
        assert hit.validation == "zip-strict" and hit.content == "stored"
        assert hit.artifacts_total == 2
        # payload_sha256 covers the full decrypted buffer, PKCS#7 padding included. That is the
        # same convention as the hand-verified corpus pins in Task 9 (RTO.apk's kit hash was
        # derived from the existing pipeline's decrypted buffer), so the pins stay independent
        # of this implementation.
        pad = 16 - len(kit) % 16
        assert hit.payload_sha256 == hashlib.sha256(kit + bytes([pad]) * pad).hexdigest()
        hit_json = json.loads((tmp_path / "out" / res.sha256[:16] / "hit.json").read_text())
        assert hit_json["hits"][0]["key_hex"] == hit.key_hex
        coverage = (tmp_path / "out" / res.sha256[:16] / "coverage.json").read_text()
        assert "key_hex" not in coverage and json.loads(coverage)["scheme_count"] > 0

    def test_recovers_lumolight_zero_iv_prior(self, tmp_path):
        stem = "bhtn0kbg"
        key = hashlib.sha1(stem.encode()).digest()[:16]
        pt = _kit_bytes()
        pad = 16 - len(pt) % 16
        ct = AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(pt + bytes([pad]) * pad)
        apk = tmp_path / "l.apk"
        _make_apk(apk, {f"assets/sub/{stem}": ct}, method=zipfile.ZIP_STORED)
        res = break_apk(apk, tmp_path / "out")
        assert res.hits[0].provenance == ["prior:gen2-zero-iv"]

    def test_mined_string_seed_is_found(self, tmp_path):
        seed = "thePassword123"
        key = hashlib.sha1(seed.encode()).digest()[:16]
        pt = _kit_bytes()
        pad = 16 - len(pt) % 16
        ct = AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(pt + bytes([pad]) * pad)
        apk = tmp_path / "p.apk"
        _make_apk(apk, {
            "classes.dex": b"dex\n035\x00" + b"\x00" * 20 + seed.encode() + b"\x00" * 200,
            "assets/pwblob": ct,
        }, method=zipfile.ZIP_STORED)
        res = break_apk(apk, tmp_path / "out")
        assert res.hits and res.hits[0].provenance == ["mined"]

    def test_extra_seeds_file_is_found(self, tmp_path):
        seed = "traceKey42"
        key = hashlib.sha1(seed.encode()).digest()[:16]
        pt = _kit_bytes()
        pad = 16 - len(pt) % 16
        ct = AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(pt + bytes([pad]) * pad)
        extra = tmp_path / "extra.json"
        extra.write_text(json.dumps({"seeds": [seed]}))
        apk = tmp_path / "e.apk"
        _make_apk(apk, {"assets/traceblob": ct}, method=zipfile.ZIP_STORED)
        res = break_apk(apk, tmp_path / "out", seeds_extra=extra)
        assert res.hits[0].provenance == ["extra"]

    def test_lcg_numeric_delta_recovers_and_is_deterministic(self, tmp_path):
        stem = "123456789012345"
        seed = int(stem) + 0xFFFF
        pt = _kit_bytes()
        from packers.breaker.schemes import JavaRandom
        ct = bytes(a ^ b for a, b in zip(pt, JavaRandom(seed).keystream(len(pt)), strict=True))
        apk = tmp_path / "n.apk"
        _make_apk(apk, {f"assets/{stem}": ct}, method=zipfile.ZIP_STORED)
        res = break_apk(apk, tmp_path / "out")
        assert res.hits[0].provenance == ["numeric:+0xffff"]
        assert res.hits[0].scheme["cipher"] == "java-lcg"
        res2 = break_apk(apk, tmp_path / "out2")
        assert res2.hits[0].seed == res.hits[0].seed

    def test_attempts_cap_marks_budget_not_exhaustion(self, tmp_path):
        apk = tmp_path / "x.apk"
        _make_apk(apk, {"assets/randomblob": os.urandom(2048)}, method=zipfile.ZIP_STORED)
        res = break_apk(apk, tmp_path / "out", attempts_cap=25)
        assert res.outcome == E_KDF_BUDGET
        assert res.members[0].outcome == E_KDF_BUDGET
        assert res.members[0].truncation == "attempts" and res.members[0].attempts == 25
        res2 = break_apk(apk, tmp_path / "out2", attempts_cap=25)
        assert res2.members[0].attempts == 25  # prefix-stable determinism

    def test_runtime_keyed_blob_is_exhausted_not_recovered(self, tmp_path):
        apk = tmp_path / "y.apk"
        _make_apk(apk, {"assets/rt": os.urandom(1024)}, method=zipfile.ZIP_STORED)
        res = break_apk(apk, tmp_path / "out")
        assert res.hits == [] and res.outcome in (E_KDF_EXHAUSTED, E_KDF_BUDGET)

    @pytest.mark.filterwarnings("ignore:Duplicate name")
    def test_duplicate_member_names_each_get_their_own_row(self, tmp_path):
        # A ZIP may legally repeat a name. Each occurrence is its own blob and must get its own
        # coverage row - never a leftover "pending" row that was silently never attacked.
        apk = tmp_path / "dup.apk"
        with zipfile.ZipFile(apk, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("assets/twice", _encrypt_prior(_payload_bytes(), "twice"))
            zf.writestr("assets/twice", _encrypt_prior(_payload_bytes(), "twice"))
        res = break_apk(apk, tmp_path / "out")
        rows = [m for m in res.members if m.name == "assets/twice"]
        assert len(rows) == 2
        assert all(row.outcome != PENDING for row in rows)
        assert all(row.outcome == RECOVERED for row in rows)

    def test_padded_dex_hit_reports_dex_header_evidence(self, tmp_path):
        # AES always pads, so an exact file_size == len(data) test can never succeed on a real
        # recovered payload: the upgrade must compare the header size against the unpadded length.
        dex = b"dex\n035\x00" + b"\x00" * 24 + (600).to_bytes(4, "little") + b"\x00" * (600 - 36)
        apk = tmp_path / "dex.apk"
        _make_apk(apk, {"assets/dexblob": _encrypt_prior(dex, "dexblob")},
                  method=zipfile.ZIP_STORED)
        res = break_apk(apk, tmp_path / "out")
        assert len(res.hits) == 1
        assert res.hits[0].validation == "dex-header"

    @pytest.mark.filterwarnings("ignore:Duplicate name")
    def test_duplicate_names_do_not_share_content(self, tmp_path):
        # Each duplicate entry must be read as the bytes that entry actually holds. zipfile's
        # read(name) resolves to the LAST entry, which would report the random one as recovered.
        apk = tmp_path / "dup2.apk"
        with zipfile.ZipFile(apk, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("assets/twice", os.urandom(2048))  # not recoverable
            zf.writestr("assets/twice", _encrypt_prior(_payload_bytes(), "twice"))
        res = break_apk(apk, tmp_path / "out")
        rows = [m for m in res.members if m.name == "assets/twice"]
        assert len(rows) == 2
        assert sum(row.outcome == RECOVERED for row in rows) == 1

    def test_deep_tier_does_not_reprobe_prior_schemes(self, tmp_path):
        # The cheap tier runs the priors, the deep tier runs the rest. A key identity must never
        # be paid for twice (and space_size must equal the true enumeration of the two tiers).
        stem = "a" * 40  # long stem: no substring-window priors, counts stay exact
        apk = tmp_path / "d.apk"
        _make_apk(apk, {"assets/" + stem: os.urandom(2048)}, method=zipfile.ZIP_STORED)
        res = break_apk(apk, tmp_path / "out", attempts_cap=10_000_000)
        stream = list(prior_schemes(stem))
        for variant in name_variants(stem):
            stream += list(matrix_schemes(variant.material, variant.provenance))
        stream += list(single_byte_xor_schemes())
        stream += [Scheme(seed=c.material, cipher="java-lcg", provenance=c.provenance)
                   for c in numeric_candidates(stem)]
        identities = {(s.cipher, derive(s)[0].hex(), derive(s)[1].hex()) for s in stream}
        row = res.members[0]
        assert row.outcome == E_KDF_EXHAUSTED
        assert row.space_size == len(stream)   # enumeration: every candidate yielded
        assert row.attempts == len(identities)  # probing: every distinct key exactly once

    def test_probe_false_positive_is_counted_not_reported(self, tmp_path):
        scheme_pt = b"PK\x03\x04" + b"\x00" * 44 + b"\x77" * 4096  # PK prefix, invalid zip
        apk = tmp_path / "fp.apk"
        _make_apk(apk, {"assets/fpblob": _encrypt_prior(scheme_pt, "fpblob")},
                  method=zipfile.ZIP_STORED)
        res = break_apk(apk, tmp_path / "out")
        assert res.hits == []
        assert res.members[0].probe_false_positives >= 1

    def test_cheap_recipe_sweep_reaches_every_member_before_deep_search(self, tmp_path):
        # The big member is attacked first and can never be cracked; its expensive deep sweep
        # must not eat a budget that another member's cheap known recipe needs.
        apk = tmp_path / "sweep.apk"
        _make_apk(apk, {
            "assets/zzzbig": os.urandom(4096),
            "assets/UZrF0u": _encrypt_prior(_payload_bytes(), "UZrF0u"),
        }, method=zipfile.ZIP_STORED)
        res = break_apk(apk, tmp_path / "out", attempts_cap=1000)
        assert [h.member for h in res.hits] == ["assets/UZrF0u"]
        assert res.outcome == RECOVERED


def _payload_bytes(size: int = 700) -> bytes:
    """A valid ZIP payload big enough that its ciphertext clears MIN_BLOB_SIZE."""
    return _write_bytes_zip({"assets/blob": os.urandom(size)})


class TestRecursion:
    def test_nested_container_is_attacked_up_to_depth(self, tmp_path):
        inner_pt = _payload_bytes()
        inner_stem = "inner7"
        inner_ct = _encrypt_prior(inner_pt, inner_stem)  # prior:myg0n inside the outer kit
        outer_pt = _write_bytes_zip({"assets/" + inner_stem: inner_ct})
        apk = tmp_path / "r.apk"
        _make_apk(apk, {"assets/outer": _encrypt_prior(outer_pt, "outer")},
                  method=zipfile.ZIP_STORED)
        res = break_apk(apk, tmp_path / "out", depth=2)
        assert len(res.hits) == 1 and len(res.hits[0].children) == 1
        assert res.hits[0].children[0].member.endswith("assets/inner7")
        # nested members are folded into the same coverage book as top-level ones
        assert res.members[0].name == "assets/outer"
        assert any(m.name.startswith("assets/outer!") for m in res.members)
        assert res.outcome == RECOVERED

    def test_unreadable_eocd_hit_does_not_crash_recursion(self, tmp_path):
        # A hit may validate only at the weaker zip-eocd level: EOCD present, strict parse fails.
        # Recursing into such a payload must yield no children, not raise BadZipFile.
        eocd = (
            b"PK\x05\x06"
            + (0).to_bytes(2, "little") + (0).to_bytes(2, "little")
            + (1).to_bytes(2, "little") + (1).to_bytes(2, "little")
            + (46).to_bytes(4, "little") + (0).to_bytes(4, "little")
            + (0).to_bytes(2, "little")
        )
        payload = b"PK\x03\x04" + b"\x00" * 600 + eocd
        apk = tmp_path / "eocd.apk"
        _make_apk(apk, {"assets/outer": _encrypt_prior(payload, "outer")},
                  method=zipfile.ZIP_STORED)
        res = break_apk(apk, tmp_path / "out", depth=2)
        assert len(res.hits) == 1
        assert res.hits[0].validation == "zip-eocd"
        assert res.hits[0].children == []

    def test_depth_one_does_not_recurse(self, tmp_path):
        inner_ct = _encrypt_prior(_payload_bytes(), "inner7")
        outer_pt = _write_bytes_zip({"assets/inner7": inner_ct})
        apk = tmp_path / "r1.apk"
        _make_apk(apk, {"assets/outer": _encrypt_prior(outer_pt, "outer")},
                  method=zipfile.ZIP_STORED)
        res = break_apk(apk, tmp_path / "out", depth=1)
        assert res.hits and res.hits[0].children == []
        assert not any(m.name.startswith("assets/outer!") for m in res.members)

    def test_nested_mining_honours_the_string_cap(self, tmp_path):
        # --max-strings must bound nested mining too: a recovered container is not a licence to
        # ignore the caller's cap and expand the deep search.
        keeper = "firstMinedSecret1"
        wanted = "secondMinedSecret2"
        sib_key = hashlib.sha1(wanted.encode()).digest()[:16]
        sib_pt = _payload_bytes()
        pad = 16 - len(sib_pt) % 16
        sib_ct = AES.new(sib_key, AES.MODE_CBC, bytes(16)).encrypt(sib_pt + bytes([pad]) * pad)
        inner = _write_bytes_zip({
            "assets/one.dex": b"dex\n035\x00" + keeper.encode() + b"\x00" * 200,
            "assets/two.dex": b"dex\n035\x00" + wanted.encode() + b"\x00" * 200,
        })
        apk = tmp_path / "cap.apk"
        _make_apk(apk, {
            "assets/first": _encrypt_prior(inner, "first"),
            "assets/sibling": sib_ct,
        }, method=zipfile.ZIP_STORED)
        capped = {h.member for h in break_apk(apk, tmp_path / "o1", depth=2, max_strings=1).hits}
        assert "assets/sibling" not in capped
        roomy = {h.member for h in break_apk(apk, tmp_path / "o2", depth=2, max_strings=2).hits}
        assert "assets/sibling" in roomy

    def test_validated_dex_hit_releases_strings_for_siblings(self, tmp_path):
        # Spec 4.8: a validated DEX hit is a seed source too. Strings it carries must reach the
        # seed plan, or a sibling blob keyed by one of them is unreachable by construction.
        secret = "dexCarriedSecret7"
        dex = b"dex\n035\x00" + secret.encode() + b"\x00" * 600
        sib_key = hashlib.sha1(secret.encode()).digest()[:16]
        sib_pt = _payload_bytes()
        pad = 16 - len(sib_pt) % 16
        sib_ct = AES.new(sib_key, AES.MODE_CBC, bytes(16)).encrypt(sib_pt + bytes([pad]) * pad)
        apk = tmp_path / "dexh.apk"
        _make_apk(apk, {
            "assets/dexfirst": _encrypt_prior(dex, "dexfirst"),
            "assets/sibling": sib_ct,
        }, method=zipfile.ZIP_STORED)
        res = break_apk(apk, tmp_path / "out")
        recovered = {h.member for h in res.hits}
        assert "assets/dexfirst" in recovered
        assert "assets/sibling" in recovered

    def test_decrypted_strings_enable_sibling_recovery(self, tmp_path):
        # sibling blob keyed by a string that only exists inside the first recovered kit
        secret = "harvestedSecret9"
        sib_key = hashlib.sha1(secret.encode()).digest()[:16]
        sib_pt = _payload_bytes()
        pad = 16 - len(sib_pt) % 16
        sib_ct = AES.new(sib_key, AES.MODE_CBC, bytes(16)).encrypt(sib_pt + bytes([pad]) * pad)
        inner = _write_bytes_zip({
            "assets/dexish": b"dex\n035\x00" + secret.encode() + b"\x00" * 200,
            "assets/pad": os.urandom(600),
        })
        apk = tmp_path / "h.apk"
        _make_apk(apk, {
            "assets/first": _encrypt_prior(inner, "first"),
            "assets/sibling": sib_ct,
        }, method=zipfile.ZIP_STORED)
        res = break_apk(apk, tmp_path / "out", depth=2)
        recovered = {h.member for h in res.hits} | {c.member for h in res.hits for c in h.children}
        assert any("sibling" in m for m in recovered)


class TestCli:
    def test_cli_batch_writes_summary_and_exits_zero(self, tmp_path):
        _make_apk(tmp_path / "good.apk",
                  {"assets/UZrF0u": _encrypt_prior(_kit_bytes(), "UZrF0u")},
                  method=zipfile.ZIP_STORED)
        _make_apk(tmp_path / "dead.apk", {"assets/rt": os.urandom(1024)},
                  method=zipfile.ZIP_STORED)
        out = tmp_path / "out"
        proc = subprocess.run(
            [sys.executable, "scripts/breaker.py", "--input", str(tmp_path), "--out", str(out),
             "--attempts-cap", "50"],
            cwd=str(Path(__file__).resolve().parent.parent), capture_output=True, text=True, timeout=120,
        )
        assert proc.returncode == 0, proc.stderr
        summary = json.loads(proc.stdout)
        assert summary["apks_deduped"] == 2 and summary["recovered"] == 1
        assert summary["budget"] == 1 and summary["miss"] == 0
        lines = (out / "summary.csv").read_text().strip().splitlines()
        assert lines[0] == "apk_path,sha256,ciphertext_members,recovered,attempts_total,truncated,wall_s,outcome"
        assert len(lines) == 3
        assert sum("RECOVERED" in line for line in lines[1:]) == 1
        assert sum("E-KDF-BUDGET" in line for line in lines[1:]) == 1

    def test_cli_isolates_one_unreadable_apk(self, tmp_path):
        # The batch contract is "always finish and write a typed verdict": a file that is not a
        # ZIP at all must become an error row, not kill the run (and the good APK still runs).
        _make_apk(tmp_path / "good.apk",
                  {"assets/UZrF0u": _encrypt_prior(_kit_bytes(), "UZrF0u")},
                  method=zipfile.ZIP_STORED)
        (tmp_path / "junk.apk").write_bytes(os.urandom(4096))
        out = tmp_path / "out"
        proc = subprocess.run(
            [sys.executable, "scripts/breaker.py", "--input", str(tmp_path), "--out", str(out)],
            cwd=str(Path(__file__).resolve().parent.parent), capture_output=True, text=True, timeout=120,
        )
        assert proc.returncode == 0, proc.stderr
        summary = json.loads(proc.stdout)
        assert summary["recovered"] == 1 and summary["errors"] == 1
        rows = (out / "summary.csv").read_text().strip().splitlines()[1:]
        assert any(row.endswith("E-ENGINE-FAULT") for row in rows)
        assert any("RECOVERED" in row for row in rows)

    def test_cli_single_file_and_stdout_schema(self, tmp_path):
        apk = tmp_path / "good.apk"
        _make_apk(apk, {"assets/UZrF0u": _encrypt_prior(_kit_bytes(), "UZrF0u")},
                  method=zipfile.ZIP_STORED)
        out = tmp_path / "out"
        proc = subprocess.run(
            [sys.executable, "scripts/breaker.py", "--input", str(apk), "--out", str(out)],
            cwd=str(Path(__file__).resolve().parent.parent), capture_output=True, text=True, timeout=120,
        )
        assert proc.returncode == 0, proc.stderr
        summary = json.loads(proc.stdout)
        assert set(summary) == {
            "apks_input", "apks_deduped", "recovered", "miss", "budget", "errors", "out"
        }
        assert summary["apks_input"] == 1 and summary["recovered"] == 1
        # stdout and coverage stay free of key material; only hit.json may carry it.
        assert "key" not in proc.stdout.lower()
        coverage = next(Path(out).rglob("coverage.json")).read_text()
        assert "key_hex" not in coverage
