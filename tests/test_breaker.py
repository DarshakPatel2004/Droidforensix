"""Tests for the master key breaker (packers/breaker/)."""
import hashlib
import json
import os
import struct
import zipfile

import pytest

from packers.breaker.blobs import (
    SKIPPED_FILTER,
    SKIPPED_PLAINTEXT,
    SKIPPED_SIZE,
    SKIPPED_ZIPCRYPTO,
    collect_apk,
    collect_from_zip,
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
from packers.breaker.schemes import (
    KEY_LENGTHS,
    JavaRandom,
    Scheme,
    decrypt,
    derive,
    matrix_schemes,
    prior_schemes,
    single_byte_xor_schemes,
)

MEDIAPLAYER2_SEED = 3664888858717910997
MEDIAPLAYER2_STEM = "3664888858717845462"
RTO_KEY_HEX = "6eada2ac127d60e3c17e4940981c5bc6"  # tests/test_framework.py
RTO_IV_HEX = "d0045d33d393892263a7b43ccac6e578"   # tests/test_framework.py


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
        assert key.hex() == RTO_KEY_HEX and iv.hex() == RTO_IV_HEX

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
        assert len(list(matrix_schemes("seed", "test"))) == 79

    def test_matrix_uses_framework_key_truncation_rules(self):
        schemes = list(matrix_schemes("seed", "test"))
        assert {s.key_len for s in schemes if s.key_hash == "md5"} == {16}  # md5 digest is 16 bytes
        assert {s.key_len for s in schemes if s.key_hash == "sha256"} == set(KEY_LENGTHS)

    def test_matrix_carries_provenance_and_covers_every_cipher(self):
        schemes = list(matrix_schemes("seed", "mined"))
        assert {s.provenance for s in schemes} == {"mined"}
        assert {s.cipher for s in schemes} == {"aes-cbc", "aes-ecb", "xor", "rc4"}
        assert all(s.seed == "seed" for s in schemes)

    def test_single_byte_xor_is_256_seed_independent_candidates(self):
        schemes = list(single_byte_xor_schemes())
        assert len(schemes) == 256
        assert all(s.cipher == "xor" and s.xor_mode == "byte" for s in schemes)
        assert {int(s.seed) for s in schemes} == set(range(256))


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
        ct = bytes(a ^ b for a, b in zip(pt, JavaRandom(MEDIAPLAYER2_SEED).keystream(len(pt))))
        assert decrypt(scheme, ct) == pt


def _make_apk(path, members: dict) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)


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
