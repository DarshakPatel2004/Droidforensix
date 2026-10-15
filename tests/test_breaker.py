"""Tests for the master key breaker (packers/breaker/)."""
import hashlib

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
