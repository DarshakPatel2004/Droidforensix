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
        # keystream = nextInt() as 4-byte little-endian. The member lies about being
        # encrypted; inflating its stored bytes yields the ciphertext, and XORing that with
        # this keystream yields a ZIP whose sha256 is the pinned ground truth
        # 5b5697c9a04c3ff1fab618abaf1002af68244ac7b39dc6ff17fdaa41b0139b5e.
        ks = JavaRandom(MEDIAPLAYER2_SEED).keystream(16)
        assert ks == bytes.fromhex("e04ccdce1cdaf4a619c669831f8034b2")

    def test_keystream_prefix_stability(self):
        r = JavaRandom(MEDIAPLAYER2_SEED)
        assert r.keystream(8) == JavaRandom(MEDIAPLAYER2_SEED).keystream(16)[:8]
