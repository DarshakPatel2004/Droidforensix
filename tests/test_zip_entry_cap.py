"""Zip-bomb guard: oversized entries are skipped before decompression (audit A1-20, B2-02)."""
import zipfile

from analysis import step8_obfuscation_analysis as step8


def test_oversized_entry_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(step8, "MAX_ZIP_ENTRY_BYTES", 10)
    apk = tmp_path / "a.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("big.so", b"x" * 100)
        z.writestr("small.so", b"y")
    with zipfile.ZipFile(apk) as z:
        assert step8._read_capped(z, "big.so") is None
        assert step8._read_capped(z, "small.so") == b"y"
