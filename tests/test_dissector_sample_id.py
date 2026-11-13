"""B2-10: a validated 64-hex sample id is reused, so the APK is not re-hashed per request."""

from backend.dissection import APKDissector

GOOD = "ab" * 32


def test_validated_sample_id_skips_hashing(tmp_path):
    missing_apk = tmp_path / "does_not_exist.apk"  # hashing would raise FileNotFoundError
    dissector = APKDissector(str(missing_apk), work_dir=str(tmp_path), sample_id=GOOD)
    assert dissector._sample_id_from_apk() == GOOD


def test_non_hex_id_is_still_computed_from_apk(tmp_path):
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"PK\x03\x04")
    dissector = APKDissector(str(apk), work_dir=str(tmp_path), sample_id="upload-123")
    assert dissector._sample_id_from_apk() != "upload-123"
    assert len(dissector._sample_id_from_apk()) == 64
