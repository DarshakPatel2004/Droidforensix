"""Encrypted zip-member handling in triage heuristics (h2/h3/h5).

zipfile raises RuntimeError on encrypted members. Before the fix this
killed the whole triage (3 pendrive dropper samples: Tubi-inin,
Google Video, MediaPlayer2 - one has an encrypted classes.dex). The
heuristics must skip unreadable members and record the fact instead.
"""

import io

import pytest

from scripts import triage


class FakeInfo:
    def __init__(self, filename, file_size, flag_bits=0):
        self.filename = filename
        self.file_size = file_size
        self.flag_bits = flag_bits


class FakeZip:
    """Members with flag_bits=1 must never be opened (open() asserts)."""

    def __init__(self, infos, contents=None):
        self._infos = infos
        self._contents = contents or {}

    def infolist(self):
        return self._infos

    def namelist(self):
        return [i.filename for i in self._infos]

    def getinfo(self, name):
        for info in self._infos:
            if info.filename == name:
                return info
        raise KeyError(name)

    def open(self, name):
        info = name if isinstance(name, FakeInfo) else self.getinfo(name)
        assert not info.flag_bits & 0x1, "encrypted member must not be opened"
        return io.BytesIO(self._contents[info.filename])


def test_h2_skips_encrypted_assets_and_records_count():
    size = max(triage.BIG_ASSET_MIN, triage.ENTROPY_WINDOW)
    encrypted = FakeInfo("assets/blob.bin", size + 1, flag_bits=1)
    normal = FakeInfo("assets/normal.bin", size, flag_bits=0)
    zf = FakeZip([encrypted, normal],
                 {"assets/normal.bin": b"\x00" * size})

    result = triage.h2_asset_entropy(zf)

    expected_windows = (min(triage.ENTROPY_WINDOW * 1024, size)
                         // triage.ENTROPY_WINDOW)
    assert result["encrypted_skipped"] == 1
    assert result["total_windows"] == expected_windows
    assert result["hit"] is False  # zero-filled windows -> entropy 0.0
    assert "encrypted_skipped" in result


def test_h2_all_encrypted_yields_no_hit_not_crash():
    encrypted = FakeInfo("assets/blob.bin", 10_000_000, flag_bits=1)
    result = triage.h2_asset_entropy(FakeZip([encrypted]))

    assert result["encrypted_skipped"] == 1
    assert result["total_windows"] == 0
    assert result["mean"] == 0.0
    assert result["hit"] is False


def test_h3_encrypted_dex_returns_reason_not_crash(monkeypatch, tmp_path):
    class FakeAPK:
        def __init__(self, _path):
            pass

        def get_attribute_value(self, _tag, _attr):
            return "com.example.App"

    monkeypatch.setattr(triage, "APK", FakeAPK)  # h3 uses module-level binding
    dex = FakeInfo("classes.dex", 1_000, flag_bits=1)
    zf = FakeZip([dex])

    result = triage.h3_native_app_class(zf, str(tmp_path / "x.apk"))

    assert result["hit"] is False
    assert result["reason"] == "dex_encrypted"
    assert result["app_class"] == "com.example.App"


def test_h5_encrypted_dex_still_matches_filename_markers(monkeypatch):
    dex = FakeInfo("classes.dex", 1_000, flag_bits=1)
    marker = FakeInfo("assets/enbggf", 10, flag_bits=0)  # filename marker
    markers = {"brands": [{"name": "TestBrand", "markers": ["enbggf"]}]}
    # open() would assert on the encrypted dex; filename path must not need it
    result = triage.h5_packer_markers(FakeZip([dex, marker]), markers)

    assert result["matched"] == [{"brand": "TestBrand",
                                  "markers": ["enbggf"]}]
