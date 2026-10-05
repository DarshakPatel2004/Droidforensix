"""ZipCrypto flag-lie handling in triage heuristics (h2/h3/h5, _elf_facts).

The pendrive "ZipCrypto trio" (Tubi-inin, Google Video, MediaPlayer2)
sets encryption bit 0x1 on plaintext, CRC-valid entries - zipfile
refuses those outright, which used to kill the whole triage. Heuristics
now defuse the flag via triage._open_member and let zlib/CRC decide:
flag-lying members are read normally; genuinely unreadable members are
recorded (counts / reasons) instead of crashing.
"""

import io

import pytest  # noqa: F401  (kept: pytest used via monkeypatch/tmp_path)

from scripts import triage


class FakeInfo:
    def __init__(self, filename, file_size, flag_bits=0):
        self.filename = filename
        self.file_size = file_size
        self.flag_bits = flag_bits


class _BrokenFH:
    """Mimics a genuinely encrypted member: open succeeds, read fails."""

    def seek(self, _pos):
        pass

    def read(self, _n=-1):
        raise RuntimeError("File is encrypted, password required for extraction")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeZip:
    """open() asserts the flag-lie was defused before opening; members in
    `broken` fail on read like real zip encryption does."""

    def __init__(self, infos, contents=None, broken=()):
        self._infos = infos
        self._contents = contents or {}
        self._broken = set(broken)

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
        assert not info.flag_bits & 0x1, "flag-lie must be defused before open"
        if info.filename in self._broken:
            return _BrokenFH()
        return io.BytesIO(self._contents[info.filename])


class FakeAPK:
    def __init__(self, _path):
        pass

    def get_attribute_value(self, _tag, _attr):
        return "com.example.App"


def test_h2_defuses_flag_lie_and_reads_member():
    size = max(triage.BIG_ASSET_MIN, triage.ENTROPY_WINDOW)
    lie = FakeInfo("assets/lie.bin", size + 1, flag_bits=1)
    zf = FakeZip([lie], {"assets/lie.bin": b"\x00" * (size + 1)})

    result = triage.h2_asset_entropy(zf)

    assert lie.flag_bits & 0x1 == 0  # flag defused in place
    assert result["encrypted_skipped"] == 0  # member was readable
    assert result["total_windows"] > 0  # and actually scanned
    assert result["hit"] is False  # zero-filled windows -> entropy 0.0


def test_h2_records_genuinely_unreadable_member_not_crash():
    size = max(triage.BIG_ASSET_MIN, triage.ENTROPY_WINDOW)
    broken = FakeInfo("assets/enc.bin", size + 1, flag_bits=1)
    normal = FakeInfo("assets/ok.bin", size, flag_bits=0)
    zf = FakeZip([broken, normal],
                 {"assets/ok.bin": b"\x00" * size},
                 broken=["assets/enc.bin"])

    result = triage.h2_asset_entropy(zf)

    assert result["encrypted_skipped"] == 1
    assert result["total_windows"] > 0  # the readable member still ran
    assert result["hit"] is False
    assert "encrypted_skipped" in result


def test_h3_reads_flag_lie_dex(monkeypatch, tmp_path):
    monkeypatch.setattr(triage, "APK", FakeAPK)  # h3 uses module-level binding
    dex = FakeInfo("classes.dex", 1_000, flag_bits=1)
    zf = FakeZip([dex], {"classes.dex": b"dex\n035\x00" + b"\x00" * 992})

    result = triage.h3_native_app_class(zf, str(tmp_path / "x.apk"))

    assert result.get("reason") != "dex_encrypted"
    assert result["dex_bytes"] == 1_000  # readable: full dex counted
    assert result["app_class"] == "com.example.App"


def test_h3_unreadable_dex_returns_reason_not_crash(monkeypatch, tmp_path):
    monkeypatch.setattr(triage, "APK", FakeAPK)  # h3 uses module-level binding
    dex = FakeInfo("classes.dex", 1_000, flag_bits=1)
    zf = FakeZip([dex], broken=["classes.dex"])

    result = triage.h3_native_app_class(zf, str(tmp_path / "x.apk"))

    assert result["hit"] is False
    assert result["reason"] == "dex_encrypted"
    assert result["app_class"] == "com.example.App"


def test_h5_reads_flag_lie_dex_blob_for_content_markers():
    dex = FakeInfo("classes.dex", 100, flag_bits=1)
    marker = FakeInfo("assets/data.bin", 10, flag_bits=0)
    markers = {"brands": [{"name": "TestBrand", "markers": ["BlobMark"]}]}
    zf = FakeZip([dex, marker],
                 {"classes.dex": b"xx blobmark xx", "assets/data.bin": b""})

    result = triage.h5_packer_markers(zf, markers)

    # matched from dex-blob CONTENT: only possible if the flag-lie was read
    assert result["matched"] == [{"brand": "TestBrand",
                                  "markers": ["BlobMark"]}]


def test_h5_unreadable_dex_still_matches_filename_markers():
    dex = FakeInfo("classes.dex", 1_000, flag_bits=1)
    marker = FakeInfo("assets/enbggf", 10, flag_bits=0)  # filename marker
    markers = {"brands": [{"name": "TestBrand", "markers": ["enbggf"]}]}
    zf = FakeZip([dex, marker], broken=["classes.dex"])

    result = triage.h5_packer_markers(zf, markers)

    assert result["matched"] == [{"brand": "TestBrand",
                                  "markers": ["enbggf"]}]


def test_elf_facts_defuses_flag_lie_without_crash():
    so = FakeInfo("lib/x.so", 100, flag_bits=1)
    zf = FakeZip([so], {"lib/x.so": b"\x7fELF" + b"\x00" * 96})

    parsed = triage._elf_facts(zf, "lib/x.so")  # garbage ELF -> warn + None

    assert so.flag_bits & 0x1 == 0  # attempted, not refused up front
    assert parsed is None
