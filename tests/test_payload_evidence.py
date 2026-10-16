"""Unit tests for analysis/payload_evidence.py (spec 2026-10-16)."""
import io
import zipfile

import pytest

from analysis import payload_evidence as pe


def _zip(members: dict[str, bytes]) -> bytes:
    """A payload ZIP; infolist() preserves this insertion order."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def test_native_lib_names_matches_lib_path_so_suffix_and_elf_magic():
    assert pe.native_lib_names("lib/arm64-v8a/libx.so", b"") == ["lib/arm64-v8a/libx.so"]
    assert pe.native_lib_names("assets/x.so", b"") == ["assets/x.so"]
    assert pe.native_lib_names("arm64-v8a", b"\x7fELFrest") == ["arm64-v8a"]
    assert pe.native_lib_names("res/drawable/icon.png", b"\x89PNG") == []


def test_class_count_from_dex_rejects_undecodable_bytes():
    with pytest.raises(Exception):
        pe.class_count_from_dex(b"not a dex at all")


def test_permissions_from_binary_manifest_rejects_non_axml():
    with pytest.raises(Exception):
        pe.permissions_from_binary_manifest(b"not xml")


def test_collect_ignores_payloads_without_zip_magic():
    evidence = pe.collect_payload_evidence([b"not a zip at all"])
    assert evidence["payloads"] == 0
    assert evidence["members_scanned"] == 0
    assert evidence["truncated"] == "none"
    assert evidence["errors"] == []


def test_collect_records_a_broken_zip_and_keeps_going():
    broken = b"PK\x03\x04" + b"garbage-central-directory"
    good = _zip({"lib/armeabi-v7a/libx.so": b"\x7fELF" + b"\x00" * 8})
    evidence = pe.collect_payload_evidence([broken, good])
    assert evidence["payloads"] == 1
    assert evidence["native_libs"] == ["lib/armeabi-v7a/libx.so"]
    assert any("BadZipFile" in e or "payload 0" in e for e in evidence["errors"])


def test_collect_skips_zero_byte_dex_without_an_error():
    evidence = pe.collect_payload_evidence([_zip({"classes.dex": b""})])
    assert evidence["class_count"] == 0
    assert evidence["errors"] == []
    assert evidence["members_scanned"] == 1


def test_collect_records_dex_and_manifest_parse_failures():
    payload = _zip({"classes.dex": b"x" * 16, "AndroidManifest.xml": b"nope"})
    evidence = pe.collect_payload_evidence([payload])
    assert evidence["class_count"] == 0
    assert evidence["permissions"] == []
    assert len(evidence["errors"]) == 2


def test_collect_finds_natives_by_path_and_by_elf_magic():
    payload = _zip({
        "lib/armeabi-v7a/libx.so": b"\x00" * 8,
        "assets/arm64": b"\x7fELF" + b"\x00" * 8,
        "res/raw/a.bin": b"data",
    })
    evidence = pe.collect_payload_evidence([payload])
    assert evidence["native_libs"] == ["assets/arm64", "lib/armeabi-v7a/libx.so"]
    assert evidence["members_scanned"] == 3


def test_collect_stops_at_the_per_member_size_cap():
    payload = _zip({"classes.dex": b"x" * 16, "assets/big.bin": b"y" * 16})
    evidence = pe.collect_payload_evidence([payload], max_member_bytes=8)
    assert evidence["truncated"] == "bytes"
    assert evidence["members_scanned"] == 2
    assert evidence["members_skipped"] == 2
    assert evidence["class_count"] == 0


def test_collect_stops_at_the_total_bytes_cap():
    payload = _zip({"classes.dex": b"x" * 16, "assets/big.bin": b"y" * 16})
    evidence = pe.collect_payload_evidence([payload], max_payload_bytes=8)
    assert evidence["truncated"] == "bytes"
    assert evidence["members_scanned"] == 1
    assert evidence["members_skipped"] == 1


def test_collect_caps_dex_members_without_stopping_other_members():
    members = {f"classes{i}.dex": b"x" * 16 for i in range(3)}
    members["lib/armeabi-v7a/libx.so"] = b"\x00" * 8
    evidence = pe.collect_payload_evidence([_zip(members)], max_dex_members=1)
    assert evidence["truncated"] == "members"
    assert evidence["members_skipped"] == 2
    assert evidence["native_libs"] == ["lib/armeabi-v7a/libx.so"], "natives still collected"


def test_dex_cap_is_per_payload():
    # A per-sample counter would skip the second payload's dex too (members_skipped == 2).
    first = _zip({"a.dex": b"x" * 4, "b.dex": b"x" * 4})
    second = _zip({"c.dex": b"x" * 4})
    evidence = pe.collect_payload_evidence([first, second], max_dex_members=1)
    assert evidence["payloads"] == 2
    assert evidence["members_skipped"] == 1, "the second payload gets its own dex budget"


def test_collect_stops_at_the_budget_cap():
    evidence = pe.collect_payload_evidence([_zip({"classes.dex": b"x" * 4})], budget_s=0.0)
    assert evidence["truncated"] == "budget"
    assert evidence["members_scanned"] == 0
    assert evidence["payloads"] == 0


def test_truncated_keeps_the_first_cap_that_bites():
    # member-size cap bites on the first member; the dex cap must not overwrite it
    payload = _zip({"a.bin": b"y" * 16, "classes.dex": b"x" * 4})
    evidence = pe.collect_payload_evidence([payload], max_member_bytes=8, max_dex_members=0)
    assert evidence["truncated"] == "bytes"
    assert evidence["members_skipped"] == 2


def test_nested_apk_members_contribute_nothing():
    payload = _zip({"payload_split0.apk": _zip({"classes.dex": b"x" * 16})})
    evidence = pe.collect_payload_evidence([payload])
    assert evidence["class_count"] == 0
    assert evidence["permissions"] == []
    assert evidence["errors"] == []
    assert evidence["members_scanned"] == 1


def test_collect_is_deterministic():
    payload = _zip({"lib/x.so": b"\x00", "classes.dex": b"x" * 8})
    first = pe.collect_payload_evidence([payload])
    assert first == pe.collect_payload_evidence([payload])
