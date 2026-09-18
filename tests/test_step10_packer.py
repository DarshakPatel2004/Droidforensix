import json
import zipfile

import pytest

from analysis.step10_binary_packing import (
    MARKERS_PATH,
    detect_binary_packing,
    match_packer_brands,
)


@pytest.fixture(scope="module")
def markers():
    with open(MARKERS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def test_marker_file_schema(markers):
    brands = markers.get("brands")
    assert brands, "packer_markers.json must define a non-empty brands list"
    for brand in brands:
        assert isinstance(brand.get("name"), str) and brand["name"].strip()
        marker_list = brand.get("markers", [])
        assert isinstance(marker_list, list) and marker_list
        assert all(isinstance(m, str) and m.strip() for m in marker_list)


def _make_apk(tmp_path, entries):
    apk_path = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return str(apk_path)


def test_brand_matched_from_entry_names(tmp_path):
    apk_path = _make_apk(
        tmp_path,
        {
            "classes.dex": b"zycom.tencent.stubshellqy",
            "libsecexe.so": b"\x00",
            "com/secneo/apkwrapper/": b"\x00",
        },
    )
    result = detect_binary_packing({"apk_path": apk_path})
    names = {b["name"] for b in result["packer_brands"]}
    assert {"Bangcle/SecNeo", "TencentLegu"} <= names


def test_brand_matched_from_dex_bytes(tmp_path):
    apk_path = _make_apk(
        tmp_path, {"classes.dex": b"some string com.secneo.apkwrapper another"}
    )
    result = detect_binary_packing({"apk_path": apk_path})
    names = {b["name"] for b in result["packer_brands"]}
    assert "Bangcle/SecNeo" in names


def test_no_markers_yields_no_brands(tmp_path):
    apk_path = _make_apk(
        tmp_path,
        {"classes.dex": b"\x00", "res/layout/main.xml": b"\x00", "AndroidManifest.xml": b"\x00"},
    )
    result = detect_binary_packing({"apk_path": apk_path})
    assert result["packer_brands"] == []
    assert result["packing_detected"] is False


def test_missing_apk_returns_empty_brands():
    result = detect_binary_packing({"apk_path": "/nonexistent/sample.apk"})
    assert result["packer_brands"] == []
    assert result["error"]