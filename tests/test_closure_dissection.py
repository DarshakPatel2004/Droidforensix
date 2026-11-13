"""Dissection tests that run on a synthetic APK (T-06).

tests/test_dissection.py skips every APK-dependent test when
samples/goodware/benign_eval is absent, which is always true in CI. This module
builds a small APK in tmp_path with zipfile: a binary AndroidManifest.xml (the
format androguard requires), a minimal DEX with class definitions, and a native
lib. The same code paths that the skipped tests exercise then run everywhere.

Limits of the synthetic APK: its DEX classes have no methods or fields, so the
method-body and bytecode paths are not covered here. Those still need a real
sample.
"""

import hashlib
import json
import struct
import threading
import uuid
import zipfile
import zlib

import pytest
from fastapi.testclient import TestClient

from backend.config import settings
from backend.dissection import APKDissector, SampleAPKCache
from backend.main import app

ANDROID_URI = "http://schemas.android.com/apk/res/android"
ATTR_IDS = {
    "name": 0x01010003,
    "label": 0x01010001,
    "exported": 0x01010010,
    "versionCode": 0x0101021B,
    "versionName": 0x0101021C,
    "minSdkVersion": 0x0101020C,
    "targetSdkVersion": 0x01010270,
}
CLASS_DESCRIPTORS = ["Lcom/example/closure/Stub;", "Lcom/example/closure/Other;"]
CLASS_NAMES = ["com.example.closure.Other", "com.example.closure.Stub"]


# ---------------------------------------------------------------------------
# Binary AXML (AndroidManifest.xml) encoder
# ---------------------------------------------------------------------------


def _string_pool(strings):
    offsets, body = [], b""
    for s in strings:
        offsets.append(len(body))
        body += struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\x00\x00"
    body += b"\x00" * ((4 - len(body) % 4) % 4)
    string_start = 28 + 4 * len(strings)
    head = struct.pack("<HHIIIIII", 0x0001, 28, string_start + len(body), len(strings), 0, 0, string_start, 0)
    return head + b"".join(struct.pack("<I", o) for o in offsets) + body


def encode_axml(root) -> bytes:
    """Encode (tag, attrs, children) as binary XML. attrs: (ns_uri|None, name, str|int)."""
    strings = [ANDROID_URI, "android"]
    index = {}

    def sidx(text):
        if text not in index:
            index[text] = len(strings)
            strings.append(text)
        return index[text]

    def register(node):
        tag, attrs, children = node
        sidx(tag)
        for _ns, name, value in attrs:
            sidx(name)
            if isinstance(value, str):
                sidx(value)
        for child in children:
            register(child)

    register(root)
    android, uri = sidx("android"), sidx(ANDROID_URI)

    def start_element(tag, attrs):
        attr_bytes = b""
        for ns, name, value in attrs:
            ns_idx = uri if ns else 0xFFFFFFFF
            name_idx = sidx(name)
            if isinstance(value, int):
                raw, dtype, data = 0xFFFFFFFF, 0x10, value
            else:
                raw = sidx(value)
                dtype, data = 0x03, raw
            attr_bytes += struct.pack("<IIIHBBI", ns_idx, name_idx, raw, 8, 0, dtype, data)
        ext = struct.pack("<IIHHHHHH", 0xFFFFFFFF, sidx(tag), 20, 20, len(attrs), 0, 0, 0)
        size = 16 + len(ext) + len(attr_bytes)
        return struct.pack("<HHIII", 0x0102, 16, size, 1, 0xFFFFFFFF) + ext + attr_bytes

    def end_element(tag):
        return struct.pack("<HHIIIII", 0x0103, 16, 24, 1, 0xFFFFFFFF, 0xFFFFFFFF, sidx(tag))

    nodes = bytearray(struct.pack("<HHIIIII", 0x0100, 16, 24, 1, 0xFFFFFFFF, android, uri))

    def emit(node):
        tag, attrs, children = node
        nodes.extend(start_element(tag, attrs))
        for child in children:
            emit(child)
        nodes.extend(end_element(tag))

    emit(root)
    nodes += struct.pack("<HHIIIII", 0x0101, 16, 24, 1, 0xFFFFFFFF, android, uri)

    pool = _string_pool(strings)
    ids = [ATTR_IDS.get(s, 0) for s in strings]
    rmap = struct.pack("<HHI", 0x0180, 8, 8 + 4 * len(ids)) + b"".join(struct.pack("<I", i) for i in ids)
    body = pool + rmap + bytes(nodes)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


MANIFEST = (
    "manifest",
    [(None, "package", "com.example.closure"), (ANDROID_URI, "versionCode", 7), (ANDROID_URI, "versionName", "1.2")],
    [
        ("uses-sdk", [(ANDROID_URI, "minSdkVersion", 21), (ANDROID_URI, "targetSdkVersion", 33)], []),
        ("uses-permission", [(ANDROID_URI, "name", "android.permission.INTERNET")], []),
        ("application", [(ANDROID_URI, "label", "Closure")], [
            ("activity", [(ANDROID_URI, "name", ".MainActivity"), (ANDROID_URI, "exported", "true")], []),
            ("receiver", [(ANDROID_URI, "name", ".BootReceiver")], []),
            ("service", [(ANDROID_URI, "name", "com.example.closure.SyncService")], []),
        ]),
    ],
)


# ---------------------------------------------------------------------------
# Minimal DEX encoder: one class per descriptor, no methods, fields or protos
# ---------------------------------------------------------------------------


def _uleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def build_dex(descriptors) -> bytes:
    n = len(descriptors)
    s_off = 0x70
    t_off = s_off + 4 * n
    c_off = t_off + 4 * n
    d_off = c_off + 32 * n

    encoded = [_uleb128(len(d)) + d.encode("ascii") + b"\x00" for d in descriptors]
    offsets, cursor = [], d_off
    for chunk in encoded:
        offsets.append(cursor)
        cursor += len(chunk)
    string_data = b"".join(encoded)

    pad = b"\x00" * ((4 - (d_off + len(string_data)) % 4) % 4)
    map_off = d_off + len(string_data) + len(pad)
    # Map list: androguard finds the class and string tables through it.
    entries = [
        (0x0000, 1, 0),        # header
        (0x0001, n, s_off),    # string_id_item
        (0x0002, n, t_off),    # type_id_item
        (0x0006, n, c_off),    # class_def_item
        (0x2002, n, d_off),    # string_data_item
        (0x1000, 1, map_off),  # map_list
    ]
    map_bytes = struct.pack("<I", len(entries)) + b"".join(
        struct.pack("<HHII", t, 0, count, off) for t, count, off in entries
    )
    end = map_off + len(map_bytes)

    header = bytearray(0x70)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 0x20, end)
    struct.pack_into("<I", header, 0x24, 0x70)
    struct.pack_into("<I", header, 0x28, 0x12345678)
    struct.pack_into("<II", header, 0x38, n, s_off)
    struct.pack_into("<II", header, 0x40, n, t_off)
    struct.pack_into("<II", header, 0x60, n, c_off)
    struct.pack_into("<II", header, 0x68, end - d_off, d_off)
    struct.pack_into("<I", header, 0x34, map_off)

    string_ids = b"".join(struct.pack("<I", off) for off in offsets)
    type_ids = b"".join(struct.pack("<I", i) for i in range(n))
    class_defs = b"".join(
        struct.pack("<IIIIIIII", i, 1, 0xFFFFFFFF, 0, 0xFFFFFFFF, 0, 0, 0) for i in range(n)
    )
    dex = bytearray(bytes(header) + string_ids + type_ids + class_defs + string_data + pad + map_bytes)
    # Signature covers bytes 32 onward; checksum covers bytes 12 onward (after itself).
    dex[12:32] = hashlib.sha1(bytes(dex[32:])).digest()
    struct.pack_into("<I", dex, 8, zlib.adler32(bytes(dex[12:])) & 0xFFFFFFFF)
    return bytes(dex)


def empty_dex() -> bytes:
    return build_dex([])


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def synthetic_apk(tmp_path):
    path = tmp_path / "closure.apk"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", encode_axml(MANIFEST))
        z.writestr("classes.dex", build_dex(CLASS_DESCRIPTORS))
        z.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF" + b"\x00" * 60)
    return path


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def dissected_sample(synthetic_apk):
    """A pipeline_result pointing at the synthetic APK, under a unique sample id."""
    sample_id = hashlib.sha256(f"closure-dissection-{uuid.uuid4()}".encode()).hexdigest()
    sample_dir = settings.WORK_DIR / sample_id
    sample_dir.mkdir(parents=True, exist_ok=True)
    result = {
        "sample_id": sample_id,
        "metadata": {
            "sample_name": "closure.apk",
            "apk_path": str(synthetic_apk),
            "package_name": "com.example.closure",
        },
        "family_identification": {"family": "unknown"},
    }
    (sample_dir / "pipeline_result.json").write_text(json.dumps(result), encoding="utf-8")
    return sample_id


# ---------------------------------------------------------------------------
# APKDissector on the synthetic APK
# ---------------------------------------------------------------------------


class TestSyntheticDissector:
    def test_dissect_returns_expected_keys_and_serialises(self, synthetic_apk):
        data = APKDissector(str(synthetic_apk)).dissect()
        for key in ("metadata", "manifest", "permissions", "components",
                    "native_libs", "resources", "dex_stats", "file_structure"):
            assert key in data
        json.dumps(data)

    def test_metadata_reads_manifest_attributes(self, synthetic_apk):
        meta = APKDissector(str(synthetic_apk)).extract_metadata()
        assert meta["package_name"] == "com.example.closure"
        assert meta["file_size_bytes"] == synthetic_apk.stat().st_size
        assert meta["version_code"] == "7"
        assert meta["version_name"] == "1.2"
        assert meta["min_sdk_version"] == "21"
        assert meta["target_sdk_version"] == "33"

    def test_permissions_include_declared_internet(self, synthetic_apk):
        perms = APKDissector(str(synthetic_apk)).extract_permissions()
        names = {p["name"] for p in perms}
        assert "android.permission.INTERNET" in names
        for perm in perms:
            assert perm["protection_level"] in {"dangerous", "signature", "normal", "unknown"}

    def test_components_keep_manifest_names_and_export_flag(self, synthetic_apk):
        comps = APKDissector(str(synthetic_apk)).extract_components()
        # Names are reported as written in the manifest; the leading-dot form is not expanded.
        assert [a["name"] for a in comps["activities"]] == [".MainActivity"]
        assert comps["activities"][0]["exported"] is True
        assert [r["name"] for r in comps["receivers"]] == [".BootReceiver"]
        assert [s["name"] for s in comps["services"]] == ["com.example.closure.SyncService"]

    def test_dex_stats_count_classes_and_zero_methods(self, synthetic_apk):
        stats = APKDissector(str(synthetic_apk)).extract_dex_stats()
        assert stats["dex_count"] == 1
        assert stats["total_classes"] == len(CLASS_DESCRIPTORS)
        assert stats["total_methods"] == 0
        assert 0 <= stats["entropy"] <= 8

    def test_native_lib_is_listed_with_its_arch(self, synthetic_apk):
        libs = APKDissector(str(synthetic_apk)).extract_native_libs()
        assert [lib["name"] for lib in libs] == ["libnative.so"]
        assert "arm64-v8a" in libs[0]["path"]

    def test_class_listing_is_sorted_dotted_names(self, synthetic_apk):
        assert APKDissector(str(synthetic_apk)).list_decompiled_classes() == CLASS_NAMES

    def test_class_objects_have_no_methods(self, synthetic_apk):
        objects = APKDissector(str(synthetic_apk), work_dir=str(settings.WORK_DIR)).list_decompiled_class_objects()
        assert [o["name"] for o in objects] == CLASS_NAMES
        assert all(o["methods"] == [] for o in objects)

    def test_empty_dex_yields_no_classes(self, tmp_path):
        path = tmp_path / "empty.apk"
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("AndroidManifest.xml", encode_axml(MANIFEST))
            z.writestr("classes.dex", empty_dex())
        assert APKDissector(str(path)).list_decompiled_classes() == []


class TestSyntheticSampleApkCache:
    def test_cache_hit_returns_same_object(self, synthetic_apk):
        cache = SampleAPKCache()
        apk1, sha1 = cache.get_or_parse("closure_hit", str(synthetic_apk))
        apk2, sha2 = cache.get_or_parse("closure_hit", str(synthetic_apk))
        assert apk2 is apk1
        assert sha1 == sha2 == hashlib.sha256(synthetic_apk.read_bytes()).hexdigest()

    def test_invalidate_forces_reparse(self, synthetic_apk):
        cache = SampleAPKCache()
        apk1, _ = cache.get_or_parse("closure_inval", str(synthetic_apk))
        cache.invalidate("closure_inval")
        apk2, _ = cache.get_or_parse("closure_inval", str(synthetic_apk))
        assert apk2 is not apk1

    def test_separate_sample_ids_do_not_share_objects(self, synthetic_apk):
        cache = SampleAPKCache()
        apk_a, sha_a = cache.get_or_parse("closure_a", str(synthetic_apk))
        apk_b, sha_b = cache.get_or_parse("closure_b", str(synthetic_apk))
        assert apk_a is not apk_b
        assert sha_a == sha_b

    def test_concurrent_parsing_is_safe(self, synthetic_apk):
        cache = SampleAPKCache()
        errors = []
        lock = threading.Lock()

        def parse(idx):
            try:
                apk, _ = cache.get_or_parse(f"closure_thread_{idx}", str(synthetic_apk))
                assert apk is not None
            except Exception as exc:  # collected and asserted below
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=parse, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []


# ---------------------------------------------------------------------------
# Dissection endpoints, with the APK reached through metadata.apk_path
# ---------------------------------------------------------------------------


class TestSyntheticDissectionEndpoints:
    def test_full_dissection_is_served_and_cached_on_disk(self, client, dissected_sample):
        resp = client.get(f"/api/sample/{dissected_sample}/dissection")
        assert resp.status_code == 200
        data = resp.json()
        assert data["metadata"]["package_name"] == "com.example.closure"
        assert "permissions" in data and "dex_stats" in data
        assert (settings.WORK_DIR / dissected_sample / "dissection.json").exists()

    def test_cached_dissection_is_served_without_the_apk(self, client, dissected_sample, synthetic_apk):
        assert client.get(f"/api/sample/{dissected_sample}/dissection").status_code == 200
        synthetic_apk.unlink()
        resp = client.get(f"/api/sample/{dissected_sample}/dissection")
        assert resp.status_code == 200
        assert resp.json()["metadata"]["package_name"] == "com.example.closure"

    def test_manifest_endpoint(self, client, dissected_sample):
        resp = client.get(f"/api/sample/{dissected_sample}/dissection/manifest")
        assert resp.status_code == 200
        assert resp.json()["manifest"]["package"] == "com.example.closure"

    def test_permissions_endpoint(self, client, dissected_sample):
        resp = client.get(f"/api/sample/{dissected_sample}/dissection/permissions")
        assert resp.status_code == 200
        names = [p["name"] for p in resp.json()["permissions"]]
        assert "android.permission.INTERNET" in names

    def test_components_endpoint(self, client, dissected_sample):
        resp = client.get(f"/api/sample/{dissected_sample}/dissection/components")
        assert resp.status_code == 200
        assert "activities" in resp.json()["components"]

    def test_dex_endpoint_reports_class_count(self, client, dissected_sample):
        resp = client.get(f"/api/sample/{dissected_sample}/dissection/dex")
        assert resp.status_code == 200
        assert resp.json()["dex_stats"]["total_classes"] == len(CLASS_DESCRIPTORS)

    def test_classes_endpoint_pagination_defaults(self, client, dissected_sample):
        data = client.get(f"/api/sample/{dissected_sample}/dissection/classes").json()
        assert data["offset"] == 0 and data["limit"] == 50
        assert data["total"] == len(CLASS_DESCRIPTORS)
        assert [c["name"] for c in data["classes"]] == CLASS_NAMES

    def test_classes_endpoint_second_page(self, client, dissected_sample):
        first = client.get(f"/api/sample/{dissected_sample}/dissection/classes?offset=0&limit=1").json()
        second = client.get(f"/api/sample/{dissected_sample}/dissection/classes?offset=1&limit=1").json()
        assert [c["name"] for c in first["classes"]] == [CLASS_NAMES[0]]
        assert [c["name"] for c in second["classes"]] == [CLASS_NAMES[1]]

    def test_classes_endpoint_refresh_rebuilds(self, client, dissected_sample):
        resp = client.get(f"/api/sample/{dissected_sample}/dissection/classes?refresh=true")
        assert resp.status_code == 200
        assert resp.json()["total"] == len(CLASS_DESCRIPTORS)

    @pytest.mark.parametrize("query", ["limit=999", "offset=-1"])
    def test_out_of_range_pagination_is_rejected(self, client, dissected_sample, query):
        resp = client.get(f"/api/sample/{dissected_sample}/dissection/classes?{query}")
        assert resp.status_code == 422

    def test_class_code_endpoint_returns_header_only_for_method_less_class(self, client, dissected_sample):
        # The class resolves, so the endpoint serves a disassembly header with no method bodies.
        resp = client.get(f"/api/sample/{dissected_sample}/dissection/code/com.example.closure.Stub")
        assert resp.status_code == 200
        data = resp.json()
        assert data["class_name"] == "com.example.closure.Stub"
        assert "Disassembled DEX Class via Androguard" in data["code"]

    def test_class_code_endpoint_missing_class_is_404(self, client, dissected_sample):
        resp = client.get(f"/api/sample/{dissected_sample}/dissection/code/DefinitelyNotARealClass")
        assert resp.status_code == 404

    def test_strings_endpoint_serves_step2_output(self, client, dissected_sample):
        strings_path = settings.WORK_DIR / dissected_sample / "step2_strings.json"
        strings_path.write_text(json.dumps({"categories": {"urls": ["https://example.com"]}}), encoding="utf-8")
        resp = client.get(f"/api/sample/{dissected_sample}/dissection/strings")
        assert resp.status_code == 200
        assert resp.json()["categories"] == {"urls": ["https://example.com"]}

    def test_strings_endpoint_404_without_step2_output(self, client, dissected_sample):
        assert client.get(f"/api/sample/{dissected_sample}/dissection/strings").status_code == 404

    def test_dissection_404_for_unknown_sample(self, client):
        assert client.get("/api/sample/nonexistent_sample_id/dissection").status_code == 404

    def test_dissection_404_when_apk_is_gone_and_no_cache(self, client, dissected_sample, synthetic_apk):
        synthetic_apk.unlink()
        resp = client.get(f"/api/sample/{dissected_sample}/dissection/classes")
        assert resp.status_code == 404
        assert resp.json()["detail"] == "APK file not found for sample"
