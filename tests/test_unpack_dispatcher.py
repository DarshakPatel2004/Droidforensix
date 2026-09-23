"""Dispatcher detection: sniff_family brand routing + FAM_MARKS coverage.

Covers the 23-Sep-2026 packer gap-closers (Wangsu/Ali/BaiduEnhancer/
DexProtector sniffing, SecShell/Baidu split) with precedence regressions so
marker order cannot silently break existing routes. No corpus access: all
fixtures are synthetic entry-name lists.
"""
import importlib.util
from pathlib import Path

UNPACK = Path(__file__).resolve().parents[1] / "scripts" / "unpack.py"


def _load():
    spec = importlib.util.spec_from_file_location("unpack_under_test", UNPACK)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


unpack = _load()


def test_sniff_new_brands_from_entry_names():
    sniff = unpack.sniff_family
    assert sniff(["lib/arm64-v8a/libkwsgmain.so", "lib/arm64-v8a/libkdp.so"]) == "Wangsu"
    assert sniff(["lib/arm64-v8a/libmobisec.so"]) == "Ali"
    assert sniff(["lib/arm64-v8a/libbaiduprotect.so"]) == "BaiduEnhancer"
    # substring covers libbaiduprotect_x86.so without a second check
    assert sniff(["lib/x86/libbaiduprotect_x86.so"]) == "BaiduEnhancer"
    assert sniff(["assets/com.baidu.protect"]) == "BaiduEnhancer"
    # covers com.licel/org.licel slash paths and libdexprotector.so alike
    assert sniff(["com/licel/core"]) == "DexProtector"
    assert sniff(["lib/arm64-v8a/libdexprotector.so"]) == "DexProtector"


def test_sniff_baidu_split_and_precedence_regressions():
    sniff = unpack.sniff_family
    assert sniff(["lib/arm64-v8a/libDexHelper.so"]) == "SecShell/Baidu"
    # both markers present -> BaiduEnhancer wins (check sits before DexHelper)
    assert sniff(["libDexHelper.so", "libbaiduprotect.so"]) == "BaiduEnhancer"
    # pre-existing routes unchanged by the new checks
    assert sniff(["lib/arm64-v8a/libshella-2.10.7.1.so"]) == "TencentLegu"
    assert sniff(["lib/arm64-v8a/libjiagu.so"]) == "360Jiagu"
    assert sniff(["lib/arm64-v8a/libexecmain.so"]) == "Ijiami(variant)"
    assert sniff(["lib/arm64-v8a/libnesec.so"]) == "Wangxin"
    assert sniff(["assets/innocent.bin"]) is None


def test_fam_marks_covers_new_families():
    for family in ("Wangsu", "Ali", "BaiduEnhancer", "DexProtector"):
        assert unpack.FAM_MARKS.get(family), f"missing FAM_MARKS for {family}"
    # baiduprotect moved out of SecShell/Baidu with the family split
    assert "baiduprotect" not in unpack.FAM_MARKS["SecShell/Baidu"]


def test_java_layer_handoff_signature():
    """Keyed on verified stub evidence; conservative fallback otherwise."""
    import io
    import zipfile

    def zipped(dex_bytes=None):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            if dex_bytes is not None:
                zf.writestr("classes.dex", dex_bytes)
            zf.writestr("lib/arm64-v8a/libdummy.so", b"\x7fELF")
        buf.seek(0)
        return zipfile.ZipFile(buf)

    # both corpus-verified shapes: TxAppEntry stub (2.10.7.1 / 4.1.0.23) and
    # the wrapper-refs variant for shells without TxAppEntry
    assert unpack.java_layer_handoff(
        zipped(b"dex\n035\x00" + b"pad" * 50 + b"TxAppEntry")) is True
    assert unpack.java_layer_handoff(
        zipped(b"pool DexFile and dexElements wrapper")) is True
    # conservative: plain app dex and missing stub both fall back to the
    # previous E-NATIVE-NO-RECOVERY behavior
    assert unpack.java_layer_handoff(zipped(b"ordinary app classes")) is False
    assert unpack.java_layer_handoff(zipped()) is False
