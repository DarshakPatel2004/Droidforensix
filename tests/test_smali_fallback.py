"""Tests for smali string extraction fallback when Androguard DEX extraction fails."""

from pathlib import Path
from analysis.step2_string_enumeration import extract_smali_strings


def test_extract_smali_strings(tmp_path):
    smali_dir = tmp_path / "smali" / "com" / "example"
    smali_dir.mkdir(parents=True)
    smali_file = smali_dir / "Main.smali"
    smali_file.write_text(
        '.class public Lcom/example/Main;\n'
        '.super Ljava/lang/Object;\n'
        '\n'
        '.method public constructor <init>()V\n'
        '    .locals 1\n'
        '    const-string v0, "https://evil.example.com/c2"\n'
        '    const-string/jumbo v1, "large_payload_string_here"\n'
        '    return-void\n'
        '.end method\n'
    )

    results = extract_smali_strings(str(tmp_path))
    values = [r["value"] for r in results]
    assert "https://evil.example.com/c2" in values
    assert "large_payload_string_here" in values
    assert all(r["category"] == "string_literal" for r in results)
    assert all(r["entropy"] > 0 for r in results)


def test_extract_smali_strings_no_smali_dir(tmp_path):
    results = extract_smali_strings(str(tmp_path))
    assert results == []


def test_extract_smali_strings_skips_short_strings(tmp_path):
    smali_dir = tmp_path / "smali"
    smali_dir.mkdir()
    smali_file = smali_dir / "Main.smali"
    smali_file.write_text(
        'const-string v0, "ab"\n'
        'const-string v1, "long enough string"\n'
    )
    results = extract_smali_strings(str(tmp_path))
    values = [r["value"] for r in results]
    assert "ab" not in values
    assert "long enough string" in values
