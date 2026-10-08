"""Standalone unpacking tool: CLI contract + output wiring.

Full-oracle recovery is exercised manually (it runs the Unicorn emulator and
can take minutes); these tests cover the tool's argument contract and the
post-recovery stages that must never silently misbehave.
"""

import importlib.util
import json
import zipfile
from pathlib import Path

import pytest

TOOL_PATH = Path(__file__).resolve().parents[1] / "rto_analysis" / "unpacking_tool.py"


@pytest.fixture(scope="module")
def tool():
    spec = importlib.util.spec_from_file_location("unpacking_tool", TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_help_exits_zero(tool, capsys):
    with pytest.raises(SystemExit) as e:
        tool.main(["--help"])
    assert e.value.code == 0


def test_missing_input_is_usage_error(tool):
    with pytest.raises(SystemExit) as e:
        tool.main([])
    assert e.value.code == 2


def test_nonexistent_input_is_usage_error(tool, tmp_path):
    with pytest.raises(SystemExit) as e:
        tool.main(["--input", str(tmp_path / "missing.apk"),
                   "--output", str(tmp_path / "out")])
    assert e.value.code == 2


def test_non_zip_input_is_usage_error(tool, tmp_path):
    junk = tmp_path / "fake.apk"
    junk.write_bytes(b"not a zip at all")
    with pytest.raises(SystemExit) as e:
        tool.main(["--input", str(junk), "--output", str(tmp_path / "out")])
    assert e.value.code == 2


def test_is_myg0n_kit_gates_on_installer_dex(tool, tmp_path):
    kit = tmp_path / "kit.zip"
    with zipfile.ZipFile(kit, "w") as zh:
        zh.writestr("installer.dex", b"dex\n000")
    assert tool.is_myg0n_kit(kit) is True
    with zipfile.ZipFile(kit, "w") as zh:
        zh.writestr("classes.dex", b"dex\n000")
    assert tool.is_myg0n_kit(kit) is False


def test_collect_outputs_copies_artifacts_and_keys(tool, tmp_path):
    src_dir = tmp_path / "work"
    src_dir.mkdir(exist_ok=True)   # conftest's isolation fixture already created it
    kit = src_dir / "kit.zip"
    kit.write_bytes(b"PK\x03\x04")
    report = {
        "artifacts": [{"file": str(kit), "sha256": "abc"}],
        "kdf": {"asset": "assets/x", "seed": "myg0N2", "key": "k", "iv": "iv"},
    }
    out = tmp_path / "out"
    copies = tool.collect_outputs(report, out)
    assert copies[0]["basename"] == "kit.zip"
    assert (out / "artifacts" / "kit.zip").read_bytes() == b"PK\x03\x04"
    keys = json.loads((out / "artifacts" / "recovery_keys.json").read_text(encoding="utf-8"))
    assert keys["seed"] == "myg0N2"


def test_run_stage3_materializes_strings_at_replay_bar(tool, tmp_path):
    result = tool.run_stage3(tmp_path)
    assert result["seeds"] == 180
    assert result["matches"] == 175
    assert result["mismatches"] == 5
    assert (tmp_path / "strings.json").exists()
    assert (tmp_path / "strings.tsv").exists()


def test_bundle_artifacts_excludes_workdir(tool, tmp_path):
    out = tmp_path / "out"
    (out / "artifacts").mkdir(parents=True)
    (out / "work").mkdir()
    (out / "summary.json").write_text("{}", encoding="utf-8")
    (out / "artifacts" / "kit.zip").write_bytes(b"PK")
    (out / "work" / "big.so").write_bytes(b"x" * 100)
    zip_path = tool.bundle_artifacts(out, "ARTIFACTS")
    assert zip_path.exists()
    with zipfile.ZipFile(zip_path) as zh:
        names = zh.namelist()
    assert "out/summary.json" in names
    assert "out/artifacts/kit.zip" in names
    assert "out/work/big.so" not in names