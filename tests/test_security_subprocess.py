"""
Security regression tests for P2-C1 / P2-C2 (OS command injection).

analysis/step1_apk_extraction.py passed an APK-author-controlled native-library
path to subprocess.run with shell=(os.name == "nt"). On Windows that is not a
harmless convenience: CPython flattens the list with list2cmdline and hands
`cmd.exe /C "<joined>"`, so a space-free name containing & | ^ ! ( ) is parsed
as a command separator. The names come from lib_dir.rglob("*.so"), i.e. the APK
author's own ZIP entry names.

These tests assert the security property - no shell is involved in the
subprocess call - rather than the specific argument list, so they stay valid if
the argv is restructured. Recording every call's kwargs also catches a future
site reintroducing shell=True.
"""
import os
from pathlib import Path

import pytest

CALLS = []


@pytest.fixture
def record_subprocess(monkeypatch):
    """Capture subprocess.run invocations instead of executing them."""
    CALLS.clear()

    class _Result:
        returncode = 1          # non-zero so the r2/rabin2 branches fall through
        stdout = ""
        stderr = ""

    def fake_run(cmd, **kwargs):
        CALLS.append({"cmd": cmd, "kwargs": kwargs})
        return _Result()

    import subprocess as real_subprocess

    monkeypatch.setattr(real_subprocess, "run", fake_run)
    return CALLS


def _make_lib_dir(tmp_path: Path, name: str) -> Path:
    lib = tmp_path / "lib" / "armeabi-v7a"
    lib.mkdir(parents=True)
    (lib / name).write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32)
    return tmp_path


def _r2_and_rabin2(monkeypatch, which):
    """Pretend radare2 IS installed, so the vulnerable branch is exercised."""
    import analysis.step1_apk_extraction as step1

    monkeypatch.setattr(step1.shutil, "which", lambda n: {
        "r2": "C:/tools/radare2/r2.exe",
        "rabin2": "C:/tools/radare2/rabin2.exe",
        "strings": "C:/tools/strings.exe",
    }.get(n))


@pytest.mark.parametrize("evil_name", [
    "x&calc.exe.so",       # & is the primary cmd.exe separator
    "x^whoami.so",        # ^ escapes the next character
    "x%USERNAME%.so",     # %VAR% expansion, quote-insensitive
    "x)whoami(x.so",      # subshell delimiters
])
def test_r2_invocation_never_uses_a_shell(record_subprocess, monkeypatch, tmp_path, evil_name):
    """A .so whose name carries a cmd metacharacter must not reach a shell."""
    from analysis.step1_apk_extraction import extract_native_strings

    _r2_and_rabin2(monkeypatch, None)
    apk_dir = _make_lib_dir(tmp_path, evil_name)

    extract_native_strings(str(apk_dir))

    assert record_subprocess, "expected the r2 branch to be attempted"
    for call in record_subprocess:
        assert call["kwargs"].get("shell") in (None, False), (
            f"subprocess.run used a shell for attacker-controlled argv: {call['cmd']}"
        )


def test_rabin2_invocation_never_uses_a_shell(record_subprocess, monkeypatch, tmp_path):
    """Same property for the rabin2 fallback branch."""
    import analysis.step1_apk_extraction as step1

    # r2 absent, rabin2 present -> the rabin2 branch is the one taken.
    monkeypatch.setattr(step1.shutil, "which", lambda n: {
        "r2": None,
        "rabin2": "C:/tools/radare2/rabin2.exe",
        "strings": "C:/tools/strings.exe",
    }.get(n))
    apk_dir = _make_lib_dir(tmp_path, "y&calc.exe.so")

    step1.extract_native_strings(str(apk_dir))

    assert record_subprocess, "expected the rabin2 branch to be attempted"
    for call in record_subprocess:
        assert call["kwargs"].get("shell") in (None, False), (
            f"subprocess.run used a shell for attacker-controlled argv: {call['cmd']}"
        )


def test_apktool_invocation_never_uses_a_shell(record_subprocess, monkeypatch, tmp_path):
    """P2-C2: run_apktool takes a client-supplied path (POST /analyze)."""
    from analysis.step1_apk_extraction import run_apktool

    monkeypatch.setattr(
        "backend.config.settings.APKTOOL_PATH", str(tmp_path / "apktool.bat")
    )
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"PK\x03\x04")
    (tmp_path / "apktool.bat").write_text("@echo off\n", encoding="utf-8")

    run_apktool(str(apk), str(tmp_path / "out"))

    assert record_subprocess, "expected run_apktool to spawn a process"
    for call in record_subprocess:
        assert call["kwargs"].get("shell") in (None, False), (
            f"run_apktool used a shell for a client-supplied path: {call['cmd']}"
        )


def test_no_module_in_the_pipeline_passes_shell_true():
    """Belt-and-braces: no analysis/* module may reintroduce shell=True.

    A cheap whole-module guard, so a future edit adding a new shell=True site is
    caught here rather than in a review.
    """
    offenders = []
    analysis_dir = Path(__file__).resolve().parent.parent / "analysis"
    for py in sorted(analysis_dir.glob("*.py")):
        for lineno, line in enumerate(py.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            code = line.split("#", 1)[0]  # a comment mentioning shell=True is not a call site
            if "shell=" in code and "shell=True" in code.replace(" ", ""):
                offenders.append(f"{py.name}:{lineno}")
    assert not offenders, f"shell=True reintroduced at: {offenders}"


@pytest.mark.skipif(os.name != "nt", reason="the injection form is Windows-specific")
def test_metacharacter_name_is_passed_as_one_literal_argument(record_subprocess, monkeypatch, tmp_path):
    """With no shell, the whole evil name stays a single argv element."""
    from analysis.step1_apk_extraction import extract_native_strings

    _r2_and_rabin2(monkeypatch, None)
    apk_dir = _make_lib_dir(tmp_path, "z&calc.exe.so")

    extract_native_strings(str(apk_dir))

    r2_calls = [c for c in record_subprocess if "r2.exe" in str(c["cmd"][0])]
    assert r2_calls, "expected an r2 invocation"
    argv = r2_calls[0]["cmd"]
    assert any(str(a).endswith("z&calc.exe.so") for a in argv), (
        f"evil name was split or mangled across argv: {argv}"
    )