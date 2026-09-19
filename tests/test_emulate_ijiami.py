"""JIAMI entry-discovery contract for scripts/emulate.py.

The full boot path (Unicorn emulation) is exercised manually against real
packed libs and takes minutes. These tests lock down the pure logic added in
the JIAMI sprint: find_entry() must fall back to JNI_OnLoad when a lib exports
no Java_* symbol (Ijiami/Bangcle expose only JNI_OnLoad), and keep preferring
a real Java_* export when one exists (RTO path must not regress).
"""

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

EMULATE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "emulate.py"


@pytest.fixture(scope="module")
def emulate():
    spec = importlib.util.spec_from_file_location("emulate", EMULATE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _sym(name, addr):
    return SimpleNamespace(name=name, address=addr, value=addr)


def _make_emulator(emulate, exported, dynamic, base=0x70000000):
    """Emulator instance without lief/Unicorn: find_entry() only reads
    self.binary and self.base."""
    em = object.__new__(emulate.Emulator)
    em.binary = SimpleNamespace(
        exported_functions=exported,
        dynamic_symbols=dynamic,
    )
    em.base = base
    return em


def test_exported_jni_onload_is_found(emulate):
    em = _make_emulator(
        emulate, exported=[_sym("JNI_OnLoad", 0x1234)], dynamic=[])
    entry, name = em.find_entry()
    assert name == "JNI_OnLoad"
    assert entry == em.base + 0x1234


def test_dynsym_jni_onload_is_found(emulate):
    """Some packers export from .dynsym only, not exported_functions."""
    em = _make_emulator(
        emulate, exported=[], dynamic=[_sym("JNI_OnLoad", 0x5678)])
    entry, name = em.find_entry()
    assert name == "JNI_OnLoad"
    assert entry == em.base + 0x5678


def test_java_export_still_preferred(emulate):
    """RTO path regression guard: a real Java_* export wins over JNI_OnLoad."""
    em = _make_emulator(
        emulate,
        exported=[_sym("Java_com_x_A", 0x100), _sym("JNI_OnLoad", 0x200)],
        dynamic=[],
    )
    entry, name = em.find_entry()
    assert name == "Java_com_x_A"
    assert entry == em.base + 0x100


def test_no_entry_raises(emulate):
    em = _make_emulator(emulate, exported=[], dynamic=[])
    with pytest.raises(RuntimeError, match="no Java_\\* export"):
        em.find_entry()


def test_multiple_java_exports_pick_shortest(emulate):
    em = _make_emulator(
        emulate,
        exported=[_sym("Java_abc", 0x10), _sym("Java_a", 0x20)],
        dynamic=[],
    )
    entry, name = em.find_entry()
    assert name == "Java_a"
    assert entry == em.base + 0x20


def test_explicit_sym_request_wins(emulate):
    em = _make_emulator(
        emulate,
        exported=[_sym("JNI_OnLoad", 0x100), _sym("Java_a", 0x200)],
        dynamic=[],
    )
    entry, name = em.find_entry("JNI_OnLoad")
    assert (name, entry) == ("JNI_OnLoad", em.base + 0x100)