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


# ---------------------------------------------------------------------------
# hardened-VM pre-check
# ---------------------------------------------------------------------------
# Build a fake lief binary shape: header.machine_type + segments[].content
import struct as _struct

_RET_ARM64 = _struct.pack("<I", 0xD65F03C0)  # ret


def _fake_binary(machine, sym_va, entry_bytes, fsize=0x1000):
    from types import SimpleNamespace as NS
    blob = bytearray(fsize)
    blob[sym_va:sym_va + len(entry_bytes)] = entry_bytes
    seg = NS(virtual_address=0, virtual_size=fsize, type="TYPE.LOAD",
             content=bytes(blob))
    return NS(
        header=NS(machine_type=machine),
        exported_functions=[NS(name="JNI_OnLoad", address=sym_va)],
        dynamic_symbols=[],
        segments=[seg],
    )


def test_hardened_vm_detects_ciphertext_entry(emulate):
    """Random high-entropy bytes at JNI_OnLoad -> hardened (like Calculator's
    libijm-emulator.so, decode density 0.0-0.03)."""
    rand = bytes(range(256)) * 8
    b = _fake_binary("ARCH.AARCH64", 0x100, rand)
    hardened, ev = emulate.is_hardened_vm(b, window=0x200)
    assert hardened is True
    assert ev["decode_density"] < 0.3


def test_hardened_vm_accepts_real_code(emulate):
    """A stream of `ret` decodes at density 1 -> not hardened."""
    code = _RET_ARM64 * 64
    b = _fake_binary("ARCH.AARCH64", 0x100, code)
    hardened, ev = emulate.is_hardened_vm(b, window=0x100)
    assert hardened is False
    assert ev["decode_density"] == 1.0


def test_hardened_vm_x86_64_entry(emulate):
    """x86_64 ret (c3) also passes."""
    code = b"\xc3" * 64  # ret
    b = _fake_binary("ARCH.X86_64", 0x100, code)
    hardened, ev = emulate.is_hardened_vm(b, window=0x100)
    assert hardened is False


def test_hardened_vm_missing_symbol_not_hardened(emulate):
    b = _fake_binary("ARCH.AARCH64", 0x100, b"\x00" * 64)
    b.exported_functions = []
    hardened, ev = emulate.is_hardened_vm(b, sym="JNI_OnLoad")
    assert hardened is False
    assert ev == {}