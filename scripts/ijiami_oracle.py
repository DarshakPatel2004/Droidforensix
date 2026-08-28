#!/usr/bin/env python3
"""Ijiami oracle: run JNI_OnLoad(vm, reserved) inside the Unicorn fake world.

Like rto_oracle.py but seeds a fake JavaVM table (GetEnv -> fake JNIEnv) so
packers that init from JNI_OnLoad (no Java_* exports) can execute.
Usage: python scripts/ijiami_oracle.py <lib.so> [symbol]
"""
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import emulate  # noqa: E402
from unicorn import UC_HOOK_CODE  # noqa: E402
from unicorn.arm64_const import (  # noqa: E402
    UC_ARM64_REG_LR, UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_X0,
    UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3)

VM_TABLE = emulate.SHIM_PAGE + 0x20000   # JavaVM*: points to FUNC_TABLE
FUNC_TABLE = VM_TABLE + 0x40             # JNIInvokeInterface (8 fn ptrs)
VM_STUB = VM_TABLE + 0x100               # shared `ret` stub for all VM functions
N_SLOTS = 8                              # 3 reserved + Destroy/Attach/Detach/GetEnv/AttachAsDaemon
GETENV_SLOT = 6                          # Android jni.h: 3 reserved first, GetEnv = slot 6


def build_vm_table(uc):
    # standard JNI: (*vm)->GetEnv == *(*vm + 0x30) — so JavaVM* points to a
    # cell holding the function-table pointer; table slots point to the stub
    uc.mem_write(VM_TABLE, struct.pack("<Q", FUNC_TABLE))
    for i in range(N_SLOTS):
        uc.mem_write(FUNC_TABLE + i * 8, struct.pack("<Q", VM_STUB))
    uc.mem_write(VM_STUB, emulate.RET_ARM)
    return VM_TABLE


def apply_relative_relocs(emu):
    """emulate.py wires only JUMP_SLOT/GLOB_DAT; RELATIVE/ABS64 pointers
    in .data.rel.ro are needed before any non-trivial lib runs."""
    uc, base, n = emu.uc, emu.base, 0
    for rel in emu.binary.relocations:
        t = str(rel.type)
        if "RELATIVE" in t:
            uc.mem_write(base + rel.address, struct.pack("<Q", base + rel.addend))
            n += 1
        elif "ABS64" in t:
            sym = rel.symbol
            if sym and sym.name and not sym.value:
                val = emulate.SHIM_PAGE + 0x8000 + (hash(sym.name) % 0x400) * 16
            else:
                val = base + ((sym.value if sym else 0) or 0) + rel.addend
            uc.mem_write(base + rel.address, struct.pack("<Q", val))
            n += 1
    return n


def vm_hook(uc, address, size, ud):
    if address == VM_STUB:
        # GetEnv(vm, &env, ver) / AttachCurrentThread(vm, &env, args):
        # hand out the fake JNIEnv and return JNI_OK; other slots are no-ops
        env_ptr = uc.reg_read(UC_ARM64_REG_X1)
        if env_ptr:
            try:
                uc.mem_write(env_ptr, struct.pack("<Q", emulate.FAKE_JENV))
            except Exception:
                pass
        uc.reg_write(UC_ARM64_REG_X0, 0)  # JNI_OK


def run_ctors(emu):
    """dlopen semantics: DT_INIT, then INIT_ARRAY (self-decryptors live here)."""
    uc, base = emu.uc, emu.base
    init_va = init_arr_va = init_arr_sz = None
    for e in emu.binary.dynamic_entries:
        if str(e.tag) == "TAG.INIT":
            init_va = e.value
        elif str(e.tag) == "TAG.INIT_ARRAY":
            init_arr_va = e.value
        elif str(e.tag) == "TAG.INIT_ARRAYSZ":
            init_arr_sz = e.value
    if init_va:
        emu.run(base + init_va, timeout_s=120)
        print(f"[ctor] DT_INIT {hex(init_va)} -> {emu.jni_log and 'jni'}")
    if init_arr_va and init_arr_sz:
        n = init_arr_sz // 8
        for i in range(n):
            (fn,) = struct.unpack("<Q", uc.mem_read(base + init_arr_va + i * 8, 8))
            if fn:
                emu.run(base + fn, timeout_s=120)
        print(f"[ctor] INIT_ARRAY {n} ctors executed")


def capture_register_natives(emu):
    """Record (name, sig, fn_offset) triples the packer binds at runtime."""
    uc = emu.uc
    orig = emu.do_jni

    def patched(name):
        if name == "RegisterNatives":
            methods = uc.reg_read(UC_ARM64_REG_X2)
            count = uc.reg_read(UC_ARM64_REG_X3)
            for i in range(min(count, 64)):
                try:
                    name_p, sig_p, fn_p = struct.unpack(
                        "<QQQ", bytes(uc.mem_read(methods + i * 24, 24)))
                    nm = emu.cstr(name_p) if name_p else "?"
                    sg = emu.cstr(sig_p) if sig_p else "?"
                    off = fn_p - emu.base if fn_p >= emu.base else fn_p
                    print(f"[REGNATIVE] {nm} {sg} -> base+{hex(off)}")
                except Exception as exc:
                    print(f"[REGNATIVE] unreadable entry {i}: {exc}")
                    break
        return orig(name)

    emu.do_jni = patched


def main():
    so = pathlib.Path(sys.argv[1])
    sym = sys.argv[2] if len(sys.argv) > 2 else "JNI_OnLoad"

    emu = emulate.Emulator(so)
    emu.load_elf()
    emu.map_regions()
    emu.wire_got_shims()
    emu.wire_jni_table()
    nrel = apply_relative_relocs(emu)
    uc = emu.uc

    entry, name = emu.find_entry(sym)
    if name != sym:
        raise SystemExit(f"symbol {sym!r} not exported (got {name!r})")

    vm = build_vm_table(uc)
    uc.hook_add(UC_HOOK_CODE, vm_hook, begin=VM_STUB, end=VM_STUB + 4)
    uc.hook_add(UC_HOOK_CODE, emu.dispatch_hook)
    capture_register_natives(emu)

    run_ctors(emu)
    emu.jni_log.clear()

    uc.reg_write(UC_ARM64_REG_SP, emulate.STACK_ADDR + 1024 * 1024 - 0x200)
    uc.reg_write(UC_ARM64_REG_X0, vm)          # JavaVM*
    uc.reg_write(UC_ARM64_REG_X1, 0)           # reserved
    uc.reg_write(UC_ARM64_REG_LR, emulate.RET_STUB)
    uc.reg_write(UC_ARM64_REG_PC, entry)

    status = "clean"
    try:
        uc.emu_start(entry, emulate.RET_STUB,
                     timeout=180 * 1_000_000, count=50_000_000)
    except Exception as exc:
        status = str(exc)[:80]

    print(f"entry={name} va={hex(entry)} status={status} relocs={nrel}")
    print(f"heap_used={emu.heap_ptr} jni_calls={len(emu.jni_log)}")
    print("\n=== JNI trace ===")
    for e in emu.jni_log[:50]:
        print("  ", e)

    blobs = emu.sweep_blobs()
    print(f"\nblobs: {len(blobs)}")
    for b in blobs:
        meta = {k: v for k, v in b.items() if k != "data"}
        print("  ", meta)
        if b.get("data"):
            out = pathlib.Path("/home/kali/DroidForensix/analysis/recovered/Ijiami")
            out.mkdir(parents=True, exist_ok=True)
            kind = "dex" if b.get("kind") in ("b64_dex", "raw_dex") else "bin"
            p = out / f"{so.stem}_{b['sha256'][:12]}.{kind}"
            p.write_bytes(b["data"])
            print("   saved ->", p)


if __name__ == "__main__":
    main()
