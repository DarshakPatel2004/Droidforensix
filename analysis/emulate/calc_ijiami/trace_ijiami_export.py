import sys, pathlib, struct
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3] / "scripts"))
from unicorn import *
from unicorn.arm64_const import *
import emulate

so = pathlib.Path("analysis/emulate/calc_ijiami/libexecmain.so")

emu = emulate.Emulator(so)
emu.load_elf()
emu.map_regions()
emu.wire_got_shims()
emu.wire_jni_table()
emu.wire_svc_hook()
n = emu.apply_relative_relocs()
print("relative relocs applied:", n)

entry, name = emu.find_entry("ijiami")
print("entry:", name, hex(entry))

vm = emu.build_vm_table()
emu.uc.hook_add(UC_HOOK_CODE, emu.vm_hook, begin=emulate.VM_STUB & ~1, end=emulate.VM_STUB + 16)
emu.uc.hook_add(UC_HOOK_CODE, emu.dispatch_hook)
emu.capture_register_natives()

print("--- ctors ---")
print(emu.run_ctors(timeout_s=60))
print("jni_log after ctors:", list(map(str, emu.jni_log))[:20])

print("--- ijiami export ---")
emu.jni_log.clear()
sp = emulate.STACK_ADDR + 1024*1024 - 0x200
emu.uc.reg_write(UC_ARM64_REG_SP, sp)
emu.uc.reg_write(UC_ARM64_REG_X0, vm)          # JavaVM*
emu.uc.reg_write(UC_ARM64_REG_X1, 0)
emu.uc.reg_write(UC_ARM64_REG_LR, emulate.RET_STUB)
emu.uc.reg_write(UC_ARM64_REG_PC, entry)
try:
    emu.uc.emu_start(entry, emulate.RET_STUB, timeout=120*1000*1000, count=100000000)
    print("status: clean")
except Exception as exc:
    print("fault:", str(exc)[:200])
    try:
        pc = emu.uc.reg_read(UC_ARM64_REG_PC)
        print("fault PC:", hex(pc & ~1))
    except Exception as e2:
        print("(pc unreadable)", str(e2)[:80])
print("jni_calls:", len(emu.jni_log))
for e in emu.jni_log:
    if e[0] == "RegisterNatives":
        print("  REGNATIVE:", e)
print("objects:", len(emu.objects))
for k, (kind, val) in list(emu.objects.items())[:6]:
    print("  obj", hex(k), kind, len(val) if isinstance(val, bytearray) else val)
print("heap_ptr:", hex(emu.heap_ptr))
blobs = emu.sweep_blobs()
for b in blobs:
    print("blob:", b["kind"], b["section"], hex(b["va"]), b["size"], b["sha256"][:16])