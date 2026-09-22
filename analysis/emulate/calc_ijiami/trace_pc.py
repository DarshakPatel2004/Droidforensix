import sys, pathlib
sys.stdout.reconfigure(line_buffering=True)
root = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(root / "scripts"))
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *
import emulate

so = root / "analysis/emulate/calc_ijiami/libexec.so"
emu = emulate.Emulator(so)
emu.load_elf()
emu.map_regions()
emu.wire_got_shims()
emu.wire_jni_table()
emu.wire_svc_hook()
emu.apply_relative_relocs()

vm = emu.build_vm_table()
emu.uc.hook_add(UC_HOOK_CODE, emu.vm_hook, begin=emulate.VM_STUB & ~1, end=emulate.VM_STUB + 16)
emu.uc.hook_add(UC_HOOK_CODE, emu.dispatch_hook)
print("base:", hex(emu.base))
try:
    print("ctors:", emu.run_ctors(timeout_s=60))
except Exception as exc:
    print("ctor fault:", str(exc)[:120])

seen = []
def pc_trace(uc, addr, size, ud):
    seen.append(addr & ~1)
    if len(seen) >= 30:
        raise Exception("enough")
emu.uc.hook_add(UC_HOOK_CODE, pc_trace)

off = 0x64e6c
entry = emu.base + off
emu.jni_log.clear()
sp = emulate.STACK_ADDR + 1024*1024 - 0x200
emu.uc.reg_write(UC_ARM64_REG_SP, sp)
emu.uc.reg_write(UC_ARM64_REG_X0, vm)
emu.uc.reg_write(UC_ARM64_REG_X1, 0)
emu.uc.reg_write(UC_ARM64_REG_LR, emulate.RET_STUB)
emu.uc.reg_write(UC_ARM64_REG_PC, entry)
try:
    emu.uc.emu_start(entry, emulate.RET_STUB, timeout=120*1000*1000, count=100000000)
    print("status clean, executed=%d" % len(seen))
except Exception as exc:
    print("status:", str(exc)[:120], "executed=%d" % len(seen))
print("entry:", hex(entry))
for a in seen[:30]:
    print("  pc %x" % a)