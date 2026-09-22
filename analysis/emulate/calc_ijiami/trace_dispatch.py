import sys, pathlib
sys.stdout.reconfigure(line_buffering=True)
root = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(root / "scripts"))
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *
import emulate
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

so = root / "analysis/emulate/calc_ijiami/libexec.so"
emu = emulate.Emulator(so)
emu.load_elf()
emu.map_regions()
emu.wire_got_shims()
emu.wire_jni_table()
emu.wire_svc_hook()
emu.apply_relative_relocs()

# intercept JNI calls to count them
from collections import Counter
cnt = Counter()
orig_jni = emu.do_jni

def spy(name):
    cnt["jni:" + name] += 1
    return orig_jni(name)
emu.do_jni = spy

vm = emu.build_vm_table()
emu.uc.hook_add(UC_HOOK_CODE, emu.vm_hook, begin=emulate.VM_STUB & ~1, end=emulate.VM_STUB + 16)
emu.uc.hook_add(UC_HOOK_CODE, emu.dispatch_hook)
print("ctors:", emu.run_ctors(timeout_s=60))

# after ctors, is the code at JNI_OnLoad decrypted?
off = 0x64e6c
mem = bytes(emu.uc.mem_read(emu.base + off, 32))
print("post-ctor bytes at JNI_OnLoad:", mem.hex())
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
for ins in md.disasm(mem, emu.base + off):
    print("  %x: %s %s" % (ins.address, ins.mnemonic, ins.op_str))

emu.jni_log.clear()
sp = emulate.STACK_ADDR + 1024*1024 - 0x200
entry = emu.base + off
emu.uc.reg_write(UC_ARM64_REG_SP, sp)
emu.uc.reg_write(UC_ARM64_REG_X0, vm)
emu.uc.reg_write(UC_ARM64_REG_X1, 0)
emu.uc.reg_write(UC_ARM64_REG_LR, emulate.RET_STUB)
emu.uc.reg_write(UC_ARM64_REG_PC, entry)
try:
    emu.uc.emu_start(entry, emulate.RET_STUB, timeout=120*1000*1000, count=100000000)
    print("JNI_OnLoad status: clean")
except Exception as exc:
    print("JNI_OnLoad fault:", str(exc)[:120])
    pc = emu.uc.reg_read(UC_ARM64_REG_PC)
    print(" fault pc:", hex(pc & ~1))
print("jni dispatch counts:", dict(cnt))
print("jni_log len:", len(emu.jni_log))
print("objects:", len(emu.objects), "heap_ptr:", hex(emu.heap_ptr))