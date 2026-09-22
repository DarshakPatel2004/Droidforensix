import sys, pathlib, struct
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3] / "scripts"))
from unicorn import *
from unicorn.arm64_const import *
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
import emulate

so = pathlib.Path("analysis/emulate/calc_ijiami/libexec.so")

emu = emulate.Emulator(so)
emu.load_elf()
emu.map_regions()
emu.wire_got_shims()
emu.wire_jni_table()
emu.wire_svc_hook()
n = emu.apply_relative_relocs()
print("relative relocs applied:", n)

entry, name = emu.find_entry("JNI_OnLoad")
print("entry:", name, hex(entry))

vm = emu.build_vm_table()
emu.uc.hook_add(UC_HOOK_CODE, emu.vm_hook, begin=emulate.VM_STUB & ~1, end=emulate.VM_STUB + 16)
emu.uc.hook_add(UC_HOOK_CODE, emu.dispatch_hook)
emu.capture_register_natives()

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
last = {}
def trap(uc, address, size, ud):
    pc = address & ~1
    if pc in last:
        last[pc] += 1
        if last[pc] > 5:
            last[pc] = -100000
    else:
        last[pc] = 1
    return
emu.uc.hook_add(UC_HOOK_CODE, trap)

def sinsn(uc, address, size, ud):
    pc = address & ~1
    if emu.base <= pc < emu.base + 0x8000 and emu.base + 0x60000 <= pc:
        pass
    # print first 3 instructions at presumably-start-of-ctors + JNI callbacks
    return
emu.uc.hook_add(UC_HOOK_CODE, sinsn)

print("--- run ctors ---")
ctors = emu.run_ctors(timeout_s=60)
print("ctors runs:", ctors)
print("jni_log after ctors:", list(map(str, emu.jni_log)))

print("--- JNI_OnLoad ---")
emu.jni_log.clear()
uc = emu.uc
sp = emulate.STACK_ADDR + 1024*1024 - 0x200
uc.reg_write(UC_ARM64_REG_SP, sp)
uc.reg_write(UC_ARM64_REG_X0, vm)
uc.reg_write(UC_ARM64_REG_X1, 0)
uc.reg_write(UC_ARM64_REG_LR, emulate.RET_STUB)
uc.reg_write(UC_ARM64_REG_PC, entry)
try:
    uc.emu_start(entry, emulate.RET_STUB, timeout=120*1000*1000, count=100000000)
    print("JNI_OnLoad complete, status clean")
except Exception as exc:
    print("fault:", str(exc)[:200])
    try:
        pc = uc.reg_read(UC_ARM64_REG_PC)
        print("fault PC:", hex(pc & ~1))
        code = bytes(uc.mem_read(pc & ~1, 8))
        print("encoding:", code.hex())
        for i in md.disasm(code, pc & ~1):
            print("  %x: %s %s" % (i.address, i.mnemonic, i.op_str))
    except Exception as e2:
        print("(pc unreadable)", str(e2)[:80])
print("jni_calls:", len(emu.jni_log), "log:", list(map(str, emu.jni_log))[:40])
print("objects:", len(emu.objects))
for k, (kind, val) in list(emu.objects.items())[:10]:
    print("  obj", hex(k), kind, len(val) if isinstance(val, bytearray) else val)
print("heap_ptr:", hex(emu.heap_ptr))
blobs = emu.sweep_blobs()
for b in blobs:
    print("blob:", b["kind"], b["section"], hex(b["va"]), b["size"], b["sha256"][:16])