import sys, pathlib
sys.stdout.reconfigure(line_buffering=True)
root = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(root / "scripts"))
from unicorn import UC_HOOK_MEM_WRITE
import emulate

so = root / "analysis/emulate/calc_ijiami/libexecmain.so"
emu = emulate.Emulator(so)
emu.load_elf()
emu.map_regions()
emu.wire_got_shims()
emu.wire_jni_table()
emu.wire_svc_hook()
emu.apply_relative_relocs()

writes = []
def mem_w(uc, access, addr, size, val, ud):
    if emu.base <= addr < emu.base + 0x90000:
        writes.append(addr)
        if len(writes) > 2000:
            raise Exception("too many writes")

emu.uc.hook_add(UC_HOOK_MEM_WRITE, mem_w)
try:
    print("ctors:", emu.run_ctors(timeout_s=90))
except Exception as exc:
    print("ctor note:", str(exc)[:80])

in_text = [a for a in writes if emu.base <= a < emu.base + 0x90000]
print("writes into libexecmain LOAD range:", len(in_text))
for a in in_text[:40]:
    print("  text-addr-write %x (off %x)" % (a, a - emu.base))

if in_text:
    ma = max(in_text)
    mem = bytes(emu.uc.mem_read(ma - 32, 96))
    print("mem near last write %x:" % (ma - 32), mem.hex())
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
if in_text:
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    off = in_text[0] - emu.base
    raw2 = bytes(emu.uc.mem_read(emu.base + off, 64))
    print("bytes at first text write:", raw2[:32].hex())
    for ins in md.disasm(raw2, emu.base + off):
        print("  %x: %s %s" % (ins.address, ins.mnemonic, ins.op_str))
        break