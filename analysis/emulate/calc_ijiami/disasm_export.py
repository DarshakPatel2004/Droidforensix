import pathlib
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

root = pathlib.Path(__file__).resolve().parents[3]
fn = root / "analysis/emulate/calc_ijiami/libexecmain.so"
raw = fn.read_bytes()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
for name, off in (("ijiami", 0x86994), ("getOpCode", 0x277dc)):
    code = raw[off:off + 0x40]
    print("=== %s @0x%x len=%d first16=%s" % (name, off, len(code), code[:16].hex()))
    n = 0
    for ins in md.disasm(code, off):
        n += 1
        if n <= 16:
            print("  %x: %s %s" % (ins.address, ins.mnemonic, ins.op_str))
    print("  (%d instructions)" % n)