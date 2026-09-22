import sys, pathlib
root = pathlib.Path(__file__).resolve().parents[3]
import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

raw = (root / "analysis/emulate/calc_ijiami/libexec.so").read_bytes()
so = lief.ELF.parse(root / "analysis/emulate/calc_ijiami/libexec.so")
sym = [s for s in so.dynamic_symbols if s.name == "JNI_OnLoad"][0]
off = sym.value
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
code = raw[off:off + 0x300]
lines = []
for ins in md.disasm(code, off):
    lines.append("%x: %s %s" % (ins.address, ins.mnemonic, ins.op_str))
out = root / "analysis/emulate/calc_ijiami/jonload.txt"
out.write_text("\n".join(lines), encoding="utf-8")
print("wrote", len(lines), "instructions to", out)