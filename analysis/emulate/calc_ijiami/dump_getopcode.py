import sys, pathlib
root = pathlib.Path(__file__).resolve().parents[3]
import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

fn = root / "analysis/emulate/calc_ijiami/libexecmain.so"
raw = fn.read_bytes()
so = lief.ELF.parse(fn)
for s in so.dynamic_symbols:
    if s.name in ("ijiami", "getOpCode"):
        off = s.value
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        lines = []
        for ins in md.disasm(raw[off:off + 0x80], off):
            lines.append("%x: %s %s" % (ins.address, ins.mnemonic, ins.op_str))
        print("==== %s @0x%x (%d bytes) ====" % (s.name, off, s.size))
        print("\n".join(lines[:30]))
        print()
# also check whole-text entropy: is .text plaintext anywhere?
for seg in so.segments:
    if seg.type == lief.ELF.Segment.TYPE.LOAD:
        pass
txt = [s for s in so.sections if s.name == ".text"][0]
tdata = raw[txt.offset:txt.offset + txt.size]
import collections
from collections import Counter
c = Counter(tdata)
print(".text size", len(tdata), "top bytes:", c.most_common(6))