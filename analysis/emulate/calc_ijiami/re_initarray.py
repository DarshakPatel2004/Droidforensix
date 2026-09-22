"""arm32 init_array: what runs first? Look for an early decryptor."""
import lief, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

P = "analysis/emulate/calc_ijiami/fullrun/libs/armeabi-v7a_libijm-emulator.so"
B = lief.parse(P)
segs = []
with open(P, "rb") as f:
    for s in B.segments:
        if str(s.type) == "TYPE.LOAD":
            f.seek(s.file_offset)
            segs.append((s.virtual_address, s.file_offset, f.read(s.virtual_size)))


def va2off(va):
    for vbase, fbase, data in segs:
        if vbase <= va < vbase + len(data):
            return (va - vbase), data
    return None, b""


dyn = {str(e.tag).split(".")[-1]: e.value for e in B.dynamic_entries}
ia = dyn["INIT_ARRAY"]
isz = dyn["INIT_ARRAYSZ"]
print("INIT_ARRAY", hex(ia), "size", isz)
off, data = va2off(ia)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
for i in range(isz // 4):
    va = struct.unpack("<I", data[off:off + 4])[0]
    off += 4
    eoff, edata = va2off(va & ~1)
    ins = list(md.disasm(edata[eoff:eoff + 0x20], va & ~1))
    print("  init[%d] -> 0x%x: %s" % (i, va, "; ".join("%s %s" % (x.mnemonic, x.op_str) for x in ins[:4])))