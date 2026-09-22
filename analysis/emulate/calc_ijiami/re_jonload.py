"""Phase 1: static RE of libijm-emulator.so.
Disassemble JNI_OnLoad + all BL-targets, find dlsym call sites, entropy check."""
import sys, pathlib
import struct, math
import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

ROOT = pathlib.Path("analysis/emulate/calc_ijiami")
SO = ROOT / "libijm-emulator.so"

b = lief.parse(str(SO))
seg = next(s for s in b.segments if str(s.type) == "TYPE.LOAD")
img = bytes(seg.content)
base = seg.virtual_address

def ent(buf):
    if not buf:
        return 0.0
    from collections import Counter
    c = Counter(buf)
    n = len(buf)
    return -sum((k / n) * math.log2(k / n) for k in c.values())

JNI_ONLOAD = 0xC5C0 if False else None
def va_to_off(va):
    return va - base

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True

jni_sym = next(s for s in b.exported_functions if s.name == "JNI_OnLoad")
va = jni_sym.address
print("JNI_OnLoad @ %x, size %d" % (va, jni_sym.size))
raw = img[va - base: va - base + jni_sym.size]
print("entropy %.2f over %d bytes" % (ent(raw), len(raw)))

# walk the function: disassemble instructions until we hit ret/undefined
def get_insn(a):
    off = a - base
    if off < 0 or off + 16 > len(img):
        return None
    code = img[off:off + 4]
    return next(md.disasm(code, a), None)

cur = va
seen = set()
calls_so_far = []
for i in range(300):
    if cur in seen:
        break
    seen.add(cur)
    try:
        ins = next(md.disasm(img[cur - base: cur - base + 16], cur))
    except StopIteration:
        print("  (undecodable at %x)" % cur)
        break
    print("  %08x: %-28s %s %s" % (cur, ins.mnemonic + " " + ins.op_str if False else "%d %s %s" % (cur, ins.mnemonic, ins.op_str), "", "")) if False else None
    print("    %08x: %s %s" % (cur, ins.mnemonic, ins.op_str))
    if ins.mnemonic == "ret":
        calls_so_far.append(("ret", cur, ""))
        break
    cur += 4
print()
print("calls made so far:", calls_so_far)