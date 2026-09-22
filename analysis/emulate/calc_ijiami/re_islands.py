"""Locate real code regions vs ciphertext islands. Where does the real
entry flow start? Does JNI_OnLoad (0xc5c0) sit inside a code island that just
doesn't decode with a naive linear sweep, or inside a ciphertext island?"""
import pathlib
import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

b = lief.parse("analysis/emulate/calc_ijiami/libijm-emulator.so")
seg = next(s for s in b.segments if str(s.type) == "TYPE.LOAD" and s.virtual_address == 0)
img = bytes(seg.content)
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True

# sliding window density over the first mapped 0x30000, window 0x400, step 0x200-ish
W, STEP = 0x400, 0x100
density = []
for off in range(0, min(len(img), 0x40000) - W, STEP):
    insn = list(md.disasm(img[off:off + W], off))
    density.append((off, len(insn) / (W // 4)))

# group consecutive high-density offsets into islands
islands = []
cur = None
for off, d in density:
    if d > 0.5:
        if cur is None:
            cur = [off, off + W, d]
        else:
            cur[1] = off + W
            cur[2] = max(cur[2], d)
    else:
        if cur:
            islands.append(cur)
            cur = None
if cur:
    islands.append(cur)

print("code islands (density>0.5):", ["%x-%x (%.0f%%)" % (a, b, d * 100) for a, b, d in islands])
jni = 0xC5C0
in_island = [(a, b) for a, b, _ in islands if a <= jni < b]
print("JNI_OnLoad 0x%x in island? %s" % (jni, in_island))

# disassemble the biggest island start and check for prologue/jump patterns
if islands:
    a, b, _ = max(islands, key=lambda t: t[1] - t[0])
    insn = list(md.disasm(img[a:a + 0x100], a))
    print("biggest island %x-%x first 20:" % (a, b))
    for i in insn[:20]:
        print("  %08x: %s %s" % (i.address, i.mnemonic, i.op_str))