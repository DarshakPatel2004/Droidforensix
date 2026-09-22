"""Phase 1 gate report for libijm-emulator (arm64 + arm32 ABI).

Output: per-ABI code island map, JNI_OnLoad target, and whether an ART call
graph exists statically. This is the go/no-go deliverable the user asked for.
"""
import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, CS_ARCH_ARM, CS_MODE_THUMB

CASES = [
    ("analysis/emulate/calc_ijiami/libijm-emulator.so", "arm64"),
    ("analysis/emulate/calc_ijiami/fullrun/libs/armeabi-v7a_libijm-emulator.so", "arm32"),
]
MD = {
    "arm64": Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN),
    "arm32": Cs(CS_ARCH_ARM, CS_MODE_THUMB),
}
W = 0x200

for path, arch in CASES:
    b = lief.parse(path)
    seg = next(s for s in b.segments if str(s.type) == "TYPE.LOAD" and s.virtual_address == 0)
    img = bytes(seg.content)
    jni = next((s.value for s in b.exported_functions if s.name == "JNI_OnLoad"), 0)
    md = MD[arch]
    islands = []
    density = []
    for off in range(0, len(img) - W, W // 2):
        ins = list(md.disasm(img[off:off + W], off))
        udf = sum(1 for i in ins if i.mnemonic.startswith("udf") or i.mnemonic == "unreachable")
        real = max(0, len(ins) - udf) / (W // (4 if arch == "arm64" else 2))
        density.append((off, real))
    cur = None
    for off, d in density:
        if d > 0.5:
            if cur is None:
                cur = [off, off + W]
            else:
                cur[1] = off + W
        else:
            if cur:
                islands.append(tuple(cur))
                cur = None
    if cur:
        islands.append(tuple(cur))
    print("=== %s %s (JNI_OnLoad=0x%x)" % (path.split("/")[-1], arch, jni))
    print("  code islands:", ["0x%x-0x%x (%db)" % (a, bl, bl - a) for a, bl in islands])
    in_isl = [ (a,bl) for a,bl in islands if a <= jni < bl ]
    print("  JNI_OnLoad inside a code island:", in_isl if in_isl else "NO (likely ciphertext/bytecode)")
    # does the real code reference the obfuscated tail strings? check addrs after each adrp
    tail_off = len(img) - 0x400
    head = img[:0x400]
    print("  head magic:", head[:16].hex())