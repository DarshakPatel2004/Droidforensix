"""Phase 1 verdict scan: is libijm-emulator code decodable at rest?

Decision gate for Path B: we can only build informed ART stubs if we can read
the ART call graph. If JNI_OnLoad / the rest of .text is ciphertext at rest,
the "call sequence" doesn't exist in static form -> Path B needs a code-decrypt
step first (a whole other Everest).

Metric: slide a window; count how many ARM64 instructions decode; a real code
region decodes with very high density (~100%) and shows a prologue pattern.
"""
import pathlib
import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, \
    CS_ARCH_ARM, CS_MODE_THUMB

CASES = [
    ("analysis/emulate/calc_ijiami/libijm-emulator.so", "arm64"),
    ("analysis/emulate/calc_ijiami/fullrun/libs/armeabi-v7a_libijm-emulator.so", "arm32"),
    ("analysis/emulate/calc_ijiami/fullrun/libs/arm64-v8a_libijm-emulator.so", "arm64"),
]

md = {
    "arm64": Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN),
    "arm32": Cs(CS_ARCH_ARM, CS_MODE_THUMB),
}


def decode_density(img, start, size, arch):
    code = img[start:start + size]
    insn = list(md[arch].disasm(code, start))
    return len(insn), (size // 4) if arch == "arm64" else (size // 2), insn


for path, arch in CASES:
    b = lief.parse(path)
    seg = next(s for s in b.segments if str(s.type) == "TYPE.LOAD" and s.virtual_address == 0)
    img = bytes(seg.content)
    n = len(img)
    sym = next((s for s in b.exported_functions if s.name == "JNI_OnLoad"), None)
    va = sym.value if sym else 0
    dec, total, insn = decode_density(img, va, 0x400, arch)
    print("=== %s (%s) size %d JNI_OnLoad %x" % (pathick if False else path.split("/")[-1], arch, n, va))
    print("  decode density @JNI_OnLoad+0x400: %d/%d (%.1f%%)" % (dec, total, 100.0 * dec / (total or 1)))
    if insn:
        print("  first 6:", "; ".join("%s %s" % (i.mnemonic, i.op_str) for i in insn[:6]))
    # content density on a sliding 0x200 window along the whole file every 0x400
    best = (0, None)
    for off in range(0, n - 0x400, 0x400):
        d, t, _ = decode_density(img, off, 0x400, arch)
        if t and d / t > best[0]:
            best = (d / t, off)
    print("  best-density window: %.1f%% @0x%x" % (best[0] * 100, best[1] if best[1] is not None else -1))