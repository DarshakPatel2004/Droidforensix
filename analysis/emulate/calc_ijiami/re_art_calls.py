"""Phase 1: ART-call mapping on libijm-emulator.so (arm64).

Goal: find dlsym() call sites -> what ART APIs does the loader resolve?
Facts so far: JNI_OnLoad bytes at rest don't disassemble (code-protected);
string table shows no ART names (they are XOR-obfuscated around file tail).
"""
import sys, pathlib, struct
import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

SO = pathlib.Path("analysis/emulate/calc_ijiami/libijm-emulator.so")
b = lief.parse(str(SO))
seg = next(s for s in b.segments if str(s.type) == "TYPE.LOAD" and s.virtual_address == 0)
img = bytes(seg.content)

# PLT slot for dlsym (import -> got -> plt)
plt_targets = {}
for rel in b.pltgot_relocations:
    if rel.symbol and rel.symbol.name == "dlsym":
        plt_targets[rel.address] = "dlsym"
    elif rel.symbol and rel.symbol.name in ("dlopen", "dl_iterate_phdr"):
        plt_targets[rel.address] = rel.symbol.name

print("PLT/GOT targets:", {hex(k): v for k, v in plt_targets.items()})

# Scan the whole executable region for BL to those GOT slots
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
call_sites = {k: [] for k in plt_targets}
for ins in md.disasm(img, 0):
    if ins.mnemonic == "bl":
        op = getattr(ins, "op_str", "")
        for got in plt_targets:
            if op and op.startswith("#0x") and int(op, 16) == got:
                call_sites[got].append(ins.address)

for got, sites in call_sites.items():
    print("dlsym bl sites:", [hex(a) for a in sites])

# where does the dynamic symbol point & is there a launcher detectable by low byte-xor?
sym = next(s for s in b.exported_functions if s.name == "JNI_OnLoad")
print("JNI_OnLoad st_value", hex(sym.value), "shndx", sym.section_idx)
# Check immediate context around 0xc5c0 for a jump table / thunk pattern
around = img[0xC570:0xC640]
print("0xc5c0 ctx:", around.hex())
for i in md.disasm(around, 0xC570):
    print("  %08x: %s %s" % (i.address, i.mnemonic, i.op_str))