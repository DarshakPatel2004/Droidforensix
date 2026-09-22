import sys, pathlib, struct
sys.path.insert(0, str(pathlib.Path("scripts").resolve()))
import lief
from lief import ELF

# minimal ARM64 shared object exporting JNI_OnLoad (a `ret`)
binary = ELF.Binary.create(ELF.ARCH.AARCH64, ELF.CLASS.ELF64)
binary.header.machine_type = ELF.ARCH.AARCH64
binary.header.entrypoint = 0

seg = binary.add(ELF.Segment())
seg.type = ELF.Segment.TYPE.LOAD
seg.content = bytearray(0x1000)
seg.virtual_address = 0x1000
seg.flags = ELF.Segment.FLAGS.R | ELF.Segment.FLAGS.X

text = binary.add_section()
text.name = ".text"
text.content = bytes.fromhex("c0035fd6")  # ret
text.virtual_address = 0x1100
text.flags = ELF.Section.FLAGS.ALLOC | ELF.Section.FLAGS.EXECINSTR

symtab = binary.add(ELF.Symbol())
symtab.name = "JNI_OnLoad"
symtab.value = 0x1100
symtab.type = ELF.Symbol.TYPE.FUNC
symtab.binding = ELF.Symbol.BINDING.GLOBAL
symtab.section_idx = text.index

out = pathlib.Path("analysis/emulate/calc_ijiami/min_jonload.so")
binary.write(str(out))
print("wrote", out, out.stat().st_size, "bytes")
# sanity: parse back
so = lief.ELF.parse(out)
print("arch:", so.header.machine_type, [s.name for s in so.exported_functions])