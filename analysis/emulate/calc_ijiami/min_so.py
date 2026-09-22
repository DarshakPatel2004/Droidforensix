"""Exploratory: handcraft a minimal ARM64 ET_DYN that lief parses.

lief 1.0 does not expose dynsym without a section header table, so a hand
crafted segment-only ELF reports 0 dynamic symbols. Keeping this file as a
reference for the failed approach; tests use fake-binary objects instead.
"""

import struct


def build_min_arm64_so() -> bytes:
    load_va = 0x1000
    code = bytes.fromhex("c0035fd6")  # ret
    ehsize, phentsize, phnum = 64, 56, 1
    phoff = ehsize
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident, 3, 183, 1, 0, phoff, 0, 0, ehsize, phentsize, phnum, 0, 0, 0,
    )
    load = struct.pack(
        "<IIQQQQQQ", 1, 5, 0x200, load_va, load_va, 0x4000, 0x4000, 0x1000,
    )
    out = bytearray(0x200) + bytearray(0x4000)
    out[0:64] = header
    out[64:64 + len(load)] = load
    out[0x200:0x204] = code  # vaddr load_va -> file 0x200
    return bytes(out)


if __name__ == "__main__":
    import lief
    import pathlib
    data = build_min_arm64_so()
    p = pathlib.Path("analysis/emulate/calc_ijiami/min_jonload.so")
    p.write_bytes(data)
    b = lief.parse(str(p))
    print("machine:", b.header.machine_type)
    print("exports:", [s.name for s in b.exported_functions])
    print("dynamic syms:", len(b.dynamic_symbols))