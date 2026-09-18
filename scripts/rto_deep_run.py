#!/usr/bin/env python3
"""M3b continuation: corrected-vtable run with disk checkpointing.

Runs RTO's arm64 decryptor with the fixed JNIEnv slot layout (+0 without
header offset), serves device properties/Build fields for key derivation,
and intercepts reflection semantics. Checkpoints every 2M instructions.
"""
import sys
sys.path.insert(0, "scripts")
import pathlib
import pickle
import time

from unicorn import UC_HOOK_CODE
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

import emulate

OUT = pathlib.Path("analysis/recovered")
STATE = pathlib.Path("/tmp/oracle_state.pkl")
CKPT_EVERY = 2_000_000

emu = emulate.Emulator(pathlib.Path("/tmp/arm64.so"))
emu.load_elf()
emu.map_regions()
emu.wire_got_shims()
emu.wire_jni_table()

history = []
insn_count = [0]
t0 = time.time()


def deep(uc, address, size, ud):
    insn_count[0] += 1
    history.append(address)
    if len(history) > 600:
        history.pop(0)
    if insn_count[0] % CKPT_EVERY == 0:
        pickle.dump({"count": insn_count[0], "log": emu.jni_log,
                     "heap": emu.heap_ptr},
                    open(STATE, "wb"))


entry, _ = emu.find_entry()
uc = emu.uc
uc.hook_add(UC_HOOK_CODE, deep)

status = "clean"
try:
    emu.run(entry, timeout_s=3600)
except Exception as e:
    status = str(e)[:60]

print(f"finished: {status} | insns~{insn_count[0]} | heap {emu.heap_ptr} "
      f"| jni calls {len(emu.jni_log)} | wall {time.time()-t0:.0f}s")

print("\n=== JNI trace ===")
for e in emu.jni_log[:60]:
    print("  ", e)

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
print("\n=== last PCs ===")
for a in history[-20:]:
    lbl = ""
    idx_jni = (a - emulate.SHIM_PAGE - 0x30000)
    if 0 <= idx_jni < len(emulate.JNI_TABLE) * 16 and idx_jni % 16 == 0:
        lbl = emulate.JNI_TABLE[idx_jni // 16]
    try:
        code = bytes(uc.mem_read(a, 4))
        txt = " ".join(f"{i.mnemonic} {i.op_str};" for i in md.disasm(code, a))[:56]
    except Exception:
        txt = "<unmapped>"
    print(f"  0x{a:x} {lbl:22} {txt}")

blobs = emu.sweep_blobs()
new = [b for b in blobs
       if b.get("sha256") != "4848633769faeaf9cb3be087308a3f4afb13fd6027b929e371dd2771c3f7bc74"]
print("\nblobs:", [{k: v for k, v in b.items() if k != "data"} for b in blobs])
for b in new:
    if b.get("data"):
        out = OUT / f"PAYLOAD_{b['sha256'][:12]}.bin"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(b["data"])
        print("*** NEW PAYLOAD", out, b["size"])

# persist everything for offline analysis regardless of outcome
pickle.dump({"jni": emu.jni_log, "objects": {hex(k): v for k, v in emu.objects.items()},
             "defined": {k: (v.hex() if isinstance(v, bytes) else v)
                          for k, v in emu.defined_classes.items()},
             "heap_used": emu.heap_ptr, "status": status,
             "insns": insn_count[0]},
            open(STATE, "wb"))
print("state ->", STATE)
