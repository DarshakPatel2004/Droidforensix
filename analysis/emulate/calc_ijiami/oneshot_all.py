import sys, pathlib
sys.stdout.reconfigure(line_buffering=True)
root = pathlib.Path(__file__).resolve().parents[0]
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3] / "scripts"))
from unicorn import UC_HOOK_MEM_WRITE
import emulate

base_dir = pathlib.Path("analysis/emulate/calc_ijiami")
for name in ("libexec.so", "libexecmain.so", "libijm-emulator.so"):
    so = base_dir / name
    emu = emulate.Emulator(so)
    writes = []
    hook = {"arm": None, "x86": None, "arm64": None}
    def mem_w(uc, access, addr, size, val, ud):
        if emu.base <= addr < emu.base + 0x90000:
            writes.append(addr)
            if len(writes) > 5000:
                raise Exception("too many writes")
    if emu.arch_name == "arm64":
        emu.uc.hook_add(UC_HOOK_MEM_WRITE, mem_w)
    try:
        meta = emu.run_jni_oneshot(run_timeout_s=45)
    except Exception as exc:
        meta = {"status": "setup-fail: %s" % str(exc)[:80]}
    lo = emu.base
    in_lo = [a for a in writes if lo <= a < lo + 0x90000]
    blobs = emu.sweep_blobs()
    print("==== %s" % name)
    print("  entry=%s status=%s ctors=%s jni=%s regnatives=%d"
          % (meta.get("entry"), meta.get("status"),
             meta.get("ctors"), meta.get("jni_calls"),
             len(meta.get("register_natives") or [])))
    print("  writes into first 0x90000 (code+data LOAD): %d" % len(in_lo))
    for a in in_lo[:6]:
        print("    wrt off %x" % (a - lo))
    print("  blobs: %d" % len(blobs))
    for b in blobs[:4]:
        print("    %s %s %s %d" % (b["kind"], b["section"], hex(b["va"]), b["size"]))