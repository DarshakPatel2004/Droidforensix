#!/usr/bin/env python3
"""C4 Emulation Oracle - generic JNI-stage loader (plan section C4).

Refactored after M2/M3 prototyping into a reusable stage:
  - LIEF-based ELF loader (x86_64 / ARM32 Thumb / ARM64), PIE aware
  - Bump-allocator heap + stack + ret-stub layout
  - GOT shim for libc imports (native Python semantics)
  - Full 233-slot JNIEnv vtable mock with DEX-capture in DefineClass
  - Post-run artifact sweep: base64 blobs -> decoded dex, raw dex magic

Batch mode:
  python3 scripts/emulate.py --apk RTO.apk              # auto-pick lib+entry
  python3 scripts/emulate.py --locklist analysis/triage_m0/summary.csv \
      --triage-packed --workdir analysis/emulate
"""

import argparse
import base64
import hashlib
import json
import os
import pathlib
import re
import struct
import sys
import zipfile

import lief
from unicorn import UC_HOOK_INTR, UC_HOOK_MEM_READ


def _dbg(msg):
    if os.environ.get("JNI_DEBUG"):
        print(msg, flush=True)


from unicorn import (
    UC_ARCH_ARM,
    UC_ARCH_ARM64,
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_MODE_64,
    UC_MODE_ARM,
    UC_MODE_LITTLE_ENDIAN,
    UC_MODE_THUMB,
    Uc,
    arm64_const,
)
from unicorn.arm64_const import (
    UC_ARM64_REG_LR,
    UC_ARM64_REG_PC,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,
    UC_ARM64_REG_X3,
)
from unicorn.arm_const import (
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
    UC_ARM_REG_R7,
    UC_ARM_REG_SP,
)
from unicorn.x86_const import (
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_RAX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDI,
    UC_X86_REG_RDX,
    UC_X86_REG_RIP,
    UC_X86_REG_RSI,
    UC_X86_REG_RSP,
)

JNI_TABLE = ["reserved0","reserved1","reserved2","reserved3","GetVersion","DefineClass","FindClass",
"FromReflectedMethod","FromReflectedField","ToReflectedMethod","GetSuperclass","IsAssignableFrom",
"ToReflectedField","Throw","ThrowNew","ExceptionOccurred","ExceptionDescribe","ExceptionClear",
"FatalError","PushLocalFrame","PopLocalFrame","NewGlobalRef","DeleteGlobalRef","DeleteLocalRef",
"IsSameObject","NewLocalRef","EnsureLocalCapacity","AllocObject","NewObject","NewObjectV","NewObjectA",
"GetObjectClass","IsInstanceOf","GetMethodID","CallObjectMethod","CallObjectMethodV","CallObjectMethodA",
"CallBooleanMethod","CallBooleanMethodV","CallBooleanMethodA","CallByteMethod","CallByteMethodV","CallByteMethodA",
"CallCharMethod","CallCharMethodV","CallCharMethodA","CallShortMethod","CallShortMethodV","CallShortMethodA",
"CallIntMethod","CallIntMethodV","CallIntMethodA","CallLongMethod","CallLongMethodV","CallLongMethodA",
"CallFloatMethod","CallFloatMethodV","CallFloatMethodA","CallDoubleMethod","CallDoubleMethodV","CallDoubleMethodA",
"CallVoidMethod","CallVoidMethodV","CallVoidMethodA",
"CallNonvirtualObjectMethod","CallNonvirtualObjectMethodV","CallNonvirtualObjectMethodA",
"CallNonvirtualBooleanMethod","CallNonvirtualBooleanMethodV","CallNonvirtualBooleanMethodA",
"CallNonvirtualByteMethod","CallNonvirtualByteMethodV","CallNonvirtualByteMethodA","CallNonvirtualCharMethod",
"CallNonvirtualCharMethodV","CallNonvirtualCharMethodA","CallNonvirtualShortMethod","CallNonvirtualShortMethodV",
"CallNonvirtualShortMethodA","CallNonvirtualIntMethod","CallNonvirtualIntMethodV","CallNonvirtualIntMethodA",
"CallNonvirtualLongMethod","CallNonvirtualLongMethodV","CallNonvirtualLongMethodA","CallNonvirtualFloatMethod",
"CallNonvirtualFloatMethodV","CallNonvirtualFloatMethodA","CallNonvirtualDoubleMethod","CallNonvirtualDoubleMethodV",
"CallNonvirtualDoubleMethodA","CallNonvirtualVoidMethod","CallNonvirtualVoidMethodV","CallNonvirtualVoidMethodA",
"GetFieldID","GetObjectField","GetBooleanField","GetByteField","GetCharField","GetShortField","GetIntField",
"GetLongField","GetFloatField","GetDoubleField","SetObjectField","SetBooleanField","SetByteField","SetCharField",
"SetShortField","SetIntField","SetLongField","SetFloatField","SetDoubleField","GetStaticMethodID","CallStaticObjectMethod",
"CallStaticObjectMethodV","CallStaticObjectMethodA","CallStaticBooleanMethod","CallStaticBooleanMethodV",
"CallStaticBooleanMethodA","CallStaticByteMethod","CallStaticByteMethodV","CallStaticByteMethodA",
"CallStaticCharMethod","CallStaticCharMethodV","CallStaticCharMethodA","CallStaticShortMethod",
"CallStaticShortMethodV","CallStaticShortMethodA","CallStaticIntMethod","CallStaticIntMethodV",
"CallStaticIntMethodA","CallStaticLongMethod","CallStaticLongMethodV","CallStaticLongMethodA",
"CallStaticFloatMethod","CallStaticFloatMethodV","CallStaticFloatMethodA","CallStaticDoubleMethod",
"CallStaticDoubleMethodV","CallStaticDoubleMethodA","CallStaticVoidMethod","CallStaticVoidMethodV",
"CallStaticVoidMethodA","GetStaticFieldID","GetStaticObjectField","GetStaticBooleanField","GetStaticByteField",
"GetStaticCharField","GetStaticShortField","GetStaticIntField","GetStaticLongField","GetStaticFloatField",
"GetStaticDoubleField","SetStaticObjectField","SetStaticBooleanField","SetStaticByteField","SetStaticCharField",
"SetStaticShortField","SetStaticIntField","SetStaticLongField","SetStaticFloatField","SetStaticDoubleField",
"NewString","GetStringLength","GetStringChars","ReleaseStringChars","NewStringUTF","GetStringUTFLength",
"GetStringUTFChars","ReleaseStringUTFChars","GetArrayLength","NewObjectArray","GetObjectArrayElement",
"SetObjectArrayElement","NewBooleanArray","NewByteArray","NewCharArray","NewShortArray","NewIntArray",
"NewLongArray","NewFloatArray","NewDoubleArray","GetBooleanArrayElements","GetByteArrayElements",
"GetCharArrayElements","GetShortArrayElements","GetIntArrayElements","GetLongArrayElements",
"GetFloatArrayElements","GetDoubleArrayElements","ReleaseBooleanArrayElements","ReleaseByteArrayElements",
"ReleaseCharArrayElements","ReleaseShortArrayElements","ReleaseIntArrayElements","ReleaseLongArrayElements",
"ReleaseFloatArrayElements","ReleaseDoubleArrayElements","GetBooleanArrayRegion","GetByteArrayRegion",
"GetCharArrayRegion","GetShortArrayRegion","GetIntArrayRegion","GetLongArrayRegion","GetFloatArrayRegion",
"GetDoubleArrayRegion","SetBooleanArrayRegion","SetByteArrayRegion","SetCharArrayRegion","SetShortArrayRegion",
"SetIntArrayRegion","SetLongArrayRegion","SetFloatArrayRegion","SetDoubleArrayRegion","RegisterNatives",
"UnregisterNatives","MonitorEnter","MonitorExit","GetJavaVM","GetStringRegion","GetStringUTFRegion",
"GetPrimitiveArrayCritical","ReleasePrimitiveArrayCritical","GetStringCritical","ReleaseStringCritical",
"NewWeakGlobalRef","DeleteWeakGlobalRef","ExceptionCheck","NewDirectByteBuffer","GetDirectBufferAddress",
"GetDirectBufferCapacity","GetObjectRefType"]

LIBC_NAMES = ["fopen","fopen64","fgets","feof","fclose","fread","fseek","ftell","getc",
    "open","openat","__open_2","read","__read_chk","close","lseek","fstat",
    "mmap","mmap64","munmap","mprotect","strstr","sscanf","vsscanf","snprintf","vsnprintf",
    "strchr","strrchr","strdup","memcmp","strncmp","mkdir","chmod","access","prctl",
    "syscall","getpid","gettid","gettimeofday","clock","sysconf","getpagesize",
    "dlopen","dlsym","dlclose","dladdr","readlink","opendir","readdir","closedir",
    "atoi","strtoll","__errno","__cxa_finalize","__cxa_atexit","__register_atfork","__stack_chk_fail",
    "pthread_mutex_lock","pthread_mutex_unlock","malloc","free","posix_memalign",
    "memset","vfprintf","fputc","vasprintf","android_set_abort_message","openlog",
    "syslog","closelog","abort","strlen","realloc","memmove","__memmove_chk",
    "__strlen_chk","memchr","__vsnprintf_chk","memcpy","strcmp","pthread_getspecific",
    "pthread_once","pthread_setspecific","pthread_key_delete","pthread_key_create",
    "getauxval","__system_property_get","strncmp","fprintf","fflush",
    "pthread_rwlock_wrlock","pthread_rwlock_unlock","dl_iterate_phdr",
    "pthread_rwlock_rdlock","fwrite",
    "calloc","inflateInit2_","inflateInit_","inflate","inflateEnd"]

def _reloc_kind(rel):
    """Classify a LIEF relocation by name. LIEF 1.x reports arch-tagged enums
    (ARM_RELATIVE=402653207, AARCH64_RELATIVE=268436483), so raw ELF numbers never
    match (audit P4). IRELATIVE needs a resolver call we do not model: skipped."""
    t = str(rel.type)
    if "IRELATIVE" in t:
        return None
    for kind in ("RELATIVE", "GLOB_DAT", "JUMP_SLOT", "ABS"):
        if kind in t:
            return kind
    return None


RET_ARM = bytes.fromhex("c0035fd6")
RET_THUMB = bytes.fromhex("7047")
RET_X86 = b"\xc3"

BASE_X64 = 0x400000
BASE_ARM = 0x100000
STACK_ADDR = 0x0FFF0000
HEAP_ADDR = 0x0A000000
# Host-side bounds on guest-controlled sizes (audit P7, P9).
MAX_GUEST_COPY = 64 * 1024 * 1024
MAX_CTORS = 64
SWEEP_MAX_SECTION = 64 * 1024 * 1024   # section bytes read per sweep (audit P8)
MAX_LIB_BYTES = 256 * 1024 * 1024     # one .so extracted from an APK (audit P13)
FAKE_JENV = 0x0B000000
JENV_TABLE = 0x0B100000
RET_STUB = 0x0C000000
SHIM_PAGE = 0x0D000000

# JavaVM/JNIInvokeInterface mock (ijiami_oracle.py, merged into Emulator).
# JavaVM* points to a cell holding the function-table pointer; slots point at
# a shared ret stub. GetEnv = slot 6 in the 3-reserved Android layout.
VM_TABLE = SHIM_PAGE + 0x20000
FUNC_TABLE = VM_TABLE + 0x40
VM_STUB = VM_TABLE + 0x100
N_VM_SLOTS = 8
GETENV_SLOT = 6

SIZES = {
    (UC_ARCH_X86, UC_MODE_64): ("x86_64", 8),
    (UC_ARCH_ARM, UC_MODE_THUMB if False else UC_MODE_ARM): ("arm", 4),
    (UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN): ("aarch64", 8),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pick_arch(so_path: pathlib.Path):
    """Return (uc_arch, uc_mode, ret_stub_bytes, reg_names) for the ELF."""
    binary = lief.parse(str(so_path))
    m = binary.header.machine_type
    name = str(m).split(".")[-1].upper()
    if "AARCH64" in name or "ARM64" in name:
        return UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, RET_ARM, "arm64"
    if "ARM" in name:
        return UC_ARCH_ARM, UC_MODE_THUMB, RET_THUMB, "arm"
    if "X86_64" in name or "AMD64" in name:
        return UC_ARCH_X86, UC_MODE_64, RET_X86, "x86_64"
    raise RuntimeError("unsupported arch %s" % name)


def is_hardened_vm(binary, sym="JNI_OnLoad", window=0x400, min_density=0.1):
    """Detect code-protected (bytecode VM) libs without booting the oracle.

    Hardened packers (Ijiami emulator family, Calculator.apk) encrypt the entire
    code payload: the exported entry (.init_array ctors, JNI_OnLoad) points at
    ciphertext that fails to decode as native instructions, and ART/class APIs
    are resolved only via dlsym with XOR-obfuscated names. Bootstrapping such a
    lib under Unicorn wastes minutes and produces no DEX; the caller should
    emit E-HARDENED-VM instead.

    Heuristic: disassemble `window` bytes at the symbol's address and measure
    the fraction of those bytes covered by decodable instructions (sum of
    insn.size / window). Real code covers >= ~0.9 (fixed-width ARM) or ~1.0
    (x86); ciphertext covers < 0.05. Threshold 0.1 keeps small real functions
    (e.g. Calculator's libcalc32 JNI_OnLoad, 0.129) unflagged while catching
    hard-encrypted entries (0.0-0.03).

    Returns (bool, dict) - (hardened, evidence for the report).
    """
    from capstone import (
        CS_ARCH_ARM,
        CS_ARCH_ARM64,
        CS_ARCH_X86,
        CS_MODE_64,
        CS_MODE_THUMB,
        Cs,
    )

    def _all_syms():
        yield from (binary.exported_functions or [])
        try:
            yield from list(binary.dynamic_symbols or [])
        except TypeError:
            for _s in binary.dynamic_symbols or []:
                yield _s

    target = None
    for _s in _all_syms():
        if _s.name == sym:
            target = _s
            break
    if target is None:
        return False, {}

    arch_name = str(binary.header.machine_type).split(".")[-1].upper()
    if "AARCH64" in arch_name or "ARM64" in arch_name:
        md = Cs(CS_ARCH_ARM64, 0)
    elif "ARM" in arch_name:
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)  # Android arm libs are Thumb-2
        mask = ~1  # Thumb symbol VAs carry bit0; decode from the real halfword
    elif "X86_64" in arch_name or "AMD64" in arch_name:
        md = Cs(CS_ARCH_X86, CS_MODE_64)  # 64-bit
    elif "I386" in arch_name or "80386" in arch_name or "X86" in arch_name:
        md = Cs(CS_ARCH_X86, 0)  # 32-bit x86
    else:
        return False, {}

    # locate the byte span for the symbol via LOAD segments (VA -> file bytes)
    va = target.address if hasattr(target, "address") else target.value
    try:
        va &= mask
    except NameError:
        pass
    blob = None
    for seg in binary.segments:
        if "LOAD" not in str(seg.type):
            continue
        sva, vsz = seg.virtual_address, seg.virtual_size
        if sva <= va < sva + vsz:
            content = bytes(seg.content)
            off = va - sva
            if off + window <= len(content):
                blob = content[off:off + window]
            break
    if not blob:
        return False, {}

    density = _decode_density(md, blob)
    return density < min_density, {"decode_density": round(density, 3)}


def _decode_density(md, blob):
    """Fraction of `blob` bytes covered by decodable instructions.

    Uses insn.size (byte coverage) rather than instruction count so x86's
    variable-length code and fixed-width ARM compare on the same scale.
    """
    covered = sum(i.size for i in md.disasm(blob, 0x0)
                  if not (i.mnemonic.startswith("udf") or i.mnemonic == "invalid"))
    return covered / max(1, len(blob))


class Emulator:
    def __init__(self, so_path: pathlib.Path):
        self.so_path = so_path
        self.binary = lief.parse(str(so_path))
        self.arch, self.mode, self.ret_bytes, self.arch_name = pick_arch(so_path)
        self.uc = Uc(self.arch, self.mode)
        self.heap_ptr = 0
        self.objects = {}
        self.next_obj = 0x500
        self.jni_log = []
        self.libc_calls = []
        self.defined_classes = {}
        self.last_pcs = []
        self.base = BASE_X64 if self.arch_name == "x86_64" else BASE_ARM
        self.method_names = {}    # method_id obj -> method name
        self.method_sigs = {}     # method_id obj -> JNI signature string
        self.key_log = []         # key-derivation trace (getBytes/digest/init)
        self._sb = {}             # StringBuilder obj -> accumulated string
        self._ctor_hint = "?"     # class of last <init> via reflection
        self.field_names = {}     # field_id obj  -> field name
        self.array_ptrs = {}      # bytes obj     -> heap backing ptr
        self.fallback_slot = SHIM_PAGE + len(LIBC_NAMES) * 16

    def bump(self, size: int) -> int:
        a = HEAP_ADDR + self.heap_ptr
        self.heap_ptr += (size + 15) & ~15
        return a

    def new_obj(self, kind, val=None):
        self.next_obj += 8
        self.objects[self.next_obj] = (kind, val)
        return self.next_obj

    def cstr(self, addr, maxn=256):
        out = bytearray()
        for i in range(maxn):
            try:
                c = self.uc.mem_read(addr + i, 1)[0]
            except Exception:
                break
            if c == 0:
                break
            out.append(c)
        return out.decode(errors="ignore")

    def load_elf(self):
        uc = self.uc
        base = self.base
        for seg in self.binary.segments:
            if "LOAD" not in str(seg.type):
                continue
            vaddr = base + seg.virtual_address
            aligned = vaddr & ~0xFFF
            sz = (vaddr + seg.virtual_size - aligned + 0xFFF) & ~0xFFF
            if sz:
                uc.mem_map(aligned, sz)
            content = bytes(seg.content)
            if content:
                uc.mem_write(vaddr, content)
        self.apply_relocations()

    def _log_null_read(self, uc, access, address, size, value, user_data):
        if len(self.null_reads) < 32:
            self.null_reads.append(hex(address))

    def apply_relocations(self):
        """Rebase internal pointers and wire remaining reloc types (arm32 .data
        function pointers otherwise point to unbased addrs -> header exec)."""
        uc = self.uc
        base = self.base
        psize = 4 if self.arch_name == "arm" else (8 if self.arch_name == "x86_64" else 8)
        fmt = "<I" if psize == 4 else "<Q"
        shim_by_name = {}
        for i, n in enumerate(LIBC_NAMES):
            shim_by_name[n] = SHIM_PAGE + i * 16
        for rel in self.binary.relocations:
            rtype = _reloc_kind(rel)
            if rtype is None:
                continue
            addr = base + rel.address
            sym = rel.symbol
            if rtype == "RELATIVE":
                try:
                    old = struct.unpack(fmt, uc.mem_read(addr, psize))[0]
                    uc.mem_write(addr, struct.pack(fmt, (old + base) & ((1 << (psize * 8)) - 1)))
                except Exception:
                    pass
            elif rtype in ("GLOB_DAT", "JUMP_SLOT"):
                if sym is not None and sym.name in shim_by_name:
                    ptr = shim_by_name[sym.name] | (1 if self.arch_name == "arm" else 0)
                    uc.mem_write(addr, struct.pack(fmt, ptr))
                elif sym is not None and sym.value:
                    # internal symbol (e.g. C++ vtable entries / callback tables)
                    uc.mem_write(addr, struct.pack(fmt, base + sym.value))
                elif sym is not None and sym.name:
                    # unknown external import -> generic ret-0 shim
                    uc.mem_write(addr, struct.pack(
                        fmt, self.fallback_slot | (1 if self.arch_name == "arm" else 0)))
            elif rtype == "ABS":
                if sym is not None and sym.value:
                    uc.mem_write(addr, struct.pack(fmt, base + sym.value))
                elif sym is None:
                    try:
                        old = struct.unpack(fmt, uc.mem_read(addr, psize))[0]
                        uc.mem_write(addr, struct.pack(fmt, (old + base) & ((1 << (psize * 8)) - 1)))
                    except Exception:
                        pass

    def map_regions(self):
        uc = self.uc
        uc.mem_map(STACK_ADDR, 1024 * 1024)
        uc.mem_map(HEAP_ADDR, 16 * 1024 * 1024)
        uc.mem_map(FAKE_JENV, 0x1000)
        uc.mem_map(JENV_TABLE, 0x20000)
        uc.mem_map(RET_STUB, 0x1000)
        uc.mem_map(0x0, 0x100000)   # TLS page for arm64 tpidr_el0-style reads
        self.null_reads = []        # reads of the mapped NULL page are logged, not silent (audit P4)
        uc.hook_add(UC_HOOK_MEM_READ, self._log_null_read, begin=0, end=0xFFFFF)
        uc.mem_write(0x28, struct.pack("<Q", HEAP_ADDR))
        uc.mem_map(SHIM_PAGE, 0x40000)
        self.uc.mem_write(self.fallback_slot, self.ret_bytes + bytes(12))
        stub = RET_STUB
        if self.arch_name == "arm64":
            uc.mem_write(stub, self.ret_bytes)
        elif self.arch_name == "arm":
            uc.mem_write(stub | 1, self.ret_bytes)
        else:
            uc.mem_write(stub, self.ret_bytes)

    def wire_got_shims(self):
        got = {rel.address: rel.symbol.name
               for rel in self.binary.pltgot_relocations if rel.symbol}
        for i, name in enumerate(LIBC_NAMES):
            slot = SHIM_PAGE + i * 16
            self.uc.mem_write(slot, self.ret_bytes + bytes(12))
            matches = [g for g, n in got.items() if n == name]
            for g in matches:
                # arm32 interworking: callee address must have bit0=1 (Thumb)
                ptr = struct.pack("<Q" if self.arch_name != "arm" else "<I",
                                  slot | 1 if self.arch_name == "arm" else slot)
                self.uc.mem_write(self.base + g, ptr)
            if matches:
                setattr(self, "_shim_%s" % name, slot)
        # Generic fallback shim: any import NOT in LIBC_NAMES returns 0
        # (prevents unresolved PLT stubs from executing PLT0 / ELF header)
        self.fallback_slot = SHIM_PAGE + len(LIBC_NAMES) * 16
        self.uc.mem_write(self.fallback_slot, self.ret_bytes + bytes(12))
        fb = self.fallback_slot | (1 if self.arch_name == "arm" else 0)
        for g, n in got.items():
            if n not in LIBC_NAMES:
                ptr = struct.pack("<Q" if self.arch_name != "arm" else "<I", fb)
                self.uc.mem_write(self.base + g, ptr)
        # keep registry of what's at which slot so the code hook can dispatch
        self._libc_slots = {SHIM_PAGE + i * 16: n for i, n in enumerate(LIBC_NAMES)}

    def wire_jni_table(self):
        uc = self.uc
        is_arm32 = self.arch_name == "arm"
        psize = 4 if is_arm32 else 8
        fmt = "<I" if is_arm32 else "<Q"
        for idx, name in enumerate(JNI_TABLE):
            # JNIEnv* deref yields this table directly; native code calls
            # funcs[idx] at idx*psize (no header) - verified against RTO's
            # ldr x8,[x19]; ldr x8,[x8,#0x720] => idx 228 ExceptionCheck.
            slot = JENV_TABLE + idx * psize
            h = SHIM_PAGE + 0x30000 + idx * 16
            uc.mem_write(h, self.ret_bytes + bytes(16 - len(self.ret_bytes)))
            # arm32 interworking: stored pointer carries bit0=1 (Thumb state)
            uc.mem_write(slot, struct.pack(fmt, h | 1 if is_arm32 else h))
            setattr(self, "_jni_%s" % name, h)
        uc.mem_write(FAKE_JENV, struct.pack(fmt, JENV_TABLE))
        self._jni_slots = {SHIM_PAGE + 0x30000 + idx * 16: n
                           for idx, n in enumerate(JNI_TABLE)}

    # ------------------------------------------------------------------
    # JavaVM mock (JNI_OnLoad path) -- merged from scripts/ijiami_oracle.py
    # ------------------------------------------------------------------
    def build_vm_table(self):
        """Standard JNI: (*vm)->GetEnv == *(*vm + 0x30), so JavaVM* points to
        a cell holding the function-table pointer; table slots -> shared stub.
        Returns the JavaVM* handle to pass as JNI_OnLoad's first arg."""
        uc = self.uc
        psize = 4 if self.arch_name == "arm" else 8
        fmt = "<I" if psize == 4 else "<Q"
        uc.mem_write(VM_TABLE, struct.pack(fmt, FUNC_TABLE))
        for i in range(N_VM_SLOTS):
            uc.mem_write(FUNC_TABLE + i * psize, struct.pack(fmt, VM_STUB))
        uc.mem_write(VM_STUB, self.ret_bytes + bytes(16 - len(self.ret_bytes)))
        return VM_TABLE

    def vm_hook(self, uc, address, size, ud):
        """GetEnv(vm, &env, ver) or AttachCurrentThread(vm, &env, args):
        hand out the fake JNIEnv in arg1 and return JNI_OK; other VM slots no-op."""
        if address & ~1 != VM_STUB:
            return
        get_arg = self._arg_readers()
        env_ptr = get_arg(1)
        if env_ptr:
            try:
                psize = 4 if self.arch_name == "arm" else 8
                fmt = "<I" if psize == 4 else "<Q"
                self.uc.mem_write(env_ptr, struct.pack(fmt, FAKE_JENV))
            except Exception:
                pass
        self._set_ret(0)

    def apply_relative_relocs(self):
        """emulate.py's apply_relocations() wires only GLOB_DAT/JUMP_SLOT.
        RELATIVE/ABS64 pointers in .data.rel.ro are needed before any
        non-trivial lib runs (self-decryptors dispatch through them).

        arm32 uses REL (addend is implicit, stored in the section data itself
        -- lief reports addend=0; reading rel.addend would clobber every slot
        with base+0, including .init_array) -> read original file bytes.
        arm64 uses RELA (explicit addend) -> keep the old path there."""
        uc, base = self.uc, self.base
        n = 0
        arm32 = self.arch_name == "arm"
        fmt = "<I" if arm32 else "<Q"
        orig = None
        if arm32:
            orig = pathlib.Path(self.so_path).read_bytes()

            def v2f(v):
                for seg in self.binary.segments:
                    if (seg.type == lief.ELF.Segment.TYPE.LOAD
                            and seg.virtual_address <= v
                            < seg.virtual_address + seg.virtual_size):
                        return seg.file_offset + (v - seg.virtual_address)
                return None
        for rel in self.binary.relocations:
            t = str(rel.type)
            if "RELATIVE" in t:
                if arm32:
                    off = v2f(rel.address)
                    if off is None or off + 4 > len(orig):
                        continue
                    (addend,) = struct.unpack("<I", orig[off:off + 4])
                else:
                    addend = rel.addend
                uc.mem_write(base + rel.address,
                             struct.pack(fmt, base + addend))
                n += 1
            elif "ABS64" in t:
                sym = rel.symbol
                if sym and sym.name and not sym.value:
                    val = SHIM_PAGE + 0x8000 + (hash(sym.name) % 0x400) * 16
                else:
                    val = base + ((sym.value if sym else 0) or 0) + rel.addend
                uc.mem_write(base + rel.address, struct.pack("<Q", val))
                n += 1
        return n

    def run_ctors(self, timeout_s=120):
        """dlopen semantics: DT_INIT, then INIT_ARRAY (self-decryptors live
        here). Runs before JNI_OnLoad; logs any JNI touchpoints."""
        uc, base = self.uc, self.base
        psize = 4 if self.arch_name == "arm" else 8
        fmt = "<I" if psize == 4 else "<Q"
        init_va = init_arr_va = init_arr_sz = None
        for e in self.binary.dynamic_entries:
            tag = str(e.tag)
            if tag == "TAG.INIT":
                init_va = e.value
            elif tag == "TAG.INIT_ARRAY":
                init_arr_va = e.value
            elif tag == "TAG.INIT_ARRAYSZ":
                init_arr_sz = e.value
        runs = []
        if init_va:
            self.run(base + init_va, timeout_s=timeout_s)
            runs.append("DT_INIT")
        if init_arr_va and init_arr_sz:
            # Capped: the count comes from the (untrusted) ELF header (audit P9).
            n = min(init_arr_sz // psize, MAX_CTORS)
            for i in range(n):
                (fn,) = struct.unpack(fmt, uc.mem_read(base + init_arr_va + i * psize, psize))
                if fn:
                    # Relocated slots already hold absolute addresses; adding base again ran ctors at
                    # 2*base+off (audit P2). Plain offsets are still accepted.
                    target = fn if fn >= base else base + fn
                    self.run(target, timeout_s=timeout_s)
            runs.append(f"INIT_ARRAY={n} ctors")
        return runs

    def capture_register_natives(self):
        """Record (name, sig, fn_offset) triples the packer binds at runtime."""
        uc = self.uc
        orig = self.do_jni
        psize = 4 if self.arch_name == "arm" else 8
        fmt = "<I" if psize == 4 else "<Q"

        def patched(name):
            if name == "RegisterNatives":
                get_arg = self._arg_readers()
                methods = get_arg(2)
                count = get_arg(3)
                for i in range(min(count, 64)):
                    try:
                        raw = bytes(uc.mem_read(methods + i * 3 * psize, 3 * psize))
                        name_p, sig_p, fn_p = struct.unpack(fmt * 3, raw)
                        nm = self.cstr(name_p) if name_p else "?"
                        sg = self.cstr(sig_p) if sig_p else "?"
                        off = fn_p - self.base if fn_p >= self.base else fn_p
                        self.jni_log.append(
                            ("RegisterNatives", nm, sg, "base+%s" % hex(off)))
                    except Exception as exc:
                        self.jni_log.append(("RegisterNatives", "unreadable", str(exc)[:40]))
                        break
            return orig(name)

        self.do_jni = patched

    def _arg_readers(self):
        uc = self.uc
        if self.arch_name == "arm64":
            read = lambda n: uc.reg_read((UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                          UC_ARM64_REG_X2, UC_ARM64_REG_X3)[n])
            self._set_ret = (lambda v: uc.reg_write(UC_ARM64_REG_X0, v))
        elif self.arch_name == "arm":
            read = lambda n: uc.reg_read((UC_ARM_REG_R0, UC_ARM_REG_R1,
                                          UC_ARM_REG_R2, UC_ARM_REG_R3)[n])
            self._set_ret = (lambda v: uc.reg_write(UC_ARM_REG_R0, v))
        else:
            from unicorn.x86_const import UC_X86_REG_RAX as RET
            from unicorn.x86_const import UC_X86_REG_RCX as A3
            from unicorn.x86_const import UC_X86_REG_RDI as A0
            from unicorn.x86_const import UC_X86_REG_RDX as A2
            from unicorn.x86_const import UC_X86_REG_RSI as A1
            read = lambda n: uc.reg_read((A0, A1, A2, A3)[n])
            self._set_ret = (lambda v: uc.reg_write(RET, v))
        return read

    def run_jni_oneshot(self, sym="JNI_OnLoad", ctor_timeout_s=120,
                        run_timeout_s=300):
        """Full JNI_OnLoad boot: relocs -> ctors (self-decrypt) -> JNI_OnLoad
        with a fake JavaVM. Returns an orchestration report used by the
        dispatcher and by tests."""
        self.load_elf()
        self.map_regions()
        self.wire_got_shims()
        self.wire_jni_table()
        self.wire_svc_hook()
        self.apply_relative_relocs()

        entry, name = self.find_entry(sym)
        if name != sym:
            raise RuntimeError(f"symbol {sym!r} not exported (got {name!r})")

        vm = self.build_vm_table()
        self.uc.hook_add(UC_HOOK_CODE, self.vm_hook,
                         begin=VM_STUB & ~1, end=VM_STUB + 16)
        self._ensure_dispatch_hook()
        self.capture_register_natives()

        ctors = self.run_ctors(ctor_timeout_s)
        self.jni_log.clear()

        self.uc.reg_write(UC_ARM64_REG_SP if self.arch_name == "arm64" else
                          UC_ARM_REG_SP if self.arch_name == "arm" else
                          UC_X86_REG_RSP,
                          STACK_ADDR + 1024 * 1024 - 0x200)
        if self.arch_name == "arm64":
            self.uc.reg_write(UC_ARM64_REG_X0, vm)
            self.uc.reg_write(UC_ARM64_REG_X1, 0)
            self.uc.reg_write(UC_ARM64_REG_LR, RET_STUB)
            self.uc.reg_write(UC_ARM64_REG_PC, entry)
        elif self.arch_name == "arm":
            self.uc.reg_write(UC_ARM_REG_R0, vm)
            self.uc.reg_write(UC_ARM_REG_R1, 0)
            self.uc.reg_write(UC_ARM_REG_LR, RET_STUB)
            self.uc.reg_write(UC_ARM_REG_PC, entry | 1)
        else:
            self.uc.mem_write(STACK_ADDR + 1024 * 1024 - 0x200,
                              struct.pack("<Q", RET_STUB))
            self.uc.reg_write(UC_X86_REG_RDI, vm)
            self.uc.reg_write(UC_X86_REG_RSI, 0)

        status = "clean"
        try:
            self.uc.emu_start(entry | 1 if self.arch_name == "arm" else entry,
                              RET_STUB,
                              timeout=run_timeout_s * 1_000_000,
                              count=100_000_000)
        except Exception as exc:
            status = str(exc)[:80]

        return {"entry": name, "status": status,
                "ctors": ctors,
                "jni_calls": len(self.jni_log),
                "register_natives": [e for e in self.jni_log
                                     if e[0] == "RegisterNatives"],
                "fault": getattr(self, "fault_info", None)}

    def do_jni(self, name):
        uc = self.uc
        def get_args():
            if self.arch_name == "arm64":
                regs = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                        UC_ARM64_REG_X3]
            elif self.arch_name == "arm":
                regs = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                        UC_ARM_REG_R3]
            else:
                from unicorn.x86_const import UC_X86_REG_RCX as RCX
                regs = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, RCX]
            return [uc.reg_read(r) for r in regs]
        def ret(v):
            if self.arch_name == "arm64":
                uc.reg_write(UC_ARM64_REG_X0, v & 0xFFFFFFFFFFFFFFFF)
            elif self.arch_name == "arm":
                uc.reg_write(UC_ARM_REG_R0, v & 0xFFFFFFFF)
            else:
                uc.reg_write(UC_X86_REG_RAX, v & 0xFFFFFFFFFFFFFFFF)
        a = get_args()
        x1, x2, x3 = a[1], a[2], a[3]

        def jni_arg(n):
            """n-th (0-based) JNI argument; beyond the register set, read the stack."""
            if self.arch_name == "arm64":
                return uc.reg_read(getattr(arm64_const, f"UC_ARM64_REG_X{n}"))
            if self.arch_name == "arm":
                if n < 4:
                    return uc.reg_read(UC_ARM_REG_R0 + n)
                sp = uc.reg_read(UC_ARM_REG_SP)
                return struct.unpack("<I", bytes(uc.mem_read(sp + 4 * (n - 4), 4)))[0]
            regs = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX,
                    UC_X86_REG_R8, UC_X86_REG_R9]
            if n < 6:
                return uc.reg_read(regs[n])
            sp = uc.reg_read(UC_X86_REG_RSP)
            return struct.unpack("<Q", bytes(uc.mem_read(sp + 8 * (n - 4), 8)))[0]

        # ---- object-semantics helpers (mini-JVM) ----
        def obj_str(h_ptr):
            return self.cstr(h_ptr)
        def make_string(s):
            b = s.encode()
            h = self.bump(len(b) + 1)
            uc.mem_write(h, b + b"\x00")
            return self.new_obj("string", h)
        def string_val(obj):
            kind, val = self.objects.get(obj, ("?", None))
            if kind == "string" and isinstance(val, int):
                return self.cstr(val)
            if kind == "bytes" and isinstance(val, bytearray):
                return bytes(val).decode(errors="ignore")
            if kind == "pybytes" and isinstance(val, bytes):
                return val.decode(errors="ignore")
            return None
        def read_obj_bytes(obj):
            kind, val = self.objects.get(obj, ("?", None))
            if kind == "string" and isinstance(val, int):
                return self.cstr(val).encode()
            if kind == "bytes" and isinstance(val, bytearray):
                return bytes(val)
            if kind == "pybytes":
                return val or b""
            return b""
        def new_array(data: bytes):
            h = self.bump(max(len(data), 1))
            uc.mem_write(h, data + b"\x00")
            o = self.new_obj("bytes", bytearray(data))
            self.array_ptrs[o] = h
            return o

        if name == "DefineClass":
            # DefineClass(env, name, loader, const jbyte *buf, jsize len)
            nm = self.cstr(x1)
            try:
                buf, buf_len = jni_arg(3), jni_arg(4)
                data = bytes(uc.mem_read(buf, min(buf_len, 65536))) if buf_len < 10 ** 7 else b""
                self.defined_classes[nm] = data[:min(buf_len, 65536)]
                self.jni_log.append(("DefineClass", nm, "len=%d" % buf_len))
            except Exception:
                self.jni_log.append(("DefineClass", nm))
            ret(self.new_obj("class", nm))
        elif name == "FindClass":
            nm = self.cstr(x1)
            self.jni_log.append(("FindClass", nm))
            ret(self.new_obj("class", nm))
        elif name in ("GetMethodID", "GetStaticMethodID"):
            cls = self.objects.get(x1, ("?", "?"))[1]
            mn, sig = self.cstr(x2), self.cstr(x3)
            mid = self.new_obj("method_id", (cls, mn, sig))
            self.method_names[mid] = mn
            self.method_sigs[mid] = sig
            self.jni_log.append((name, str(cls), mn, sig))
            ret(mid)
        elif name == "GetStaticFieldID" or name == "GetFieldID":
            fld = self.new_obj("field_id", self.cstr(x2))
            self.field_names[fld] = self.cstr(x2)
            ret(fld)
        elif name == "GetStaticObjectField":
            fname = self.field_names.get(x2, "?")
            known = {"MANUFACTURER": "Google", "MODEL": "Pixel 4a",
                     "DEVICE": "sunfish", "PRODUCT": "sunfish",
                     "HARDWARE": "sdn855", "BRAND": "google",
                     "FINGERPRINT": "google/sunfish/sunfish:11/RQ3A.211001.001",
                     "CPU_ABI": "arm64-v8a"}
            support = {"SUPPORTED_ABIS": ["arm64-v8a", "armeabi-v7a", "armeabi"]}
            if fname in known:
                obj = make_string(known[fname])
                self.jni_log.append(("GetStaticObjectField", fname, known[fname]))
                ret(obj)
            elif fname == "SUPPORTED_ABIS":
                objs = [make_string(s) for s in support["SUPPORTED_ABIS"]]
                arr = self.bump(8 * len(objs))
                for i, ob in enumerate(objs):
                    uc.mem_write(arr + 8 * i, struct.pack("<Q", ob))
                container = self.new_obj("objarray", arr)
                self.jni_log.append(("GetStaticObjectField", fname, "array"))
                ret(container)
            else:
                self.jni_log.append(("GetStaticObjectField", fname, "<none>"))
                ret(make_string(""))
        elif name.startswith("Call"):
            mid_name = self.method_names.get(x2, "?")
            mid_sig = self.method_sigs.get(x2, "")
            tgt_kind, tgt_val = self.objects.get(x1, ("?", None))
            self.jni_log.append((name, mid_name))
            # Signature-aware arg mapping. JNI A-variants: X3 -> jvalue[]
            # with ONLY the method args (no receiver). Non-A variants:
            # receiver in x1, then args in x2..x5 registers (up to 3 captured).
            if name.endswith("A"):
                jptr = x3
                params = []
                # count params from sig: strip return type
                body = mid_sig[1:mid_sig.rfind(")")] if ")" in mid_sig else ""
                i = 0
                while i < len(body):
                    c = body[i]
                    if c == "[":
                        i += 1
                        continue
                    if c == "L":
                        i = body.index(";", i) + 1
                        params.append("obj")
                    else:
                        params.append("prim" if c in "ZBCSIJFD" else "?")
                        i += 1
                raw = bytes(uc.mem_read(jptr, 8 * max(len(params), 1))) \
                      if jptr and params else b""
                slots = list(struct.unpack("<%dQ" % len(params), raw)) \
                        if params and len(raw) >= 8 * len(params) else []
                call_args = [x1] + slots
                # For virtual calls the object handle IS in the slot list when
                # signature starts with an obj param of its own class; here the
                # packer passes explicit receivers via Method.invoke, so treat
                # every slot as arg.
                call_args = [x1] + list(slots)
                self._sig_params = params
            else:
                call_args = [x1, x2, x3]
                self._sig_params = []
            try:
                rv = self.invoke_java(mid_name, emu_args=call_args,
                                      helpers=(make_string, new_array,
                                               string_val, read_obj_bytes))
                if rv is None:
                    ret(self.new_obj("callret"))
                elif isinstance(rv, int):
                    ret(rv)
                elif isinstance(rv, bytes):
                    ret(new_array(rv))
                elif isinstance(rv, str):
                    ret(make_string(rv))
                else:
                    ret(self.new_obj("callret"))
            except Exception as exc:
                self.jni_log.append(("CallERR", mid_name, str(exc)[:80]))
                ret(self.new_obj("callret"))
        elif name == "NewStringUTF":
            s = self.cstr(x1)
            self.jni_log.append(("NewStringUTF", s[:48]))
            ret(make_string(s))
        elif name == "GetStringUTFChars" or name == "GetStringChars":
            data = read_obj_bytes(x1)
            h = self.bump(len(data) + 1)
            uc.mem_write(h, data + b"\x00")
            ret(h)
        elif name == "ReleaseStringUTFChars" or name == "ReleaseStringChars":
            ret(0)
        elif name == "GetArrayLength" or name == "GetStringLength":
            kind, val = self.objects.get(x1, ("?", None))
            ln = len(val) if isinstance(val, (bytearray, bytes)) else 0
            ret(ln)
        elif name == "NewByteArray":
            o = self.new_obj("bytes", bytearray(min(x1, 16 * 1024 * 1024)))
            self.array_ptrs[o] = self.bump(max(len(self.objects[o][1]), 1) +
                                           (len(self.objects[o][1]) == 0))
            ret(o)
        elif name == "SetByteArrayRegion":
            # (env, array, jsize start, jsize len, const jbyte *buf)
            start, length, buf = x2, x3, jni_arg(4)
            kind, val = self.objects.get(x1, ("?", None))
            if kind == "bytes" and length <= 4 * 1024 * 1024 and start + length <= len(val):
                try:
                    data = bytes(uc.mem_read(buf, length))
                    _dbg(f"[SBR] start={start} len={length} head={data[:24].hex()}")
                    val[start:start + length] = bytearray(data)
                except Exception:
                    pass
            ret(0)
        elif name == "GetByteArrayRegion":
            # (env, array, jsize start, jsize len, jbyte *buf)
            start, length, buf = x2, min(x3, 4 * 1024 * 1024), jni_arg(4)
            kind, val = self.objects.get(x1, ("?", None))
            data = bytes(val)[start:start + length] if kind == "bytes" else b""
            _dbg(f"[GBR] kind={kind} start={start} len={length} head={data[:24].hex()}")
            try:
                uc.mem_write(buf, data.ljust(length, b"\x00"))
            except Exception:
                pass  # native gets stale bytes; better than crashing the oracle
            ret(0)
        elif name in ("IsSameObject", "DeleteLocalRef", "DeleteGlobalRef",
                      "ExceptionCheck", "ExceptionOccurred"):
            ret(0)
        elif name == "GetVersion":
            ret(0x10006)
        elif name == "PopLocalFrame":
            ret(self.new_obj("frame"))
        elif name in ("EnsureLocalCapacity", "PushLocalFrame"):
            ret(0)
        elif name in ("NewLocalRef", "NewGlobalRef"):
            ret(x1 if x1 in self.objects else self.new_obj("ref"))
        elif name in ("AllocObject", "NewObject"):
            ret(self.new_obj("object"))
        elif name == "GetObjectClass":
            ret(self.new_obj("cls"))
        else:
            self.jni_log.append((name,))
            ret(self.new_obj("gen"))

    def invoke_java(self, method_name, emu_args, helpers):
        """Semantics for the Java methods this packer calls via reflection.
        Returns None (default object), int, bytes or str."""
        make_string, new_array, string_val, read_obj_bytes = helpers
        # ---- mocked asset pipeline (libcater loadDex) ----
        if method_name == "open":
            name = string_val(emu_args[1]) if len(emu_args) > 1 else ""
            if not name:
                name = getattr(self, "_open_asset", "") or ""
            self._open_asset = name
            self.jni_log.append(("AssetManager.open", name))
            data = (getattr(self, "_asset_map", {}) or {}).get(name, b"")
            o = self.new_obj("stream", len(data))
            self._stream_len = len(data)
            self._stream_pos = 0
            return o
        if method_name == "available":
            return getattr(self, "_stream_len", 0) - getattr(self, "_stream_pos", 0)
        if method_name == "read":
            data = (getattr(self, "_asset_map", {}) or {}).get(
                getattr(self, "_open_asset", ""), b"")
            pos = getattr(self, "_stream_pos", 0)
            chunk = data[pos:pos + 65536]
            n = 0
            for a_ in emu_args[1:]:
                kind, val = self.objects.get(a_, ("?", None))
                if kind == "bytes":
                    n = min(len(chunk), len(val))
                    val[:n] = bytearray(chunk[:n])
                    break
            self._stream_pos = pos + (n or 0)
            self.jni_log.append(("stream.read", f"pos={pos} n={n}"))
            return n if n else 0
        # ---- mocked HttpURLConnection flow (geo-gated loaders, e.g. libcater) ----
        if method_name == "getResponseCode":
            return 200
        if method_name in ("getInputStream", "getErrorStream"):
            return self.new_obj("stream")
        if method_name == "readLine":
            # serve canned response lines; return 0 (=NULL) at end-of-stream
            lines = getattr(self, "_http_lines", None) or []
            if lines:
                return lines.pop(0)
            return 0
        if method_name == "toString":
            sb = self._sb.get(emu_args[0])
            return sb if sb is not None else (string_val(emu_args[0]) or "")
        if method_name == "append":
            acc = ""
            for arg in emu_args[1:]:
                s = string_val(arg)
                acc += s or ""
            self._sb[emu_args[0]] = self._sb.get(emu_args[0], "") + acc
            return emu_args[0]
        if method_name in ("substring", "toLowerCase", "trim",
                           "getName", "getNamejava"):
            s = string_val(emu_args[0]) or ""
            if method_name == "toLowerCase":
                s = s.lower()
            elif method_name == "substring":
                try:
                    # emu_args[0]=this, [1]=begin, [2]=end (if present)
                    begin = int(emu_args[1]) if len(emu_args) > 1 else 0
                    if len(emu_args) > 2:
                        end = int(emu_args[2])
                        s = s[begin:end]
                    else:
                        s = s[begin:]
                except Exception:
                    pass
            self.jni_log.append((method_name, "->", s[:40]))
            return s
        if method_name == "getBytes":
            o = emu_args[0]
            s = self._sb.get(o) or string_val(o) or ""
            self.key_log.append(("getBytes", s))
            return s.encode()
        if method_name == "equals":
            a = string_val(emu_args[0]) or ""
            b = getattr(self, "_last_invoke_arg", "")
            return 1 if a == b else 0
        if method_name == "getInstance":     # Cipher / MessageDigest (static)
            # static: emu_args[0]=class, [1]=algorithm string; instance fallback uses [0]
            is_static = self.objects.get(emu_args[0], ("?", None))[0] == "class"
            arg_idx = 1 if is_static and len(emu_args) > 1 else 0
            return self.new_obj("engine", string_val(emu_args[arg_idx]))
        if method_name == "digest":
            import hashlib
            data = b""
            for a_ in emu_args:
                d = read_obj_bytes(a_)
                if d:
                    data = d
                    break
            eng = self.objects.get(emu_args[0], ("engine", "?"))[1]
            self.key_log.append(("digest", f"engine={eng} len={len(data)} "
                                          f"head={data[:32].hex()}"))
            _dbg(f"[DIGEST] {eng} len={len(data)} input_head={data[:48].hex()}")
            h = hashlib.sha1(data) if eng == "SHA-1" else hashlib.sha256(data)
            _dbg(f"[DIGEST-OUT] {h.digest().hex()}")
            self.last_digest = h.digest()
            return h.digest()
        if method_name == "copyOf":  # static Arrays.copyOf
            is_static = self.objects.get(emu_args[0], ("?", None))[0] == "class"
            src_idx = 1 if is_static else 0
            len_idx = 2 if is_static else 1
            src = read_obj_bytes(emu_args[src_idx]) if len(emu_args) > src_idx else b""
            try:
                n = int(emu_args[len_idx]) if len(emu_args) > len_idx else 16
            except Exception:
                n = 16
            out = (src + b"\x00" * n)[:n]
            self.key_log.append(("copyOf", f"src_len={len(src)} -> {len(out)}B "
                                           f"{out.hex()}"))
            _dbg(f"[COPYOF] {out.hex()}")
            return out
        if method_name == "<init>" or method_name == "init":
            # Cipher.init(mode, key, iv) / SecretKeySpec.<init> / IvParameterSpec
            if getattr(self, "last_digest", None):
                hay = bytes(self.uc.mem_read(HEAP_ADDR, min(self.heap_ptr + 4096, 16 * 1024 * 1024)))
                off = hay.find(self.last_digest)
                _dbg(f"[HEAP-SCAN] digest@ {'0x%x' % (HEAP_ADDR + off) if off >= 0 else 'NOT FOUND'} "
                f"context={hay[max(0,off-16):off+80].hex() if off >= 0 else ''}")
            vals = []
            for a_ in emu_args:
                kind, val = self.objects.get(a_, ("?", None))
                if kind == "bytes":
                    vals.append(bytes(val).hex())
                elif kind == "engine":
                    vals.append(str(val))
                else:
                    vals.append(kind)
            self.key_log.append((f"<init:{self._ctor_hint}>", "; ".join(vals)))
            _dbg(f"[CTOR {self._ctor_hint}] {'; '.join(vals)}")
            return None
        return None

    def do_libc(self, name):
        uc = self.uc
        def get_args():
            if self.arch_name == "arm64":
                return [uc.reg_read(r) for r in
                        (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                         UC_ARM64_REG_X3)]
            if self.arch_name == "arm":
                return [uc.reg_read(r) for r in
                        (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                         UC_ARM_REG_R3)]
            fmt = {0: UC_X86_REG_RDI, 1: UC_X86_REG_RSI, 2: UC_X86_REG_RDX,
                   3: UC_X86_REG_RCX}
            return [uc.reg_read(fmt[i]) for i in range(4)]
        def set_ret(v):
            if self.arch_name == "arm64":
                uc.reg_write(UC_ARM64_REG_X0, v)
            elif self.arch_name == "arm":
                uc.reg_write(UC_ARM_REG_R0, v)
            else:
                uc.reg_write(UC_X86_REG_RAX, v)
        x0, x1, x2, x3 = get_args()
        if name == "malloc":
            set_ret(self.bump(x0)); self.libc_calls.append("malloc(%d)" % x0)
        elif name == "calloc":
            s = x1 * x2 or 16
            a = self.bump(s); uc.mem_write(a, bytes(min(s, 65536))); set_ret(a)
        elif name in ("free", "getauxval", "dl_iterate_phdr") or \
             (name or "").startswith("__cxa") or name == "__register_atfork":
            set_ret(0)
        elif name in ("memcpy", "memmove", "__memmove_chk"):
            # Guest-controlled length: a hostile lib could ask for GBs of host memory (audit P7).
            d = bytes(uc.mem_read(x1, min(x2, MAX_GUEST_COPY))); uc.mem_write(x0, d); set_ret(x0)
        elif name == "memset":
            uc.mem_write(x0, bytes([x1 & 0xFF]) * min(x2, MAX_GUEST_COPY)); set_ret(x0)
        elif name == "posix_memalign":
            bb = self.bump(x2); uc.mem_write(x0, struct.pack("<Q", bb)); set_ret(0)
        elif name in ("strlen", "__strlen_chk"):
            k = 0
            while k < 8192:
                try:
                    if uc.mem_read(x0 + k, 1)[0] == 0: break
                except Exception: break
                k += 1
            set_ret(k)
        elif name in ("strcmp", "strncmp"):
            la = min(x2, 4096) if name == "strncmp" else 4096
            sa = bytes(uc.mem_read(x0, la)).split(b"\x00")[0]
            sb = bytes(uc.mem_read(x1, la)).split(b"\x00")[0]
            self.libc_calls.append(f"strcmp({sa[:40]!r}, {sb[:40]!r})")
            set_ret(0 if sa == sb else 1)
        elif name == "__system_property_get":
            key = self.cstr(x0).encode()
            PROPS = {b"ro.product.cpu.abi": b"arm64-v8a",
                     b"ro.product.cpu.abilist": b"arm64-v8a,armeabi-v7a,armeabi",
                     b"ro.build.fingerprint": b"google/sunfish/sunfish:11/RQ3A.211001.001",
                     b"ro.product.manufacturer": b"Google",
                     b"ro.product.model": b"Pixel 4a",
                     b"ro.product.device": b"sunfish",
                     b"ro.hardware": b"sdn855",
                     b"ro.build.version.release": b"11"}
            if key in PROPS:
                uc.mem_write(x1, PROPS[key] + b"\x00")
                set_ret(len(PROPS[key]))
            else:
                set_ret(0)
        elif name == "realloc":
            set_ret(self.bump(x1))
        elif name == "memchr":
            d = bytes(uc.mem_read(x0, min(x2, 1048576)))
            ii = d.find(x1 & 0xFF)
            set_ret(x0 + ii if ii >= 0 else 0)
        elif name in ("fopen", "fopen64"):
            path = self.cstr(x0) if x0 else ""
            self._fake_files = getattr(self, "_fake_files", {})
            if "maps" in path:
                data = b""
                for _ in range(3):
                    data += ("%08x-%08x r-xp 00000000 fd:01 12345   "
                             "/data/app/probe/lib/arm64/libtarget.so\n"
                             % (self.base, self.base + 0x200000)).encode()
                fh = self.bump(64)
                self._fake_files[fh] = {"data": data, "off": 0}
                set_ret(fh)
            elif "status" in path:
                data = (b"Name: probe\nState: S (sleeping)\nTgid: 12345\nPid: 12345\n"
                        b"PPid: 1\nTracerPid: 0\nUid: 10100\t10100\t10100\t10100\n"
                        b"Gid: 10100\t10100\t10100\t10100\nFDSize: 256\n")
                fh = self.bump(64)
                self._fake_files[fh] = {"data": data, "off": 0}
                set_ret(fh)
            elif "cmdline" in path:
                data = b"com.hidenipure.calculat\x00"
                fh = self.bump(64)
                self._fake_files[fh] = {"data": data, "off": 0}
                set_ret(fh)
            elif path.endswith(".so") or "libtarget" in path or ".so" in path or ".apk" in path or "base.apk" in path:
                try:
                    if ".apk" in path:
                        # Never serve another APK (audit P16): only this sample's own file, else fail the open.
                        own_apk = getattr(self, "apk_path", None)
                        if own_apk is None:
                            raise FileNotFoundError("no sample APK available to serve")
                        data = pathlib.Path(own_apk).read_bytes()
                    else:
                        data = pathlib.Path(self.so_path).read_bytes()
                except Exception:
                    data = b""
                fh = self.bump(64)
                self._fake_files[fh] = {"data": data, "off": 0}
                set_ret(fh)
            else:
                set_ret(0)
        elif name == "fgets":
            f = getattr(self, "_fake_files", {}).get(x2)
            if f and x0 and x1 > 1 and f["off"] < len(f["data"]):
                d = f["data"]
                endi = d.find(b"\n", f["off"])
                if endi < 0 or endi - f["off"] > x1 - 1:
                    endi = min(f["off"] + x1 - 1, len(d))
                else:
                    endi += 1
                chunk = d[f["off"]:endi]
                uc.mem_write(x0, chunk + b"\x00")
                f["off"] = endi
                set_ret(x0)
            else:
                set_ret(0)
        elif name == "fread":
            f = getattr(self, "_fake_files", {}).get(x3)
            if f and x0:
                total = x1 * x2
                chunk = f["data"][f["off"]:f["off"] + total]
                uc.mem_write(x0, chunk)
                f["off"] += len(chunk)
                set_ret(len(chunk) // x1 if x1 else len(chunk))
            else:
                set_ret(0)
        elif name == "feof":
            f = getattr(self, "_fake_files", {}).get(x0)
            set_ret(1 if (f and f["off"] >= len(f["data"])) else 0)
        elif name == "fseek":
            f = getattr(self, "_fake_files", {}).get(x0)
            if f:
                # the offset register is unsigned: fseek(-16, SEEK_END) arrives as a huge value
                width = 1 << (32 if self.arch_name == "arm" else 64)
                off = x1 - width if x1 >= width // 2 else x1
                base_off = {0: 0, 1: f["off"], 2: len(f["data"])}.get(x2, 0)
                f["off"] = max(0, min(len(f["data"]), base_off + off))
                set_ret(0)
            else:
                set_ret(0)
        elif name == "ftell":
            f = getattr(self, "_fake_files", {}).get(x0)
            set_ret(f["off"] if f else 0)
        elif name == "getc":
            f = getattr(self, "_fake_files", {}).get(x0)
            if f and f["off"] < len(f["data"]):
                ch = f["data"][f["off"]]; f["off"] += 1
                set_ret(ch)
            else:
                set_ret(-1 & 0xFFFFFFFFFFFFFFFF if self.arch_name == "arm64" else -1 & 0xFFFFFFFF)
        elif name == "fclose":
            getattr(self, "_fake_files", {}).pop(x0, None)
            set_ret(0)
        elif name == "strstr":
            try:
                hay = bytes(uc.mem_read(x0, 65536)).split(b"\x00")[0]
                nee = bytes(uc.mem_read(x1, 4096)).split(b"\x00")[0]
                self.libc_calls.append(f"strstr({hay[:70]!r}, {nee[:40]!r})")
                ii = hay.find(nee)
                set_ret(x0 + ii if ii >= 0 else 0)
            except Exception:
                set_ret(0)
        elif name == "sscanf" or name == "vsscanf":
            try:
                src = bytes(uc.mem_read(x1, 512)).split(b"\x00")[0]
                fmt = self.cstr(x2).encode() if x2 else b""
                nums = re.findall(rb"[0-9a-fA-F]+", src)
                if b"-" in fmt and len(nums) >= 2:
                    uc.mem_write(x3, struct.pack("<I", int(nums[0], 16)))
                    if self.arch_name == "arm64":
                        from unicorn.arm64_const import UC_ARM64_REG_X4
                        p4 = uc.reg_read(UC_ARM64_REG_X4)
                    else:
                        from unicorn.arm_const import UC_ARM_REG_R4
                        p4 = uc.reg_read(UC_ARM_REG_R4)
                    if p4:
                        uc.mem_write(p4, struct.pack("<I", int(nums[1], 16)))
                    set_ret(2)
                else:
                    set_ret(0)
            except Exception:
                set_ret(0)
        elif name == "memcmp":
            try:
                da = bytes(uc.mem_read(x0, x2)); db = bytes(uc.mem_read(x1, x2))
                set_ret(0 if da == db else 1)
            except Exception:
                set_ret(0)
        elif name == "dladdr":
            info = x1
            if info:
                fname = self.bump(128)
                uc.mem_write(fname, b"/data/app/probe/lib/arm64/libtarget.so\x00")
                psz = 8 if self.arch_name == "arm64" else 4
                pk = "<Q" if self.arch_name == "arm64" else "<I"
                uc.mem_write(info, struct.pack(pk, fname))
                uc.mem_write(info + psz, struct.pack(pk, self.base))
                uc.mem_write(info + 2 * psz, struct.pack(pk, fname))
                uc.mem_write(info + 3 * psz, struct.pack(pk, self.base))
            set_ret(1)
        elif name == "inflateInit2_" or name == "inflateInit_":
            # x0 = z_stream*
            self._zstrm = x0
            self._zinfl = None
            set_ret(0)
        elif name == "inflate":
            # z_stream field offsets follow the target pointer size (audit P17); the
            # arm64/x86_64 layout is 64-bit pointers with 8-byte total counters.
            import zlib as _zlib
            strm = x0
            if self.arch_name == "arm":
                psz, off = 4, {"next_in": 0, "avail_in": 4, "next_out": 12, "avail_out": 16, "total_out": 20}
            else:
                psz, off = 8, {"next_in": 0, "avail_in": 8, "next_out": 24, "avail_out": 32, "total_out": 40}
            def rd(o, n):
                return int.from_bytes(bytes(uc.mem_read(strm + o, n)), "little")
            def wr(o, n, v):
                uc.mem_write(strm + o, int(v).to_bytes(n, "little"))
            try:
                next_in = rd(off["next_in"], psz)
                avail_in = rd(off["avail_in"], 4)
                next_out = rd(off["next_out"], psz)
                avail_out = rd(off["avail_out"], 4)
                data = bytes(uc.mem_read(next_in, min(avail_in, 8 * 1024 * 1024)))
                if getattr(self, "_zinfl", None) is None:
                    self._zinfl = _zlib.decompressobj(-15)
                out = self._zinfl.decompress(data, avail_out)
                if out:
                    uc.mem_write(next_out, out)
                # advance the input by what zlib consumed, not by an unchanged avail_in
                consumed = len(data) - len(self._zinfl.unconsumed_tail)
                wr(off["next_in"], psz, next_in + consumed)
                wr(off["avail_in"], 4, avail_in - consumed)
                wr(off["next_out"], psz, next_out + len(out))
                wr(off["avail_out"], 4, avail_out - len(out))
                wr(off["total_out"], psz, rd(off["total_out"], psz) + len(out))
                self.libc_calls.append(f"inflate(in={avail_in} out={len(out)})")
                set_ret(1 if self._zinfl.eof else 0)   # Z_STREAM_END / Z_OK
            except Exception as exc:
                self.libc_calls.append(f"inflate-ERR {exc}")
                set_ret(0)
        elif name == "inflateEnd":
            self._zinfl = None
            set_ret(0)
        elif name in ("__stack_chk_fail", "abort"):
            raise RuntimeError(name)
        else:
            set_ret(0)  # pthread*, syslog family etc.

    def _svc_fake_open(self, path):
        self._fake_files = getattr(self, "_fake_files", {})
        path = path or ""
        if "maps" in path:
            data = b""
            for _ in range(3):
                data += ("%08x-%08x r-xp 00000000 fd:01 12345   "
                         "/data/app/probe/lib/arm64/libtarget.so\n"
                         % (self.base, self.base + 0x200000)).encode()
        elif "status" in path:
            data = (b"Name: probe\nState: S (sleeping)\nTgid: 12345\nPid: 12345\n"
                    b"PPid: 1\nTracerPid: 0\n")
        elif "cmdline" in path:
            data = b"com.hidenipure.calculat\x00"
        elif ".so" in path:
            data = pathlib.Path(self.so_path).read_bytes()
        else:
            return 0
        fh = self.bump(64)
        self._fake_files[fh] = {"data": data, "off": 0}
        return fh

    def _svc_dispatch(self, uc_):
        if self.arch_name == "arm64":
            from unicorn.arm64_const import (
                UC_ARM64_REG_X0,
                UC_ARM64_REG_X1,
                UC_ARM64_REG_X8,
            )
            nr = uc_.reg_read(UC_ARM64_REG_X8)
            a1 = uc_.reg_read(UC_ARM64_REG_X1)
            if nr == 222:
                uc_.reg_write(UC_ARM64_REG_X0, self.bump((a1 + 4095) & ~4095 or 4096))
            else:
                uc_.reg_write(UC_ARM64_REG_X0, 0)
            return
        from unicorn.arm_const import (
            UC_ARM_REG_R0,
            UC_ARM_REG_R1,
            UC_ARM_REG_R2,
            UC_ARM_REG_R3,
            UC_ARM_REG_R4,
            UC_ARM_REG_R5,
        )
        nr = uc_.reg_read(UC_ARM_REG_R7)
        a0 = uc_.reg_read(UC_ARM_REG_R0)
        a1 = uc_.reg_read(UC_ARM_REG_R1)
        a2 = uc_.reg_read(UC_ARM_REG_R2)
        a3 = uc_.reg_read(UC_ARM_REG_R3)
        a4 = uc_.reg_read(UC_ARM_REG_R4)
        a5 = uc_.reg_read(UC_ARM_REG_R5)
        if nr == 192:  # mmap2
            size = (a1 + 4095) & ~4095 or 4096
            self.libc_calls.append(f"mmap2(req={hex(a0)} size={hex(size)} prot={a2} flags={hex(a3)} fd={a4})")
            if a0 and a0 != 0xFFFFFFFF:
                addr = a0 & ~4095  # honor fixed-address requests
                try:
                    uc_.mem_map(addr, size)
                except Exception as e:
                    self.libc_calls.append(f"mmap2 map fail {e}")
            else:
                addr = (self.bump(size + 8192) + 4095) & ~4095
            if a4 not in (0, 0xFFFFFFFF):  # file-backed: fd = fake-file handle
                f = getattr(self, "_fake_files", {}).get(a4)
                if f:
                    off = min(a5 << 12, len(f["data"]))
                    uc_.mem_write(addr, f["data"][off:off + size])
            uc_.reg_write(UC_ARM_REG_R0, addr)
        elif nr == 322 or nr == 5:  # openat / open
            path = self.cstr(a1 if nr == 322 else a0)
            uc_.reg_write(UC_ARM_REG_R0, self._svc_fake_open(path))
        elif nr == 3:  # read
            f = getattr(self, "_fake_files", {}).get(a0)
            if f and a1:
                chunk = f["data"][f["off"]:f["off"] + a2]
                uc_.mem_write(a1, chunk)
                f["off"] += len(chunk)
                uc_.reg_write(UC_ARM_REG_R0, len(chunk))
            else:
                uc_.reg_write(UC_ARM_REG_R0, 0)
        elif nr == 6:  # close
            getattr(self, "_fake_files", {}).pop(a0, None)
            uc_.reg_write(UC_ARM_REG_R0, 0)
        elif nr in (91, 26):  # munmap, ptrace
            uc_.reg_write(UC_ARM_REG_R0, 0)
        elif nr in (224, 20):  # gettid/getpid
            uc_.reg_write(UC_ARM_REG_R0, 12345)
        elif nr == 640 or nr == 126:  # prctl / sigreturn etc.
            uc_.reg_write(UC_ARM_REG_R0, 0)
        else:
            uc_.reg_write(UC_ARM_REG_R0, 0)

    def wire_svc_hook(self):
        """Raw svc #0 syscalls (arm32: nr in r7; arm64: nr in x8)."""
        uc = self.uc
        from unicorn.arm64_const import UC_ARM64_REG_X0 as X0
        from unicorn.arm64_const import UC_ARM64_REG_X1 as X1
        from unicorn.arm64_const import UC_ARM64_REG_X8 as X8
        from unicorn.arm_const import UC_ARM_REG_R0 as R0
        from unicorn.arm_const import UC_ARM_REG_R1

        def svc_hook(uc_, intno, ud):
            try:
                self._svc_dispatch(uc_)
            except Exception as exc:
                print("[SVC-ERR]", exc)
                uc_.reg_write(R0 if self.arch_name != "arm64" else X0, 0)

        def _unused():
            pass

        def svc_hook_orig(uc_, intno, ud):
            if intno != 2:
                return
            if self.arch_name == "arm64":
                nr = uc_.reg_read(X8)
                a1 = uc_.reg_read(X1)
                if nr == 222:  # mmap
                    uc_.reg_write(X0, self.bump((a1 + 4095) & ~4095 or 4096))
                elif nr == 215:  # munmap
                    uc_.reg_write(X0, 0)
                elif nr == 117:  # ptrace
                    uc_.reg_write(X0, 0)
                else:
                    uc_.reg_write(X0, 0)
            else:
                nr = uc_.reg_read(UC_ARM_REG_R7)
                a1 = uc_.reg_read(UC_ARM_REG_R1)
                if nr == 192:  # mmap2
                    uc_.reg_write(R0, self.bump((a1 + 4095) & ~4095 or 4096))
                elif nr == 91:  # munmap
                    uc_.reg_write(R0, 0)
                elif nr == 26:  # ptrace
                    uc_.reg_write(R0, 0)
                elif nr == 224 or nr == 20:  # gettid/getpid
                    uc_.reg_write(R0, 12345)
                else:
                    uc_.reg_write(R0, 0)

        uc.hook_add(UC_HOOK_INTR, svc_hook)

    def dispatch_hook(self, uc, address, size, ud):
        if self.arch_name == "arm":
            address &= ~1  # normalize Thumb bit for slot lookup
        self.last_pcs.append(address)
        if len(self.last_pcs) > 80:
            self.last_pcs.pop(0)
        jni_slot_base = SHIM_PAGE + 0x30000
        if jni_slot_base <= address < jni_slot_base + len(JNI_TABLE) * 16:
            idx = (address - jni_slot_base) // 16
            self.do_jni(JNI_TABLE[idx])
            return
        if SHIM_PAGE <= address < SHIM_PAGE + len(LIBC_NAMES) * 16:
            idx = (address - SHIM_PAGE) // 16
            self.libc_calls.append(LIBC_NAMES[idx])
            self.do_libc(LIBC_NAMES[idx])

    def find_entry(self, sym_name=None):
        candidates = []
        try:
            for s in self.binary.exported_functions:
                candidates.append((s.name, s.address))
        except Exception:
            pass
        try:
            for s in self.binary.dynamic_symbols:
                candidates.append((s.name, s.value))
        except Exception:
            pass
        if sym_name:
            for n, a in candidates:
                if n == sym_name:
                    return self.base + a, n
        jni = [(n, a) for n, a in candidates if n.startswith("Java_")]
        if not jni:
            # JNI_OnLoad-only packers (Ijiami, Bangcle, ...) never export
            # Java_*. Prefer JNI_OnLoad as the bootstrap entry.
            oneshot = [(n, a) for n, a in candidates if n == "JNI_OnLoad"]
            if oneshot:
                return self.base + oneshot[0][1], oneshot[0][0]
            raise RuntimeError("no Java_* export or JNI_OnLoad found")
        if len(jni) == 1:
            return self.base + jni[0][1], jni[0][0]
        # prefer shortest name; ties -> first sorted
        jni.sort(key=lambda x: (len(x[0]), x[0]))
        return self.base + jni[0][1], jni[0][0]

    def _ensure_dispatch_hook(self):
        """Register the dispatch hook once. Adding it per run() made every shim run N+1 times (audit P3)."""
        if not getattr(self, "_dispatch_hooked", False):
            self.uc.hook_add(UC_HOOK_CODE, self.dispatch_hook)
            self._dispatch_hooked = True

    def run(self, entry_addr, timeout_s=180):
        uc = self.uc
        self._ensure_dispatch_hook()
        if self.arch_name == "arm64":
            uc.reg_write(UC_ARM64_REG_SP, STACK_ADDR + 1024 * 1024 - 0x200)
            uc.reg_write(UC_ARM64_REG_X0, FAKE_JENV)
            uc.reg_write(UC_ARM64_REG_X1, 0x1234)
            uc.reg_write(UC_ARM64_REG_LR, RET_STUB)
            uc.reg_write(UC_ARM64_REG_PC, entry_addr)
        elif self.arch_name == "arm":
            sp = STACK_ADDR + 1024 * 1024 - 0x200
            uc.reg_write(UC_ARM_REG_SP, sp)
            uc.reg_write(UC_ARM_REG_R0, FAKE_JENV)
            uc.reg_write(UC_ARM_REG_R1, 0x1234)
            uc.reg_write(UC_ARM_REG_LR, RET_STUB)
            # ALWAYS start in Thumb (Android arm .so text is Thumb-2);
            # PC with bit0=1 makes Unicorn switch to Thumb state.
            uc.reg_write(UC_ARM_REG_PC, entry_addr | 1)
        else:
            sp = STACK_ADDR + 1024 * 1024 - 0x200
            sp -= 8
            uc.mem_write(sp, struct.pack("<Q", RET_STUB))
            uc.reg_write(UC_X86_REG_RSP, sp)
            uc.reg_write(UC_X86_REG_RDI, FAKE_JENV)
            uc.reg_write(UC_X86_REG_RSI, 0x1234)
            uc.reg_write(UC_X86_REG_RDX, 0)
            uc.reg_write(UC_X86_REG_RIP, entry_addr)
        status = "clean"
        start = entry_addr | 1 if self.arch_name == "arm" else entry_addr
        try:
            uc.emu_start(start, RET_STUB,
                         timeout=timeout_s * 1000000, count=100_000_000)
        except Exception as e:
            status = str(e)[:60]
            try:
                pc = uc.reg_read(UC_ARM_REG_PC if self.arch_name == "arm" else
                                 UC_ARM64_REG_PC if self.arch_name == "arm64" else
                                 UC_X86_REG_RIP)
                self.fault_info = {"pc": hex(pc), "status": status,
                                   "last_pcs": [hex(p) for p in self.last_pcs[-12:]]}
                _dbg(f"[FAULT] pc={hex(pc)} {status}")
            except Exception:
                self.fault_info = {"status": status}
        return status

    # -------- post-run artifact recovery --------

    def sweep_blobs(self):
        """Read .data/.bss after run, find base64 blobs that decode to DEX.
        Also sweeps bump-heap byte arrays (NewByteArray/SetByteArrayRegion
        path used by Ijiami-family DEX minting)."""
        results = []
        data_sections = [s for s in self.binary.sections
                         if s.name in (".data", ".bss", ".data.rel.ro")]
        for sec in data_sections:
            lo = self.base + sec.virtual_address
            size = sec.size
            if size < 64:
                continue
            try:
                mem = bytes(self.uc.mem_read(lo, min(size, SWEEP_MAX_SECTION)))
            except Exception:   # section headers are untrusted; the range may be unmapped (audit P8)
                continue
            consumed = 0
            for match in re.finditer(rb"ZGV4", mem):
                idx = match.start()
                if idx < consumed:   # already inside a decoded blob: no quadratic rescans (audit P8)
                    continue
                b64chars = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r")
                end = idx; gap = None
                for i in range(idx, len(mem)):
                    c = mem[i]
                    if c in b64chars:
                        end = i + 1; gap = None
                    else:
                        if gap is None:
                            gap = i
                        if i - gap >= 8:
                            break
                consumed = end
                blob = mem[idx:end]
                cleaned = re.sub(rb"[^A-Za-z0-9+/=]", b"", blob.replace(b"\n", b"").replace(b"\r", b""))
                pad = cleaned + b"A" * (-len(cleaned) % 4)
                try:
                    dec = base64.b64decode(pad)
                except Exception:
                    continue
                if dec[:4] == b"dex\n":
                    fsz = struct.unpack("<I", dec[32:36])[0] if len(dec) >= 36 else 0
                    if 0 < fsz <= len(dec):
                        dec = dec[:fsz]
                    results.append({"kind": "b64_dex", "section": sec.name,
                                    "va": hex(sec.virtual_address + idx),
                                    "size": len(dec), "sha256": sha256(dec),
                                    "data": dec})
                else:
                    results.append({"kind": "b64_other", "section": sec.name,
                                    "va": hex(sec.virtual_address + idx),
                                    "size": len(dec)})
            # also look for RAW dex magic (non-base64 embedded payload)
            for match in re.finditer(rb"dex\n0\d\d\x00", mem):
                idx = match.start()
                fsz_off = idx + 32
                if fsz_off + 4 > len(mem):
                    continue
                fsz = struct.unpack("<I", mem[fsz_off:fsz_off + 4])[0]
                if 0 < fsz <= size - idx and fsz > 112:
                    data = mem[idx:idx + fsz]
                    results.append({"kind": "raw_dex", "section": sec.name,
                                    "va": hex(sec.virtual_address + idx),
                                    "size": len(data), "sha256": sha256(data),
                                    "data": data})
        # bump-heap sweep: byte arrays written via SetByteArrayRegion land in
        # the tail of HEAP_ADDR..HEAP_ADDR+heap_ptr even though the JNI mock
        # also mirrors them into self.objects.
        if self.heap_ptr > 0:
            region = min(self.heap_ptr, 64 * 1024 * 1024)
            try:
                mem = bytes(self.uc.mem_read(HEAP_ADDR, region))
            except Exception:
                mem = b""
            for match in re.finditer(rb"dex\n0\d\d\x00", mem):
                idx = match.start()
                fsz_off = idx + 32
                if fsz_off + 4 > len(mem):
                    continue
                fsz = struct.unpack("<I", mem[fsz_off:fsz_off + 4])[0]
                if 0 < fsz <= len(mem) - idx and fsz > 112:
                    data = mem[idx:idx + fsz]
                    results.append({"kind": "heap_dex", "section": "heap",
                                    "va": hex(HEAP_ADDR + idx),
                                    "size": len(data), "sha256": sha256(data),
                                    "data": data})
            # byte-array mirrors in self.objects (NewByteArray path)
            for obj, (kind, val) in list(self.objects.items()):
                if kind == "bytes" and isinstance(val, bytearray) and val:
                    if val[:4] == b"dex\n" or val[:2] == b"PK":
                        data = bytes(val)
                        fsz = struct.unpack("<I", data[32:36])[0] if len(data) >= 36 and data[:4] == b"dex\n" else len(data)
                        results.append({"kind": "obj_dex" if data[:4] == b"dex\n" else "obj_zip",
                                        "section": "objects",
                                        "va": hex(obj),
                                        "size": len(data), "sha256": sha256(data),
                                        "data": data})
        return results


def extract_so_from_apk(apk_path: pathlib.Path, out_dir: pathlib.Path) -> list:
    out_dir.mkdir(parents=True, exist_ok=True)
    sos = []
    with zipfile.ZipFile(apk_path) as zf:
        for info in zf.infolist():
            if not info.filename.endswith(".so"):
                continue
            # packer libs can live outside lib/ (Ijiami: assets/ijm_lib/, etc.)
            parts = pathlib.Path(info.filename).parts
            abi = next((p for p in parts if p in
                        ("arm64-v8a", "armeabi-v7a", "armeabi",
                         "x86", "x86_64", "mips", "mips64")), "unknown")
            if info.file_size > MAX_LIB_BYTES:
                continue
            # the member path hash keeps two same-named libs from overwriting each other (audit P22)
            tag = hashlib.sha1(info.filename.encode("utf-8")).hexdigest()[:8]
            target = out_dir / ("%s_%s_%s" % (abi, tag, pathlib.Path(info.filename).name))
            target.write_bytes(zf.read(info.filename))
            sos.append(target)
    return sos


def emulate_apk_lib(apk_path: pathlib.Path, workdir: pathlib.Path,
                    prefer_arch: str = None, entry_sym: str = None) -> dict:
    workdir.mkdir(parents=True, exist_ok=True)
    libs = extract_so_from_apk(apk_path, workdir / "libs")
    report = {"apk_path": str(apk_path),
              "apk_sha256": sha256(apk_path.read_bytes()),
              "libs_tried": [], "recovered": [], "status": []}
    order = libs
    if prefer_arch:
        pref = [l for l in libs if l.name.startswith(prefer_arch)]
        rest = [l for l in libs if not l.name.startswith(prefer_arch)]
        order = pref + rest
    best_recovery = None
    for lib in order:
        try:
            emu = Emulator(lib)
            emu.load_elf()
            emu.map_regions()
            emu.wire_got_shims()
            emu.wire_jni_table()
            entry, entry_name = emu.find_entry(entry_sym)
            if entry_name == "JNI_OnLoad":   # no Java_* export: needs the oneshot boot (audit P1)
                raise RuntimeError("JNI_OnLoad-only library")
        except Exception as exc:
            # JNI_OnLoad-only packer: try the oneshot boot path.
            try:
                emu = Emulator(lib)
                meta = emu.run_jni_oneshot()
                blobs = emu.sweep_blobs()
                dexes = [b for b in blobs if b.get("kind") in ("b64_dex", "raw_dex", "heap_dex", "obj_dex")]
                if dexes:
                    rec = {"lib": lib.name, "entry": meta.get("entry"),
                           "arch": emu.arch_name, "status": meta.get("status"),
                           "jni_calls": meta.get("jni_calls")}
                    report["libs_tried"].append(rec)
                    report["status"].append(meta.get("status"))
                    if best_recovery is None:
                        best_recovery = (lib, dexes[0])
                    break
                report["libs_tried"].append({"lib": lib.name,
                                             "oneshot": meta.get("status"),
                                             "blobs": len(blobs)})
                continue
            except Exception as exc2:
                report["libs_tried"].append({"lib": lib.name,
                                             "error": f"{str(exc)[:60]} / {str(exc2)[:60]}"})
                continue
        status = emu.run(entry)
        blobs = emu.sweep_blobs()
        entry_rec = {"lib": lib.name, "entry": entry_name,
                     "entry_va": hex(entry), "arch": emu.arch_name,
                     "status": status, "heap_used": emu.heap_ptr,
                     "jni_calls": len(emu.jni_log)}
        report["libs_tried"].append(entry_rec)
        report["status"].append(status)
        dexes = [b for b in blobs if b.get("kind") in ("b64_dex", "raw_dex")]
        if dexes and best_recovery is None:
            best_recovery = (lib, dexes[0])
        if dexes:
            break   # first success wins
    if best_recovery:
        lib, blob = best_recovery
        sample_id = report["apk_sha256"][:16]
        out = workdir / ("%s_recovered.dex" % sample_id)
        out.write_bytes(blob.pop("data"))
        report["recovered"] = [{"file": str(out), "size": out.stat().st_size,
                                "via_lib": lib.name,
                                "blob_kind": blob["kind"],
                                "blob_section": blob["section"]}]
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--apk", help="APK to unpack generically")
    parser.add_argument("--so", help="single .so file (toy/manual path)")
    parser.add_argument("--sym", help="entry symbol override")
    parser.add_argument("--prefer-arch", default="arm64",
                       help="arm64|armeabi-v7a|x86 priority (default arm64)")
    parser.add_argument("--workdir", default="analysis/emulate")
    parser.add_argument("--out", help="explicit JSON report path")
    args = parser.parse_args(argv)

    if args.apk:
        apk_path = pathlib.Path(args.apk)
        report = emulate_apk_lib(apk_path, pathlib.Path(args.workdir),
                                 prefer_arch=args.prefer_arch,
                                 entry_sym=args.sym)
        rendered = json.dumps(report, indent=2, default=str)
        out = pathlib.Path(args.out) if args.out else (
            pathlib.Path(args.workdir) /
            ("%s_emulate_report.json" % report["apk_sha256"][:16]))
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(rendered)
        print(rendered)
        print("\nreport -> %s" % out, file=sys.stderr)
        return 0

    if args.so:
        so_path = pathlib.Path(args.so)
        emu = Emulator(so_path)
        try:
            emu.load_elf(); emu.map_regions(); emu.wire_got_shims(); emu.wire_jni_table()
            entry, name = emu.find_entry(args.sym)
            if name == "JNI_OnLoad":   # JNI_OnLoad-only: oneshot boot, not a direct run (audit P1)
                raise RuntimeError("JNI_OnLoad-only library")
            status = emu.run(entry)
        except Exception:
            # JNI_OnLoad path (Ijiami/Bangcle style); fresh Uc, the failed one has mapped regions (audit P20)
            emu = Emulator(so_path)
            meta = emu.run_jni_oneshot()
            name, status = meta.get("entry"), meta.get("status")
            blobs = emu.sweep_blobs()
            print(json.dumps({"so": str(so_path), "entry": name, "status": status,
                              "oneshot": True,
                              "registers": meta.get("register_natives"),
                              "blobs": [{k: v for k, v in b.items() if k != "data"}
                                        for b in blobs]}, indent=2))
            for b in blobs:
                if b.get("data") and b.get("kind") in ("b64_dex", "raw_dex", "heap_dex", "obj_dex"):
                    p = pathlib.Path(args.workdir) / ("blob_%s.dex" % b["sha256"][:12])
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_bytes(b["data"])
                    print("saved %s" % p)
            return 0
        blobs = emu.sweep_blobs()
        print(json.dumps({"so": str(so_path), "entry": name, "status": status,
                          "blobs": [{k: v for k, v in b.items() if k != "data"}
                                    for b in blobs]}, indent=2))
        for b in blobs:
            if b.get("data"):
                p = pathlib.Path(args.workdir) / ("blob_%s.dex" % b["sha256"][:12])
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(b.pop("data"))
                print("saved %s" % p)
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
