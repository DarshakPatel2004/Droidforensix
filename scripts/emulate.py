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
import csv
import hashlib
import json
import os
import pathlib
import re
import struct
import sys
import tempfile
import zipfile

import lief


def _dbg(msg):
    if os.environ.get("JNI_DEBUG"):
        print(msg, flush=True)


from unicorn import (Uc, UC_ARCH_X86, UC_ARCH_ARM, UC_ARCH_ARM64,
                     UC_MODE_32, UC_MODE_64, UC_MODE_ARM, UC_MODE_THUMB,
                     UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE)
from unicorn.x86_const import (UC_X86_REG_RSP, UC_X86_REG_RAX, UC_X86_REG_RDI,
                               UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RIP)
from unicorn.arm_const import (UC_ARM_REG_SP, UC_ARM_REG_R0, UC_ARM_REG_R1,
                               UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_PC,
                               UC_ARM_REG_LR)
from unicorn.arm64_const import (UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                 UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                                 UC_ARM64_REG_PC, UC_ARM64_REG_LR)

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

LIBC_NAMES = ["__cxa_finalize","__cxa_atexit","__register_atfork","__stack_chk_fail",
    "pthread_mutex_lock","pthread_mutex_unlock","malloc","free","posix_memalign",
    "memset","vfprintf","fputc","vasprintf","android_set_abort_message","openlog",
    "syslog","closelog","abort","strlen","realloc","memmove","__memmove_chk",
    "__strlen_chk","memchr","__vsnprintf_chk","memcpy","strcmp","pthread_getspecific",
    "pthread_once","pthread_setspecific","pthread_key_delete","pthread_key_create",
    "getauxval","__system_property_get","strncmp","fprintf","fflush",
    "pthread_rwlock_wrlock","pthread_rwlock_unlock","dl_iterate_phdr",
    "pthread_rwlock_rdlock","fwrite"]

RET_ARM = bytes.fromhex("c0035fd6")
RET_THUMB = bytes.fromhex("7047")
RET_X86 = b"\xc3"

BASE_X64 = 0x400000
BASE_ARM = 0x100000
STACK_ADDR = 0x0FFF0000
HEAP_ADDR = 0x0A000000
FAKE_JENV = 0x0B000000
JENV_TABLE = 0x0B100000
RET_STUB = 0x0C000000
SHIM_PAGE = 0x0D000000

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

    def map_regions(self):
        uc = self.uc
        uc.mem_map(STACK_ADDR, 1024 * 1024)
        uc.mem_map(HEAP_ADDR, 16 * 1024 * 1024)
        uc.mem_map(FAKE_JENV, 0x1000)
        uc.mem_map(JENV_TABLE, 0x20000)
        uc.mem_map(RET_STUB, 0x1000)
        uc.mem_map(0x0, 0x100000)   # TLS page for arm64 tpidr_el0-style reads
        uc.mem_write(0x28, struct.pack("<Q", HEAP_ADDR))
        uc.mem_map(SHIM_PAGE, 0x40000)
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
                ptr = struct.pack("<Q" if self.arch_name != "arm" else "<I", slot)
                self.uc.mem_write(self.base + g, ptr)
            if matches:
                setattr(self, "_shim_%s" % name, slot)
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
            uc.mem_write(slot, struct.pack(fmt, h))
            setattr(self, "_jni_%s" % name, h)
        uc.mem_write(FAKE_JENV, struct.pack(fmt, JENV_TABLE))
        self._jni_slots = {SHIM_PAGE + 0x30000 + idx * 16: n
                           for idx, n in enumerate(JNI_TABLE)}

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
                from unicorn.x86_const import (UC_X86_REG_RCX as RCX)
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
        env, x1, x2, x3 = a[0], a[1], a[2], a[3]

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
            nm = self.cstr(x1)
            try:
                buf_len = x2
                data = bytes(uc.mem_read(x2, min(buf_len, 4096))) if buf_len < 10 ** 7 else b""
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
                nslots = 4
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
                call_args = [x1] + [s for s, p in zip(slots, params)] if False else \
                            ([x1] + slots if False else ([x1] + slots))
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
            kind, val = self.objects.get(x1, ("?", None))
            if kind == "bytes":
                data = bytes(uc.mem_read(x2, x3))
                _dbg(f"[SBR] len={x3} head={data[:24].hex()}")
                val[:x3] = bytearray(data)
            ret(0)
        elif name == "GetByteArrayRegion":
            kind, val = self.objects.get(x1, ("?", None))
            data = bytes(val)[:x3] if kind == "bytes" else b"\x00" * x3
            _dbg(f"[GBR] kind={kind} len={x3} head={data[:24].hex()}")
            uc.mem_write(x2, data.ljust(x3, b"\x00") if len(data) < x3 else data[:x3])
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
        if method_name == "getInstance":     # Cipher / MessageDigest
            return self.new_obj("engine", string_val(emu_args[0]))
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
        if method_name == "copyOf":
            src = read_obj_bytes(emu_args[0])
            n = emu_args[1] if len(emu_args) > 2 else 16
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
        is64 = self.arch_name in ("arm64", "x86_64")
        def get_args():
            if self.arch_name == "arm64":
                return [uc.reg_read(r) for r in
                        (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2)]
            if self.arch_name == "arm":
                return [uc.reg_read(r) for r in
                        (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)]
            fmt = {0: UC_X86_REG_RDI, 1: UC_X86_REG_RSI, 2: UC_X86_REG_RDX}
            return [uc.reg_read(fmt[i]) for i in range(3)]
        def set_ret(v):
            if self.arch_name == "arm64":
                uc.reg_write(UC_ARM64_REG_X0, v)
            elif self.arch_name == "arm":
                uc.reg_write(UC_ARM_REG_R0, v)
            else:
                uc.reg_write(UC_X86_REG_RAX, v)
        x0, x1, x2 = get_args()
        if name == "malloc":
            set_ret(self.bump(x0)); self.libc_calls.append("malloc(%d)" % x0)
        elif name == "calloc":
            s = x1 * x2 or 16
            a = self.bump(s); uc.mem_write(a, bytes(min(s, 65536))); set_ret(a)
        elif name in ("free", "getauxval", "dl_iterate_phdr") or \
             (name or "").startswith("__cxa") or name == "__register_atfork":
            set_ret(0)
        elif name in ("memcpy", "memmove", "__memmove_chk"):
            d = bytes(uc.mem_read(x1, x2)); uc.mem_write(x0, d); set_ret(x0)
        elif name == "memset":
            uc.mem_write(x0, bytes([x1 & 0xFF]) * x2); set_ret(x0)
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
        elif name in ("__stack_chk_fail", "abort"):
            raise RuntimeError(name)
        else:
            set_ret(0)  # pthread*, syslog family etc.

    def dispatch_hook(self, uc, address, size, ud):
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
            raise RuntimeError("no Java_* export found")
        if len(jni) == 1:
            return self.base + jni[0][1], jni[0][0]
        # prefer shortest name; ties -> first sorted
        jni.sort(key=lambda x: (len(x[0]), x[0]))
        return self.base + jni[0][1], jni[0][0]

    def run(self, entry_addr, timeout_s=180):
        uc = self.uc
        uc.hook_add(UC_HOOK_CODE, self.dispatch_hook)
        ret_target = RET_STUB
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
            addr = entry_addr
            if addr & 1:
                addr &= ~1  # thumb handled via emu_start `until` using even address
            else:
                addr |= 1  # force thumb when loading from stripped symbol address? (conservative)
            uc.reg_write(UC_ARM_REG_PC, addr)
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
        try:
            uc.emu_start(entry_addr, RET_STUB,
                         timeout=timeout_s * 1000000, count=100_000_000)
        except Exception as e:
            status = str(e)[:60]
        return status

    # -------- post-run artifact recovery --------

    def sweep_blobs(self):
        """Read .data/.bss after run, find base64 blobs that decode to DEX."""
        results = []
        data_sections = [s for s in self.binary.sections
                         if s.name in (".data", ".bss", ".data.rel.ro")]
        for sec in data_sections:
            lo = self.base + sec.virtual_address
            size = sec.size
            if size < 64:
                continue
            mem = bytes(self.uc.mem_read(lo, size))
            for match in re.finditer(rb"ZGV4", mem):
                idx = match.start()
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
        return results


def extract_so_from_apk(apk_path: pathlib.Path, out_dir: pathlib.Path) -> list:
    out_dir.mkdir(parents=True, exist_ok=True)
    sos = []
    with zipfile.ZipFile(apk_path) as zf:
        for info in zf.infolist():
            if info.filename.endswith(".so") and \
               (info.filename.startswith("lib/") or "/lib/" in info.filename):
                abi = pathlib.Path(info.filename).parent.name
                target = out_dir / ("%s_%s" % (abi, pathlib.Path(info.filename).name))
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
        except Exception as exc:
            report["libs_tried"].append({"lib": lib.name, "error": str(exc)[:100]})
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
    parser.add_argument("--test-toy", action="store_true")
    parser.add_argument("--workdir", default="analysis/emulate")
    parser.add_argument("--out", help="explicit JSON report path")
    args = parser.parse_args(argv)

    if args.test_toy:
        from scripts_legacy import test_toy_x64  # noqa
        print("legacy toy test moved; use M2-era script or rerun git history")
        return 2

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
        emu.load_elf(); emu.map_regions(); emu.wire_got_shims(); emu.wire_jni_table()
        entry, name = emu.find_entry(args.sym)
        status = emu.run(entry)
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
