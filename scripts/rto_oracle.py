#!/usr/bin/env python3
"""Final oracle: run RTO's arm64 libstrangulation.so SUO4 under Unicorn with full
libc + JNIEnv shims, then read out the decrypted base64 -> dex from .data."""
import lief, base64, pathlib, re, struct, json
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE
from unicorn.arm64_const import *

JNI_ALL = ["reserved0","reserved1","reserved2","reserved3","GetVersion","DefineClass","FindClass",
"FromReflectedMethod","FromReflectedField","ToReflectedMethod","GetSuperclass","IsAssignableFrom",
"ToReflectedField","Throw","ThrowNew","ExceptionOccurred","ExceptionDescribe","ExceptionClear",
"FatalError","PushLocalFrame","PopLocalFrame","NewGlobalRef","DeleteGlobalRef","DeleteLocalRef",
"IsSameObject","NewLocalRef","EnsureLocalCapacity","AllocObject","NewObject","NewObjectV","NewObjectA",
"GetObjectClass","IsInstanceOf","GetMethodID","CallObjectMethod","CallObjectMethodV","CallObjectMethodA",
"CallBooleanMethod","CallBooleanMethodV","CallBooleanMethodA","CallByteMethod","CallByteMethodV","CallByteMethodA",
"CallCharMethod","CallCharMethodV","CallCharMethodA","CallShortMethod","CallShortMethodV","CallShortMethodA",
"CallIntMethod","CallIntMethodV","CallIntMethodA","CallLongMethod","CallLongMethodV","CallLongMethodA",
"CallFloatMethod","CallFloatMethodV","CallFloatMethodA","CallDoubleMethod","CallDoubleMethodV","CallDoubleMethodA",
"CallVoidMethod","CallVoidMethodV","CallVoidMethodA"]

LIBC_NAMES=["__cxa_finalize","__cxa_atexit","__register_atfork","__stack_chk_fail",
    "pthread_mutex_lock","pthread_mutex_unlock","malloc","free","posix_memalign",
    "memset","vfprintf","fputc","vasprintf","android_set_abort_message","openlog",
    "syslog","closelog","abort","strlen","realloc","memmove","__memmove_chk",
    "__strlen_chk","memchr","__vsnprintf_chk","memcpy","strcmp","pthread_getspecific",
    "pthread_once","pthread_setspecific","pthread_key_delete","pthread_key_create",
    "getauxval","__system_property_get","strncmp","fprintf","fflush",
    "pthread_rwlock_wrlock","pthread_rwlock_unlock","dl_iterate_phdr",
    "pthread_rwlock_rdlock","fwrite"]

BASE=0x100000; HEAP=0x0a000000; STACK=0x0fff0000
FAKE_JENV=0x0b000000; JENV_TABLE=0x0b100000; RET_STUB=0x0c000000

so_path=pathlib.Path("/tmp/arm64.so")
if not so_path.exists():
    import zipfile
    zipfile.ZipFile("RTO.apk").extract("lib/arm64-v8a/libstrangulation.so", "/tmp/x")
    pathlib.Path("/tmp/arm64.so").write_bytes(
        open("/tmp/x/lib/arm64-v8a/libstrangulation.so","rb").read())
b=lief.parse(str(so_path))

uc=Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
for seg in b.segments:
    if "LOAD" not in str(seg.type): continue
    vaddr=BASE+seg.virtual_address; aligned=vaddr & ~0xFFF
    sz=((vaddr+seg.virtual_size-aligned+0xFFF)&~0xFFF)
    if sz: uc.mem_map(aligned, sz)
    uc.mem_write(vaddr, bytes(seg.content))
uc.mem_map(STACK, 1024*1024); uc.mem_map(HEAP, 16*1024*1024)
uc.mem_map(FAKE_JENV, 0x1000); uc.mem_map(JENV_TABLE, 0x20000)
uc.mem_map(RET_STUB, 0x1000); uc.mem_map(0x0, 0x100000)
uc.mem_write(0x28, struct.pack("<Q", HEAP))
SHIM_PAGE=0x0d000000; uc.mem_map(SHIM_PAGE, 0x40000)

got={rel.address: rel.symbol.name for rel in b.pltgot_relocations if rel.symbol}
RET32=bytes.fromhex("c0035fd6")
shim_names={}; heap_ptr=[0]
def bump(sz):
    a=HEAP+heap_ptr[0]; heap_ptr[0]+=(sz+15)&~15; return a

func_addr=BASE+0x10058
uc.mem_write(func_addr, struct.pack("<I", 0xD503201F))       # nop (str d8 save)
uc.mem_write(func_addr+0x24, struct.pack("<I", 0xD2800008))  # mov x8,#0 (mrs tpidr)

jenv_handlers={}; objects={}; nxt=[0x500]; log=[]
def new_obj(k,v=None):
    nxt[0]+=8; objects[nxt[0]]=(k,v); return nxt[0]

def cstr(addr,maxn=256):
    o=b""
    for i in range(maxn):
        try: c=uc.mem_read(addr+i,1)[0]
        except Exception: break
        if c==0: break
        o+=bytes([c])
    return o.decode(errors="ignore")

for idx,name in enumerate(JNI_ALL):
    slot=JENV_TABLE+8+idx*8
    h=SHIM_PAGE+0x30000+idx*16
    uc.mem_write(h, RET32+bytes(12))
    uc.mem_write(slot, struct.pack("<Q", h))
    jenv_handlers[h]=name
uc.mem_write(FAKE_JENV, struct.pack("<Q", JENV_TABLE))

libc_shims={}
for i,nm in enumerate(LIBC_NAMES):
    s=SHIM_PAGE+i*16
    uc.mem_write(s, RET32+bytes(12))
    ga=[g for g,n2 in got.items() if n2==nm]
    if ga: uc.mem_write(BASE+ga[0], struct.pack("<Q", s)); libc_shims[s]=nm

def do_jni(name):
    def ret(v): uc.reg_write(UC_ARM64_REG_X0,v)
    x1=uc.reg_read(UC_ARM64_REG_X1); x2=uc.reg_read(UC_ARM64_REG_X2)
    if name=="DefineClass":
        nm=cstr(x1)
        log.append(("DefineClass",nm))
        ret(new_obj("class",nm))
    elif name=="FindClass":
        nm=cstr(x1); log.append(("FindClass",nm)); ret(new_obj("class",nm))
    elif name in ("GetMethodID","GetStaticMethodID"):
        log.append((name,cstr(x1),cstr(x2))); ret(new_obj("method_id",(log[-1][1],log[-1][2])))
    elif name.startswith("Call"):
        tgt=objects.get(x1,("?","?"))[1] if x1 in objects else hex(x1)
        log.append((name,str(tgt))); ret(new_obj("callret"))
    elif name=="IsSameObject": ret(0)
    elif name in ("DeleteLocalRef","DeleteGlobalRef","ExceptionCheck","ExceptionOccurred"): ret(0)
    elif name=="GetVersion": ret(0x10006)
    elif name=="PopLocalFrame": ret(new_obj("frame"))
    elif name in ("EnsureLocalCapacity","PushLocalFrame"): ret(0)
    elif name in ("NewLocalRef","NewGlobalRef"): ret(new_obj("ref"))
    elif name in ("AllocObject","NewObject"): ret(new_obj("object"))
    elif name=="GetObjectClass": ret(new_obj("cls"))
    else: log.append((name,)); ret(new_obj("gen"))

def do_libc(n):
    x0=uc.reg_read(UC_ARM64_REG_X0); x1=uc.reg_read(UC_ARM64_REG_X1); x2=uc.reg_read(UC_ARM64_REG_X2)
    def ret(v): uc.reg_write(UC_ARM64_REG_X0,v)
    if n=="malloc": ret(bump(x0))
    elif n=="calloc":
        s=x1*x2 or 16; a=bump(s); uc.mem_write(a, bytes(min(s,65536))); ret(a)
    elif n in ("free","getauxval","dl_iterate_phdr") or (n or "").startswith("__cxa") or n=="__register_atfork": ret(0)
    elif n in ("memcpy","memmove","__memmove_chk"):
        d=bytes(uc.mem_read(x1,x2)); uc.mem_write(x0,d); ret(x0)
    elif n=="memset":
        uc.mem_write(x0, bytes([x1 & 0xFF])*x2); ret(x0)
    elif n=="posix_memalign":
        bb=bump(x2); uc.mem_write(x0, struct.pack("<Q", bb)); ret(0)
    elif n in ("strlen","__strlen_chk"):
        k=0
        while k<8192:
            try:
                if uc.mem_read(x0+k,1)[0]==0: break
            except Exception: break
            k+=1
        ret(k)
    elif n in ("strcmp","strncmp"):
        la=min(x2,4096) if n=="strncmp" else 4096
        sa=bytes(uc.mem_read(x0,la)).split(b"\x00")[0]
        sb=bytes(uc.mem_read(x1,la)).split(b"\x00")[0]
        ret(0 if sa==sb else 1)
    elif n=="__system_property_get": ret(0)
    elif n=="realloc": ret(bump(x1))
    elif n=="memchr":
        d=bytes(uc.mem_read(x0,min(x2,1048576))); i=d.find(x1&0xFF)
        ret(x0+i if i>=0 else 0)
    elif n in ("__stack_chk_fail","abort"): raise RuntimeError(n)
    else: ret(0)

last_pcs=[]
def combined(uc,address,size,ud):
    last_pcs.append(address)
    if len(last_pcs)>80: last_pcs.pop(0)
    n=jenv_handlers.get(address)
    if n: return do_jni(n)
    ln=libc_shims.get(address)
    if ln: return do_libc(ln)
uc.hook_add(UC_HOOK_CODE, combined)

uc.reg_write(UC_ARM64_REG_SP, STACK+1024*1024-0x200)
uc.reg_write(UC_ARM64_REG_X0, FAKE_JENV)
uc.reg_write(UC_ARM64_REG_X1, 0x1234)
uc.reg_write(UC_ARM64_REG_LR, RET_STUB)

status="clean"
try:
    uc.emu_start(func_addr, RET_STUB, timeout=180*1000000, count=100000000)
except Exception as e:
    status=str(e)[:60]

print(f"emulation {status}")
print(f"heap used: {heap_ptr[0]} bytes | shim slots executed")

# Read .data blob
mem=bytes(uc.mem_read(BASE+0x51C50, 0x54050-0x51C50))
idx=mem.find(b"ZGV4")
print(f".data blob at offset 0x{idx:x}" if idx>=0 else "no ZGV4 found!")

B64=set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r")
end=idx; gap=None
for i in range(idx,len(mem)):
    c=mem[i]
    if c in B64: end=i+1; gap=None
    else:
        if gap is None: gap=i
        if i-gap>=8: break
blob=mem[idx:end]
no_nl=blob.replace(b"\n",b"").replace(b"\r",b"")
cleaned=re.sub(rb"[^A-Za-z0-9+/=]",b"",no_nl)
pad=cleaned+b"A"*(-len(cleaned)%4)
dec=base64.b64decode(pad)
print("decoded:",len(dec),"magic:",dec[:8])

out=pathlib.Path("analysis/recovered/RTO_stage2.dex")
if dec[:4]==b"dex\n":
    fsz=struct.unpack("<I",dec[32:36])[0]
    if 0<fsz<=len(dec): dec=dec[:fsz]
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_bytes(dec)
    print(f"WROTE {out} ({len(dec)} bytes)")
else:
    print("unexpected magic; blob head:", dec[:24])

print("\n=== JNI calls observed ===")
for e in log[:30]: print(" ",e)
pathlib.Path("/tmp/oracle_log.json").write_text(json.dumps({"jni":[list(map(str,x)) for x in log]}, indent=2))
