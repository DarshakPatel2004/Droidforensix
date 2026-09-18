import json
from pathlib import Path

POOL = Path("cjk_pool.txt").read_bytes().decode('utf-8', errors='ignore').strip().replace('\r','').replace('\n','')
# Actually cjk_pool.txt is one line, but we need to handle
lines=Path("cjk_pool.txt").read_text(encoding='utf-8', errors='ignore').splitlines()
lines=[l for l in lines if len(l)>1000]
if lines:
    POOL = max(lines, key=len)
print("pool len", len(POOL))
open("pool_req_out.txt","w",encoding="utf-8",errors="ignore").write(f"pool len {len(POOL)}\n")
data=json.loads(Path("rto_analysis/phase2/installer_deobfuscated_strings.json").read_text(encoding='utf-8'))
MASK64=(1<<64)-1
def to_short(x): x&=0xFFFF; return x if x<0x8000 else x-0x10000
def ushr64(x,n): return (x & MASK64)>>n
def mul64(a,b): return (a*b)&MASK64
def to_signed64(x): x&=MASK64; return x if x<(1<<63) else x-(1<<64)
def rotate32(v,s):
    v_int=v &0xFFFFFFFF
    shl=(v_int<<s)&0xFFFFFFFF
    ushr=(v_int>> (32-s)) &0xFFFFFFFF
    return to_short((shl|ushr)&0xFFFF)

def LMK(x):
    x&=MASK64
    v=ushr64(x,33)^x
    x=v&MASK64
    x=mul64(x,7109453100751455733)
    v=ushr64(x,28)^x
    x=v&MASK64
    c2=(-3808689974395783757)&MASK64
    x=mul64(x,c2)
    x=ushr64(x,32)
    return to_signed64(x)

def NkWa(j):
    j_u=j&MASK64
    low=to_short(j_u &0xFFFF)
    high=to_short((j_u>>16)&0xFFFF)
    s=to_short((low+high)&0xFFFF)
    s_rot=rotate32(s,9)
    s2=to_short((s_rot+low)&0xFFFF)
    xor=to_short((high^low)&0xFFFF)
    r1=rotate32(low,13)
    r1=to_short((r1^xor)&0xFFFF)
    xor_int = xor &0xFFFFFFFF
    shl5=(xor_int<<5)&0xFFFFFFFF
    r1=to_short(((r1 &0xFFFFFFFF) ^ shl5) &0xFFFF)
    r2=rotate32(xor,10)
    v1=((s2 & MASK64)<<16)&MASK64
    v4=(r2 & MASK64) | v1
    v4=(v4<<16)&MASK64
    v4=(v4 | (r1 & MASK64))&MASK64
    return to_signed64(v4)

seed=-9154610674182
exp="app_installation"
low32 = (seed & MASK64) &0xFFFFFFFF
t0=LMK(low32)
t1=NkWa(t0)
print(f"t0 {t0&MASK64:016x} t1 {t1&MASK64:016x}")
open("pool_req_out.txt","a",encoding="utf-8",errors="ignore").write(f"t0 {t0&MASK64:016x} t1 {t1&MASK64:016x}\n")
t1_u=t1&MASK64
v3=(t1_u>>32)&0xFFFF
t2=NkWa(t1)
t2_u=t2&MASK64
tmp=(t2_u>>16)&0xFFFF0000
seed_high=ushr64(seed &MASK64,32)
combined=(seed_high ^ v3 ^ tmp)&MASK64
combined_int = (combined &0xFFFFFFFF)
if combined_int>=0x80000000: combined_int-=0x100000000
print(f"combined {combined_int} seed_high {seed_high:08x} v3 {v3:04x} tmp {tmp:08x} t2 {t2&MASK64:016x}")
open("pool_req_out.txt","a",encoding="utf-8",errors="ignore").write(f"combined {combined_int} seed_high {seed_high:08x} v3 {v3:04x} tmp {tmp:08x}\n")
ns=NkWa(t1)
ns_u=ns&MASK64
pool_idx = combined_int//8191 if combined_int>=0 else -((-combined_int)//8191)
char_idx = combined_int%8191 if combined_int>=0 else -((-combined_int)%8191)
if char_idx<0: char_idx+=8191
if pool_idx<0 or pool_idx>=1: pool_idx=0
if char_idx<0 or char_idx>=len(POOL): char_idx%=len(POOL)
pool_c = POOL[char_idx]
ns_high = (ns_u>>32)&0xFFFF
length_exp = len(exp)
req_pool_char = length_exp ^ ns_high
open("pool_req_out.txt","a",encoding="utf-8",errors="ignore").write(f"length step ns {ns&MASK64:016x} ns_high {ns_high:04x} pool_idx {pool_idx} char_idx {char_idx} pool_c ord {ord(pool_c):04x} req {req_pool_char:04x} match {ord(pool_c)==req_pool_char}\n")
print(f"length step ns {ns&MASK64:016x} ns_high {ns_high:04x} pool idx {pool_idx} ci {char_idx} pool ord {ord(pool_c):04x} req {req_pool_char:04x} match {ord(pool_c)==req_pool_char}")
# For string chars
state = ((ord(pool_c)<<32) ^ ns_u) &MASK64
state = to_signed64(state)
for i,ch in enumerate(exp):
    idx = combined_int + i +1
    ns2 = NkWa(state)
    ns2_u=ns2&MASK64
    ns2_high = (ns2_u>>32)&0xFFFF
    req = ord(ch) ^ ns2_high
    pi = idx//8191 if idx>=0 else -((-idx)//8191)
    ci = idx%8191 if idx>=0 else -((-idx)%8191)
    if ci<0: ci+=8191
    if pi<0 or pi>=1: pi=0
    if ci>=len(POOL): ci%=len(POOL)
    pc = POOL[ci]
    open("pool_req_out.txt","a",encoding="utf-8",errors="ignore").write(f"i {i} idx {idx} pi {pi} ci {ci} ns2 {ns2&MASK64:016x} high {ns2_high:04x} ch {ch!r} {ord(ch):04x} req {req:04x} pc {ord(pc):04x} match {req==ord(pc)}\n")
    print(f"i {i} idx {idx} req {req:04x} pc {ord(pc):04x} match {req==ord(pc)} ch {ch!r}")
    state = ((ord(pc)<<32) ^ ns2_u) &MASK64
    state = to_signed64(state)
    if i>=5: break
