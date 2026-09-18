import json
from pathlib import Path

POOL = Path("cjk_pool.txt").read_text(encoding='utf-8', errors='ignore').strip().splitlines()[0] if Path("cjk_pool.txt").exists() else ""
# handle multi
if not POOL or len(POOL)<4000:
    POOL = Path("cjk_pool.txt").read_bytes().decode('utf-8', errors='ignore').strip().replace('\r','').replace('\n','')
    # take longest line
    lines=Path("cjk_pool.txt").read_text(encoding='utf-8', errors='ignore').splitlines()
    lines=[l for l in lines if len(l)>1000]
    if lines:
        POOL = max(lines, key=len)
print(f"pool len {len(POOL)}")
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
def rotate16(v,s):
    v2=v &0xFFFF
    shl=(v2<<s)&0xFFFF
    ushr=(v2>> (16-s)) &0xFFFF if s!=0 else 0
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

def make_NkWa(rot):
    def NkWa(j):
        j_u=j&MASK64
        low=to_short(j_u &0xFFFF)
        high=to_short((j_u>>16)&0xFFFF)
        s=to_short((low+high)&0xFFFF)
        s_rot=rot(s,9)
        s2=to_short((s_rot+low)&0xFFFF)
        xor=to_short((high^low)&0xFFFF)
        r1=rot(low,13)
        r1=to_short((r1^xor)&0xFFFF)
        xor_int = xor &0xFFFFFFFF
        shl5=(xor_int<<5)&0xFFFFFFFF
        r1=to_short(((r1 &0xFFFFFFFF) ^ shl5) &0xFFFF)
        r2=rot(xor,10)
        # build with sign extend
        v1=((s2 & MASK64)<<16)&MASK64
        v4=(r2 & MASK64) | v1
        v4=(v4<<16)&MASK64
        v4=(v4 | (r1 & MASK64))&MASK64
        return to_signed64(v4)
    return NkWa

for rot_name, rot in [("32",rotate32),("16",rotate16)]:
    for NkWa in [make_NkWa(rotate32), make_NkWa(rotate16)]:
        # test
        NkWa_use = NkWa
        # Actually need to test both rots for NkWa, but we already did
        pass

# Test with rotate32 sign extend
NkWa32 = make_NkWa(rotate32)
NkWa16 = make_NkWa(rotate16)

def test_one(rot_name, NkWa_func, seed, exp):
    pool=[POOL]
    # compute t0,t1 etc
    low32 = (seed & MASK64) &0xFFFFFFFF
    t0=LMK(low32)
    t1=NkWa_func(t0)
    t1_u=t1&MASK64
    v3=(t1_u>>32)&0xFFFF
    t2=NkWa_func(t1)
    t2_u=t2&MASK64
    tmp=(t2_u>>16)&0xFFFF0000
    seed_high=ushr64(seed &MASK64,32)
    combined=(seed_high ^ v3 ^ tmp)&MASK64
    combined_int = (combined &0xFFFFFFFF)
    if combined_int>=0x80000000: combined_int-=0x100000000
    # prng step for length
    def prng(idx, state):
        ns=NkWa_func(state)
        ns_u=ns&MASK64
        pool_idx = idx//8191 if idx>=0 else -((-idx)//8191)  # trunc towards zero
        char_idx = idx %8191 if idx>=0 else -((-idx)%8191)
        # Java's % for negative gives negative remainder, need to handle
        # In Java, -1 %8191 = -1, not 8190. So for negative idx, char_idx negative
        # We'll use Python's % gives positive, but Java gives negative. So for negative idx, char_idx will be negative in Java, which would be out of bounds.
        # For now, handle negative by adding 8191
        if char_idx<0:
            char_idx+=8191
            pool_idx-=1 if idx<0 else 0  # not correct
        # pool handling
        if pool_idx<0 or pool_idx>=len(pool):
            pool_idx=0
            if char_idx<0 or char_idx>=len(pool[0]):
                char_idx %= len(pool[0])
        elif char_idx<0 or char_idx>=len(pool[pool_idx]):
            char_idx %= len(pool[pool_idx])
        c=pool[pool_idx][char_idx] if 0 <= char_idx < len(pool[pool_idx]) else '\x00'
        c_val=ord(c)
        res=( (c_val<<32) ^ ns_u) &MASK64
        return to_signed64(res), c, pool_idx, char_idx
    state, c0, pi, ci = prng(combined_int, t1)
    length = (state &MASK64 >>32) &0xFFFF if False else ((state &MASK64)>>32)&0xFFFF
    # Actually state>>32
    length2 = ((state &MASK64)>>32)&0xFFFF
    print(f"rot {rot_name} seed {seed} exp {exp!r} len exp {len(exp)} got len {length2} combined {combined_int} pi {pi} ci {ci} c {c0!r} t1 {t1&MASK64:016x} t0 {t0&MASK64:016x}")

for seed_str, exp in list(data.items())[:5]:
    if exp is None: continue
    seed=int(seed_str)
    print(f"\n=== seed {seed} exp {exp!r} ===")
    test_one("32", NkWa32, seed, exp)
    test_one("16", NkWa16, seed, exp)
    break

# Test for app_installation
seed=-9154610674182
exp="app_installation"
for name, func in [("32",NkWa32),("16",NkWa16)]:
    print(f"\n--- Testing {name} for app_installation ---")
    low32 = (seed & MASK64) &0xFFFFFFFF
    t0=LMK(low32)
    t1=func(t0)
    print(f"t0 {t0&MASK64:016x} t1 {t1&MASK64:016x}")
    # compute required pool chars for each output char
    # Need to simulate prng steps to get required pool chars
    # We know expected string, we can compute expected pool char for each step
    # prng: ns = NkWa(state), c = pool[idx], res = (c<<32)^ns, out = (res>>32)&0xFFFF = c ^ (ns>>32 &0xFFFF)
    # So c = out ^ (ns>>32 &0xFFFF)
    # For length step, out is length, c is pool char at combined_int
    # For subsequent steps, out is string chars
    # Let's compute
    t1_u=t1&MASK64
    v3=(t1_u>>32)&0xFFFF
    t2=func(t1)
    t2_u=t2&MASK64
    tmp=(t2_u>>16)&0xFFFF0000
    seed_high=ushr64(seed &MASK64,32)
    combined=(seed_high ^ v3 ^ tmp)&MASK64
    combined_int = (combined &0xFFFFFFFF)
    if combined_int>=0x80000000: combined_int-=0x100000000
    print(f"combined {combined_int} seed_high {seed_high:08x} v3 {v3:04x} tmp {tmp:08x}")
    # length step
    ns=func(t1)
    ns_u=ns&MASK64
    # pool char at combined_int
    pool_idx = combined_int//8191 if combined_int>=0 else -((-combined_int)//8191)
    char_idx = combined_int %8191 if combined_int>=0 else -((-combined_int)%8191)
    if char_idx<0: char_idx+=8191
    if pool_idx<0 or pool_idx>=1: pool_idx=0
    if char_idx<0 or char_idx>=len(POOL): char_idx%=len(POOL)
    pool_c = POOL[char_idx]
    length_exp = len(exp)
    # required pool char for length
    ns_high = (ns_u>>32)&0xFFFF
    req_pool_char = length_exp ^ ns_high
    print(f"length step: ns {ns&MASK64:016x} ns_high {ns_high:04x} pool_c {pool_c!r} ord {ord(pool_c):04x} req {req_pool_char:04x} chr {chr(req_pool_char)!r} match {ord(pool_c)==req_pool_char}")
    # For string chars
    state = ( (ord(pool_c)<<32) ^ ns_u) &MASK64
    state = to_signed64(state)
    for i, ch in enumerate(exp):
        idx = combined_int + i +1
        ns2 = func(state)
        ns2_u=ns2&MASK64
        ns2_high = (ns2_u>>32)&0xFFFF
        req = ord(ch) ^ ns2_high
        # pool char at idx
        pi = idx//8191 if idx>=0 else -((-idx)//8191)
        ci = idx%8191 if idx>=0 else -((-idx)%8191)
        if ci<0: ci+=8191
        if pi<0 or pi>=1: pi=0
        if ci>=len(POOL): ci%=len(POOL)
        pc = POOL[ci]
        print(f" i {i} idx {idx} pi {pi} ci {ci} ns2 {ns2&MASK64:016x} ns_high {ns2_high:04x} exp ch {ch!r} {ord(ch):04x} req pool {req:04x} {chr(req)!r} actual pool {pc!r} {ord(pc):04x} match {req==ord(pc)}")
        # update state for next
        state = ((ord(pc)<<32) ^ ns2_u) &MASK64
        state = to_signed64(state)
        if i>=5: break
