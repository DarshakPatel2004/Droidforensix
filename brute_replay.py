import json
from pathlib import Path

POOL = Path("cjk_pool.txt").read_text(encoding='utf-8', errors='ignore').strip().splitlines()[0] if Path("cjk_pool.txt").exists() else ""
if not POOL:
    POOL = Path("cjk_pool.txt").read_bytes().decode('utf-8', errors='ignore').strip()
pool=[POOL]
print(f"pool len {len(POOL)}")
data=json.loads(Path("rto_analysis/phase2/installer_deobfuscated_strings.json").read_text(encoding='utf-8'))

# Try to brute force variations
MASK64=(1<<64)-1

def to_short(x):
    x&=0xFFFF
    return x if x<0x8000 else x-0x10000
def to_int32(x):
    x&=0xFFFFFFFF
    return x if x<0x80000000 else x-0x100000000
def ushr64(x,n): return (x & MASK64)>>n
def mul64(a,b): return (a*b)&MASK64
def to_signed64(x): 
    x&=MASK64
    return x if x<(1<<63) else x-(1<<64)

def rotate32(value, shift):
    v_int=value & 0xFFFFFFFF
    shl=(v_int<<shift)&0xFFFFFFFF
    r=32-shift
    ushr=(v_int>>r) if r>=0 else 0
    res=(shl|ushr)&0xFFFFFFFF
    return to_short(res &0xFFFF)

def rotate16(value, shift):
    v=value &0xFFFF
    shl=(v<<shift)&0xFFFF
    r=16-shift
    ushr=(v>>r) &0xFFFF
    res=(shl|ushr)&0xFFFF
    return to_short(res)

# Test both
for name, func in [("rotate32", rotate32), ("rotate16", rotate16)]:
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
    def NkWa_rot(j, rot):
        j_u=j&MASK64
        low=to_short(j_u &0xFFFF)
        high=to_short((j_u>>16)&0xFFFF)
        s=to_short((low+high)&0xFFFF)
        s_rot=rot(s,9)
        s2=to_short((s_rot+low)&0xFFFF)
        xor=to_short((high^low)&0xFFFF)
        r1=rot(low,13)
        r1=to_short((r1^xor)&0xFFFF)
        # shl 5 on xor as 32-bit
        xor_int = xor & 0xFFFFFFFF
        shl5 = (xor_int <<5) &0xFFFFFFFF
        # r1 ^ shl5 as 32 then to_short
        r1 = to_short( ((r1 &0xFFFFFFFF) ^ shl5) &0xFFFF )
        r2=rot(xor,10)
        # build long with sign extend vs zero extend
        # try both
        return s2, r2, r1
    # quick test
    j=0x123456789ABCDEF0 &MASK64
    j_signed=to_signed64(j)
    s2,r2,r1=NkWa_rot(j_signed, func)
    print(f"{name} s2 {s2} r2 {r2} r1 {r1} hex {s2&0xFFFF:04x} {r2&0xFFFF:04x} {r1&0xFFFF:04x}")

# Now brute force decode with each rotate variant and each build variant
def test_variant(rot_func, build_sign_extend):
    def NkWa2(j):
        j_u=j&MASK64
        low=to_short(j_u &0xFFFF)
        high=to_short((j_u>>16)&0xFFFF)
        s=to_short((low+high)&0xFFFF)
        s_rot=rot_func(s,9)
        s2=to_short((s_rot+low)&0xFFFF)
        xor=to_short((high^low)&0xFFFF)
        r1=rot_func(low,13)
        r1=to_short((r1^xor)&0xFFFF)
        xor_int = xor &0xFFFFFFFF
        shl5 = (xor_int <<5) &0xFFFFFFFF
        r1 = to_short( ((r1 &0xFFFFFFFF) ^ shl5) &0xFFFF )
        r2=rot_func(xor,10)
        if build_sign_extend:
            # sign extend to 64
            v1 = ((s2 & MASK64) <<16) &MASK64
            v4 = (r2 & MASK64) | v1
            v4 = (v4 <<16) &MASK64
            v4 = (v4 | (r1 & MASK64)) &MASK64
        else:
            # zero extend
            v = ((s2 &0xFFFF)<<32) | ((r2 &0xFFFF)<<16) | (r1 &0xFFFF)
            v4=v
        return to_signed64(v4)
    def LMK2(x):
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
    def prng_step(idx, pool, state):
        ns=NkWa2(state)
        ns_u=ns&MASK64
        pool_idx=idx//8191
        char_idx=idx%8191
        if pool_idx>=len(pool):
            pool_idx=0
            char_idx=char_idx % len(pool[0]) if pool else 0
        elif char_idx>=len(pool[pool_idx]):
            char_idx%=len(pool[pool_idx])
        row=pool[pool_idx]
        c=row[char_idx] if char_idx < len(row) else '\x00'
        c_val=ord(c)
        c_long=(c_val &0xFFFFFFFF)<<32
        res=(c_long ^ ns_u)&MASK64
        return to_signed64(res)
    def decode(seed, pool):
        seed_u=seed&MASK64
        low32=seed_u &0xFFFFFFFF
        t0=LMK2(to_signed64(low32))
        t1=NkWa2(t0)
        t1_u=t1&MASK64
        v3=(t1_u>>32)&0xFFFF
        t2=NkWa2(t1)
        t2_u=t2&MASK64
        tmp=(t2_u>>16)&0xFFFF0000
        seed_high=ushr64(seed_u,32)
        combined=(seed_high ^ v3 ^ tmp)&MASK64
        combined_int=to_int32(combined &0xFFFFFFFF)
        state=prng_step(combined_int, pool, t1)
        state_u=state&MASK64
        length=(state_u>>32)&0xFFFF
        chars=[]
        for i in range(length):
            idx=combined_int + i +1
            state=prng_step(idx, pool, state)
            state_u=state&MASK64
            c_val=(state_u>>32)&0xFFFF
            chars.append(chr(c_val &0xFFFF))
        return ''.join(chars)
    # test on few seeds
    tests=[-9154610674182, -11667166542342, -2643440253446, -12852577516038]
    for seed in tests:
        exp=data.get(str(seed))
        if exp is None: continue
        try:
            got=decode(seed, pool)
            ok=got==exp
            print(f"rot {rot_func.__name__} sign {build_sign_extend} seed {seed} exp {exp!r} got len {len(got)} ok {ok} got {got[:20]!r}")
        except Exception as e:
            print(f"err {e}")

for rot, name in [(rotate32,"32"), (rotate16,"16")]:
    for sign in [True, False]:
        print(f"\n=== Testing rot {name} sign {sign} ===")
        test_variant(rot, sign)
