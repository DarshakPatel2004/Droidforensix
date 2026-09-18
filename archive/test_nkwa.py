MASK64=(1<<64)-1
def to_short(x): x&=0xFFFF; return x if x<0x8000 else x-0x10000
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
def NkWa(j, rot):
    MASK64=(1<<64)-1
    def to_signed64(x): x&=MASK64; return x if x<(1<<63) else x-(1<<64)
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
    # sign extend
    v1=((s2 & MASK64)<<16)&MASK64
    v4=(r2 & MASK64) | v1
    v4=(v4<<16)&MASK64
    v4=(v4 | (r1 & MASK64))&MASK64
    return to_signed64(v4)
def NkWa_zero(j, rot):
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
    v = ((s2 &0xFFFF)<<32) | ((r2 &0xFFFF)<<16) | (r1 &0xFFFF)
    return v if v<0x8000000000000000 else v-0x10000000000000000

t0=0x7718AF51
for name, rot in [("32",rotate32),("16",rotate16)]:
    for func in [lambda j: NkWa(j, rot), lambda j: NkWa_zero(j, rot)]:
        v=func(t0)
        print(f"{name} {'sign' if func==NkWa else 'zero'} {v & MASK64:016x} high {(v>>32)&0xFFFF:04x} low {v &0xFFFF:04x}")
        # also test for t1
        # For our earlier t1, we had t1 = NkWa(t0) = ?
        # Then ns = NkWa(t1) high should be pool_char ^16
        # Let's compute ns for each
        t1=func(t0)
        ns=func(t1)
        print(f"  ns {ns & MASK64:016x} high {(ns>>32)&0xFFFF:04x}")

# Also test LMK alternative: maybe low32 should be sign-extended 32 to 64 as unsigned vs signed?
# Already did.

# Test pool char requirement
POOL = open("cjk_pool.txt", encoding="utf-8", errors="ignore").read().strip().splitlines()[0] if open("cjk_pool.txt", encoding="utf-8", errors="ignore").read().strip() else ""
# Actually read correctly
import pathlib
txt=pathlib.Path("cjk_pool.txt").read_bytes().decode('utf-8', errors='ignore').strip().replace('\r','').replace('\n','')
lines=pathlib.Path("cjk_pool.txt").read_text(encoding='utf-8', errors='ignore').splitlines()
lines=[l for l in lines if len(l)>1000]
if lines:
    POOL=max(lines, key=len)
else:
    POOL=txt
print(f"pool len {len(POOL)}")
# For test seed, combined 2131, pool char at 2131 is POOL[2131]
print(f"pool[2131] {ord(POOL[2131]):04x} {POOL[2131]!r}")
# For each variant, compute required
for name, rot in [("32",rotate32),("16",rotate16)]:
    for build in ["sign","zero"]:
        func = NkWa if build=="sign" else NkWa_zero
        # need to create with rot
        def make(rot, build):
            def f(j):
                j_u=j&MASK64
                low=to_short(j_u &0xFFFF)
                high=to_short((j_u>>16)&0xFFFF)
                s=to_short((low+high)&0xFFFF)
                s_rot=rot(s,9)
                s2=to_short((s_rot+low)&0xFFFF)
                xor=to_short((high^low)&0xFFFF)
                r1=rot(low,13)
                r1=to_short((r1^xor)&0xFFFF)
                shl5=( (xor &0xFFFFFFFF)<<5)&0xFFFFFFFF
                r1=to_short(((r1 &0xFFFFFFFF) ^ shl5)&0xFFFF)
                r2=rot(xor,10)
                if build=="sign":
                    v1=((s2 & MASK64)<<16)&MASK64
                    v4=(r2 & MASK64) | v1
                    v4=(v4<<16)&MASK64
                    v4=(v4 | (r1 & MASK64))&MASK64
                    return v4 if v4<0x8000000000000000 else v4-0x10000000000000000
                else:
                    v=((s2 &0xFFFF)<<32)|((r2 &0xFFFF)<<16)|(r1 &0xFFFF)
                    return v if v<0x8000000000000000 else v-0x10000000000000000
            return f
        f=make(rot, build)
        t0_val=0x7718AF51
        t1=f(t0_val)
        ns=f(t1)
        high=(ns>>32)&0xFFFF if ns>=0 else (ns & MASK64>>32)&0xFFFF
        # Actually ns is Python signed, need unsigned
        ns_u = ns & MASK64
        high2=(ns_u>>32)&0xFFFF
        pool_c = POOL[2131]
        req = 16 ^ high2
        print(f"{name} {build} t1 {t1 &MASK64:016x} ns {ns_u:016x} high {high2:04x} req {req:04x} pool {ord(pool_c):04x} match {req==ord(pool_c)}")
