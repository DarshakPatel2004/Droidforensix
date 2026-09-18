import json
from pathlib import Path

POOL_PATH = Path("cjk_pool.txt")
# Load pool as list of chars for reference, but we will solve
pool_txt = Path("cjk_pool.txt").read_bytes().decode('utf-8', errors='ignore').strip().replace('\r','').replace('\n','')
lines = Path("cjk_pool.txt").read_text(encoding='utf-8', errors='ignore').splitlines()
lines = [l for l in lines if len(l)>1000]
if lines:
    pool_txt = max(lines, key=len)
POOL_LEN = len(pool_txt)
print(f"pool len {POOL_LEN}")

data = json.loads(Path("rto_analysis/phase2/installer_deobfuscated_strings.json").read_text(encoding='utf-8'))

MASK64=(1<<64)-1
def to_short(x): x&=0xFFFF; return x if x<0x8000 else x-0x10000
def ushr64(x,n): return (x & MASK64)>>n
def mul64(a,b): return (a*b)&MASK64
def to_signed64(x): x&=MASK64; return x if x<(1<<63) else x-(1<<64)
def rotate_S(s,i):
    # decompiled: (short)((s >>> (32-i)) | (s << i))
    # s is short, promoted to int, then >>> and << as 32-bit, then cast to short
    s_int = s & 0xFFFFFFFF  # sign extend to 32
    # Actually s as short -1 => s_int = 0xFFFFFFFF
    # s << i as 32-bit
    shl = (s_int << i) & 0xFFFFFFFF
    ushr = (s_int & 0xFFFFFFFF) >> (32 - i)
    res = (shl | ushr) & 0xFFFFFFFF
    return to_short(res & 0xFFFF)

def LMK(j):
    j2 = (j ^ (j >> 33)) * 7109453100751455733 & MASK64
    # Actually (j ^ (j>>>33)) * 710... where j is long, >>> is logical, ^ is 64-bit
    # Our j is Python int, need to mask
    # Let's do exactly as Java: (j ^ (j >>>33)) * 710... where j is long (64-bit)
    # j>>>33 is logical
    # Use unsigned
    j_u = j & MASK64
    j2 = ((j_u ^ (j_u >>33)) * 7109453100751455733) & MASK64
    # Actually need to do (j ^ (j>>>33)) as 64-bit, then * constant, then (j2 ^ (j2>>>28)) * -380...
    # Let's do step by step with unsigned
    j2_u = j2 & MASK64
    j3 = ((j2_u ^ (j2_u >>28)) * ((-3808689974395783757) & MASK64)) & MASK64
    res = (j3 >>32) & MASK64
    return to_signed64(res)

def NkWa(j):
    s = to_short(j & 0xFFFF)
    s2 = to_short((j >>16) & 0xFFFF)
    Oh = to_short((rotate_S(to_short(s + s2), 9) + s) & 0xFFFF)
    s3 = to_short((s2 ^ s) & 0xFFFF)
    r2 = rotate_S(s3, 10)
    # Build as 32-bit int with sign extension, then sign-extend to 64
    # Java does 32-bit operations, then (long) cast sign-extends
    r2_int = r2  # as Python signed int, already sign-extended to infinite, but as 32-bit it's sign-extended
    # Convert to 32-bit signed int representation for Java's int
    # For r2=-1, r2_int = -1, as 32-bit 0xFFFFFFFF, correct
    # For Oh, need Oh as int sign-extended
    Oh_int = Oh
    tmp = ( (r2_int & 0xFFFFFFFF) | (((Oh_int & 0xFFFFFFFF) <<16) & 0xFFFFFFFF) ) & 0xFFFFFFFF
    tmp = (tmp <<16) & 0xFFFFFFFF
    r1 = rotate_S(s, 13)
    r1 = to_short((r1 ^ s3) & 0xFFFF)
    shl5 = ((s3 & 0xFFFFFFFF) <<5) & 0xFFFFFFFF
    r1 = to_short(((r1 & 0xFFFFFFFF) ^ shl5) & 0xFFFF)
    res_int = (tmp | (r1 & 0xFFFFFFFF)) & 0xFFFFFFFF
    res_signed32 = res_int if res_int < 0x80000000 else res_int - 0x100000000
    return res_signed32  # as Python int, will be sign-extended to 64 when used as long (since Python int is signed)

# Test LMK and NkWa for t0
seed=-9154610674182
low32 = (seed & MASK64) & 0xFFFFFFFF
t0 = LMK(low32)
print(f"t0 {t0 &MASK64:016x}")
t1 = NkWa(t0)
print(f"t1 {t1 &MASK64:016x}")
# Now try to solve pool for this seed
exp="app_installation"
# Steps as per Java
seed_u = seed & MASK64
t0_2 = LMK(seed_u & 0xFFFFFFFF)
t1_2 = NkWa(t0_2)
v3 = (t1_2 &MASK64 >>32) &0xFFFF if False else ((t1_2 &MASK64)>>32)&0xFFFF
# Actually need to do (t1 >>>32) &0xFFFF where t1 is long sign-extended
# t1 as signed 64, >>> is logical, so (t1 &MASK64)>>32
v3 = ((t1_2 &MASK64)>>32) &0xFFFF
t2 = NkWa(t1_2)
tmp = ((t2 &MASK64)>>16) &0xFFFF0000
seed_high = (seed_u >>32) &0xFFFFFFFF
combined = (seed_high ^ v3 ^ tmp) &0xFFFFFFFF
combined_int = combined if combined <0x80000000 else combined-0x100000000
print(f"v3 {v3:04x} t2 {t2&MASK64:016x} tmp {tmp:08x} seed_high {seed_high:08x} combined {combined:08x} int {combined_int}")

# Now first prng
def prng_solve(idx, state, expected_char=None):
    # returns next state and required pool char if expected is given
    ns = NkWa(state)
    ns_u = ns &MASK64
    ns_high = (ns_u>>32)&0xFFFF
    # pool idx
    pool_idx = idx//8191 if idx>=0 else -((-idx)//8191)
    char_idx = idx%8191 if idx>=0 else -((-idx)%8191)
    if char_idx<0: char_idx+=8191
    # For solving, we need to know what pool char would make expected
    if expected_char is not None:
        exp_ord = ord(expected_char) if isinstance(expected_char, str) else expected_char
        req = exp_ord ^ ns_high
        return ns, req, pool_idx, char_idx
    else:
        # length case, expected length is len(exp)
        exp_len = len(exp) if isinstance(exp, str) else exp
        req = exp_len ^ ns_high
        return ns, req, pool_idx, char_idx

# For length, expected is len(exp) =16
ns, req, pi, ci = prng_solve(combined_int, t2, len(exp))
open("solve_out.txt","a",encoding="utf-8",errors="ignore").write(f"length step: ns {ns&MASK64:016x} high {(ns&MASK64>>32)&0xFFFF:04x} req {req:04x} pi {pi} ci {ci} actual {ord(pool_txt[ci]):04x} match {req==ord(pool_txt[ci])}\n")

# Now for each char
state = ( (req<<32) ^ (ns &MASK64)) &MASK64
state = to_signed64(state)
for i,ch in enumerate(exp):
    idx = combined_int + i +1
    ns2 = NkWa(state)
    ns2_u = ns2 &MASK64
    ns2_high = (ns2_u>>32)&0xFFFF
    req2 = ord(ch) ^ ns2_high
    pi = idx//8191 if idx>=0 else -((-idx)//8191)
    ci = idx%8191 if idx>=0 else -((-idx)%8191)
    if ci<0: ci+=8191
    actual = ord(pool_txt[ci]) if 0 <= ci < len(pool_txt) else 0
    print(f"i {i} idx {idx} ch {ch!r} {ord(ch):04x} ns_high {ns2_high:04x} req {req2:04x} actual {actual:04x} {pool_txt[ci]!r} match {req2==actual}")
    state = ((actual<<32) ^ ns2_u) &MASK64 if False else ((req2<<32) ^ ns2_u) &MASK64
    # For next iteration, state should be based on actual pool char if we want to simulate correct, but for solving we use required
    state = to_signed64(state)
    if i>=2: break
