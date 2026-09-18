import json, pathlib
MASK64=(1<<64)-1
def to_short(x): x&=0xFFFF; return x if x<0x8000 else x-0x10000
def ushr64(x,n): return (x & MASK64)>>n
def mul64(a,b): return (a*b)&MASK64
def to_signed64(x): x&=MASK64; return x if x<(1<<63) else x-(1<<64)
def rotate_S(s,i):
    # as per decompiled: (short)((s >>> (32-i)) | (s << i))
    # s is short, promoted to int, then >>> and << as 32-bit, then cast to short
    s_int = s & 0xFFFFFFFF
    shl = (s_int << i) & 0xFFFFFFFF
    ushr = (s_int & 0xFFFFFFFF) >> (32 - i)
    res = (shl | ushr) & 0xFFFFFFFF
    return to_short(res & 0xFFFF)
def LMK(j):
    j_u = j & MASK64
    j2 = ((j_u ^ (j_u >>33)) * 7109453100751455733) & MASK64
    return to_signed64(((j2 ^ (j2 >>28)) * ((-3808689974395783757) & MASK64) >>32) & MASK64)
def NkWa(j):
    s = to_short(j & 0xFFFF)
    s2 = to_short((j >>16) & 0xFFFF)
    Oh = to_short((rotate_S(to_short(s + s2), 9) + s) & 0xFFFF)
    s3 = to_short((s2 ^ s) & 0xFFFF)
    r2 = rotate_S(s3, 10)
    tmp = ( (r2 & 0xFFFFFFFF) | (((Oh & 0xFFFFFFFF) <<16) & 0xFFFFFFFF) ) & 0xFFFFFFFF
    tmp = (tmp <<16) & 0xFFFFFFFF
    r1 = rotate_S(s, 13)
    r1 = to_short((r1 ^ s3) & 0xFFFF)
    shl5 = ((s3 & 0xFFFFFFFF) <<5) & 0xFFFFFFFF
    r1 = to_short(((r1 & 0xFFFFFFFF) ^ shl5) & 0xFFFF)
    res_int = (tmp | (r1 & 0xFFFFFFFF)) & 0xFFFFFFFF
    res_signed32 = res_int if res_int < 0x80000000 else res_int - 0x100000000
    return res_signed32

# Load data
data = json.loads(pathlib.Path("rto_analysis/phase2/installer_deobfuscated_strings.json").read_text(encoding='utf-8'))
# Try to solve for pool
# We need to know pool length, assume 8191 or 4320, try both
for pool_len in [4320, 4321, 8191]:
    pool = [0]*8191  # use 8191 for max, init 0
    # Actually we will use dict for required chars
    required = {}
    conflict=False
    for k, exp in data.items():
        if exp is None: continue
        seed=int(k)
        # Simulate to get required pool chars
        # Steps per decompiled
        low = seed & 0xFFFFFFFF
        t0 = LMK(low)
        t1 = NkWa(t0)
        j2 = (t1 &MASK64 >>32) &0xFFFF if False else ((t1 &MASK64)>>32)&0xFFFF
        # Actually t1 is signed 32, need unsigned for >>>32
        t1_u = t1 & MASK64
        j2 = (t1_u >>32) &0xFFFF
        t2 = NkWa(t1)
        t2_u = t2 &MASK64
        tmp = (t2_u >>16) &0xFFFF0000
        seed_high = (seed &MASK64 >>32) &0xFFFFFFFF
        combined = (seed_high ^ j2 ^ tmp) &0xFFFFFFFF
        combined_int = combined if combined <0x80000000 else combined-0x100000000
        # First prng for length
        # Need to handle pool idx via 8191
        # For solving, we need to know what pool char at combined would make len = len(exp)
        # prng: ns = NkWa(t2), pool_char = pool[combined %8191], state = (pool_char<<32) ^ ns, len = (state>>32)&0xFFFF
        # So pool_char = len ^ (ns>>32 &0xFFFF)
        ns = NkWa(t2)
        ns_u = ns &MASK64
        ns_high = (ns_u>>32)&0xFFFF
        # For len, expected len = len(exp)
        exp_len = len(exp)
        # pool idx for length
        # In Ftp, they do i = combined, then NkWa(i, pool, t2) where i is combined, pool is array, t2 is state
        # That NkWa does (pool[i%8191] <<32) ^ NkWa(t2)
        # So pool_char for length is at i %8191
        # For our case, i=combined_int
        pi = combined_int//8191 if combined_int>=0 else -((-combined_int)//8191)
        ci = combined_int%8191 if combined_int>=0 else -((-combined_int)%8191)
        if ci<0: ci+=8191
        # Actually need to handle Java's % for negative: -1%8191 = -1, not 8190, but combined is positive 2131, so fine
        # For positive, ci = combined %8191
        # Use 8191
        ci = combined_int %8191 if combined_int>=0 else (8191 + (combined_int%8191))%8191
        # For pool array size 1, pi should be 0, ci < pool_len, but we use 8191 as divisor, not pool_len
        # For solving, we map ci to pool index via ci % pool_len? No, the code does charAt(ci) where ci is 0..8190, but pool string length is 4320, so ci must be <4320, otherwise out of bounds
        # For our case, ci=2131 <4320, so okay
        # Required pool char for length
        req_len_char = exp_len ^ ns_high
        # Record
        key = ci  # using 8191 modulus, but actual pool index is ci, not pi
        # For pool array with 1 element, the char index is ci, but ci must be < len(pool[0])
        # So we map required char at position ci
        if ci in required and required[ci] != req_len_char:
            print(f"conflict len for ci {ci} exp {exp_len} req {req_len_char:04x} vs {required[ci]:04x}")
            conflict=True
            break
        required[ci]=req_len_char
        # Now for string chars
        # state after length
        state = ((req_len_char<<32) ^ ns_u) &MASK64
        state = state if state <0x8000000000000000 else state-0x10000000000000000
        # Actually Ftp's state is (pool_char<<32) ^ ns, where pool_char is 16-bit, ns is 64-bit, result is 64-bit
        # For next, we need to iterate
        for idx_offset, ch in enumerate(exp):
            i2 = combined_int + idx_offset +1
            pi2 = i2//8191 if i2>=0 else -((-i2)//8191)
            ci2 = i2%8191 if i2>=0 else -((-i2)%8191)
            if ci2<0: ci2+=8191
            ns2 = NkWa(state)
            ns2_u = ns2 &MASK64
            ns2_high = (ns2_u>>32)&0xFFFF
            req2 = ord(ch) ^ ns2_high
            if ci2 in required and required[ci2] != req2:
                #print(f"conflict char for ci {ci2} ch {ch!r} exp {ord(ch):04x} req {req2:04x} vs {required[ci2]:04x}")
                conflict=True
                break
            required[ci2]=req2
            state = ((req2<<32) ^ ns2_u) &MASK64
            state = state if state <0x8000000000000000 else state-0x10000000000000000
        if conflict:
            break
    if not conflict:
        print(f"pool_len {pool_len} no conflict, required size {len(required)} max ci {max(required.keys()) if required else 0}")
        # Check if all required ci < pool_len
        max_ci = max(required.keys()) if required else 0
        if max_ci < pool_len:
            print(f"  -> fits in pool_len {pool_len}")
            # Build pool string of length pool_len with required chars, fill rest with 0
            pool_chars = ['\u0000']*pool_len
            for ci, val in required.items():
                if ci < pool_len:
                    pool_chars[ci]=chr(val)
            # Check if pool_chars at 2131 matches earlier
            print(f"  pool[2131] {ord(pool_chars[2131]):04x} {repr(pool_chars[2131])}")
            # Write pool for test
            pathlib.Path(f"reconstructed_pool_{pool_len}.txt").write_text(''.join(pool_chars), encoding='utf-8', errors='ignore')
            print(f"  written reconstructed_pool_{pool_len}.txt")
        else:
            print(f"  -> does not fit, max {max_ci} >= {pool_len}")
    else:
        print(f"pool_len {pool_len} conflict")
