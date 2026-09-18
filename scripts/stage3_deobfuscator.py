#!/usr/bin/env python3
"""Stage-3 bytecode replay: regenerate installer strings from CJK pool."""
import json, sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
POOL_PATH = PROJECT_ROOT / "cjk_pool.txt"
JSON_PATH = PROJECT_ROOT / "rto_analysis" / "phase2" / "installer_deobfuscated_strings.json"

MASK64 = (1<<64)-1
MASK32 = (1<<32)-1

def to_signed64(x):
    x &= MASK64
    return x if x < (1<<63) else x - (1<<64)
def ushr64(x, n):
    return (x & MASK64) >> n
def mul64(a,b):
    return (a * b) & MASK64
def to_short(x):
    x &= 0xFFFF
    return x if x < 0x8000 else x - 0x10000
def to_int32(x):
    x &= MASK32
    return x if x < 0x80000000 else x - 0x100000000

def rotate_S(value, shift):
    # value is signed short, shift 0..31
    # Java: shl-int v0, v1, v2; rsub v2,32; ushr v1,v2; or; int-to-short
    # v1 is short sign-extended to 32-bit int
    v_int = value & 0xFFFFFFFF  # sign extend via Python's & gives correct for negative?
    # For value=-21555 (0xABCD), Python value=-21555, &0xFFFFFFFF = 0xFFFFABCD = 4294945741, correct
    # For value=4660, & = 4660
    shl = (v_int << shift) & 0xFFFFFFFF
    r = 32 - shift
    ushr = (v_int & 0xFFFFFFFF) >> r
    res = (shl | ushr) & 0xFFFFFFFF
    return to_short(res & 0xFFFF)

def LMK(x):
    x = x & MASK64
    v = ushr64(x, 33) ^ x
    x = v & MASK64
    x = mul64(x, 7109453100751455733)
    v = ushr64(x, 28) ^ x
    x = v & MASK64
    c2 = (-3808689974395783757) & MASK64
    x = mul64(x, c2)
    x = ushr64(x, 32) & MASK64
    return to_signed64(x)

def NkWa(j):
    # Decompiled: short s = (short)(j &65535); short s2 = (short)((j>>>16)&65535);
    # short Oh = (short)(rotate_S(s+s2,9)+s); short s3 = (short)(s2 ^ s);
    # return ((rotate_S(s3,10) | (Oh<<16))<<16) | ((short)((rotate_S(s,13) ^ s3) ^ (s3<<5)));
    s = to_short(j & 0xFFFF)
    s2 = to_short((j >>16) & 0xFFFF)  # use arithmetic >>? In Java, (j>>>16) is logical, but j is long, >>>16 is logical, then &65535, then cast to short
    # For j as signed 64, j>>16 logical is (j &MASK64)>>16, then &0xFFFF
    j_u = j & MASK64
    s = to_short(j_u & 0xFFFF)
    s2 = to_short((j_u >>16) & 0xFFFF)
    Oh = to_short((rotate_S(to_short(s + s2), 9) + s) & 0xFFFF)
    s3 = to_short((s2 ^ s) & 0xFFFF)
    # Build as Java does: 32-bit int operations, then sign-extend to long
    # In Java: int tmp = (rotate(s3,10) | (Oh<<16)); tmp <<=16; tmp |= (short)((rotate(s,13) ^ s3) ^ (s3<<5)); return (long)tmp;
    r2 = rotate_S(s3, 10)
    # r2 | (Oh<<16) as 32-bit ints with sign extension
    r2_int = r2 & 0xFFFFFFFF
    Oh_int = Oh & 0xFFFFFFFF
    tmp = (r2_int | ((Oh_int <<16) & 0xFFFFFFFF)) & 0xFFFFFFFF
    tmp = (tmp <<16) & 0xFFFFFFFF
    r1 = rotate_S(s, 13)
    r1 = to_short((r1 ^ s3) & 0xFFFF)
    shl5 = ((s3 & 0xFFFFFFFF) <<5) & 0xFFFFFFFF
    r1b = to_short(((r1 & 0xFFFFFFFF) ^ shl5) & 0xFFFF)
    res_int = (tmp | (r1b & 0xFFFFFFFF)) & 0xFFFFFFFF
    res_signed32 = res_int if res_int < 0x80000000 else res_int - 0x100000000
    return res_signed32  # as Python int, will be sign-extended when used as long

def prng_step(idx, pool, state):
    new_state = NkWa(state)
    new_state_u = new_state & MASK64
    pool_idx = idx // 8191
    char_idx = idx % 8191
    if pool_idx <0 or pool_idx >= len(pool):
        pool_idx = 0
        if char_idx >= len(pool[0]):
            char_idx = char_idx % len(pool[0])
    elif char_idx >= len(pool[pool_idx]):
        char_idx = char_idx % len(pool[pool_idx])
    row = pool[pool_idx]
    c = row[char_idx] if char_idx < len(row) else '\x00'
    c_val = ord(c)
    c_long = (c_val & 0xFFFFFFFF) << 32
    res = (c_long ^ (new_state_u & MASK64)) & MASK64
    return to_signed64(res)

def decode_string(seed, pool):
    seed_u = seed & MASK64
    low32 = seed_u & 0xFFFFFFFF
    low_signed = to_signed64(low32)
    t0 = LMK(low_signed)
    t1 = NkWa(t0)
    t1_u = t1 & MASK64
    v3 = (t1_u >> 32) & 0xFFFF
    t2 = NkWa(t1)
    t2_u = t2 & MASK64
    tmp = (t2_u >> 16) & 0xFFFF0000
    seed_high = ushr64(seed_u, 32)
    combined = (seed_high ^ v3 ^ tmp) & MASK64
    combined_int = to_int32(combined & 0xFFFFFFFF)
    state = prng_step(combined_int, pool, t2)
    state_u = state & MASK64
    length = (state_u >> 32) & 0xFFFF
    chars = []
    for i in range(length):
        idx = combined_int + i + 1
        state = prng_step(idx, pool, state)
        state_u = state & MASK64
        c_val = (state_u >> 32) & 0xFFFF
        chars.append(chr(c_val & 0xFFFF))
    return ''.join(chars)

if __name__ == "__main__":
    txt = POOL_PATH.read_text(encoding='utf-8', errors='ignore')
    # pool file may contain newlines; the pool is one line, but if it was written with newline, strip
    lines = [l for l in txt.splitlines() if l.strip()!='Field:']
    # The pool file from get_pool2.py contains single string without newlines, but our earlier file may have header? Let's just take longest line
    if len(lines)>1:
        txt = max(lines, key=len)
    else:
        txt = txt.strip().replace('\r','').replace('\n','')
        # If file was written via cjk_pool.txt from get_pool2, it's one line, but we stripped newlines, need to re-read raw?
        # Actually cjk_pool.txt from get_pool2 is single line with pool, no header, so first method works
        pass
    # If still short, try cjk_pool_raw.bin
    if len(txt) < 4000:
        # fallback to raw
        try:
            raw = Path("cjk_pool_raw.bin").read_bytes()
            txt = raw.decode('utf-8', errors='ignore')
        except: pass
    pool = [txt]
    print(f"Loaded pool len {len(txt)}", flush=True)
    data = json.loads(Path(JSON_PATH).read_text(encoding='utf-8'))
    print(f"JSON entries: {len(data)}, decoded: {sum(1 for v in data.values() if v)}", flush=True)
    mismatches=0
    matches=0
    nulls=0
    out=[]
    for k, exp in data.items():
        seed=int(k)
        if exp is None:
            nulls+=1
            continue
        try:
            got=decode_string(seed, pool)
            if got==exp:
                matches+=1
            else:
                mismatches+=1
                out.append(f"MISMATCH {seed} exp {exp!r} got {got!r} len {len(exp)} vs {len(got)}")
        except Exception as e:
            import traceback; out.append(f"ERROR {seed} {e}\n{traceback.format_exc()}")
            mismatches+=1
    print(f"Matches {matches} Mismatches {mismatches} Nulls {nulls}", flush=True)
    if matches+mismatches:
        print(f"Rate {matches/(matches+mismatches):.2%}", flush=True)
    Path("replay_result.txt").write_text("\n".join(out[:50]) + f"\nMatches {matches} Mismatches {mismatches}", encoding='utf-8', errors='ignore')
    test_seed=-9154610674182
    exp=data.get(str(test_seed))
    got=decode_string(test_seed, pool)
    Path("single_test.txt").write_text(f"seed {test_seed}\nexp {exp!r}\ngot {got!r}\nlen exp {len(exp) if exp else 0} got {len(got)}\ngot raw {got.encode('unicode_escape').decode()!r}\n", encoding='utf-8', errors='ignore')
    print(f"Single test {test_seed}: exp {exp!r} got len {len(got)} first 50 {got[:50]!r}", flush=True)
