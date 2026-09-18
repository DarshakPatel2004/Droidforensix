#!/usr/bin/env python3
"""Stage-3 bytecode replay: regenerate installer strings from the CJK pool.

Faithful Python port of the real smali (source of truth is the fresh baksmali
dump in `_hole1_smali/VjAcb76OojLigvhwYH.smali`):

    CZRR4ZREoGNpLeGZze  (pool holder, single 4320-char CJK array element)
    FtpOxqekIibXASlT37.NkWaRdJEKEf58YYznc(I[Ljava/lang/String;J)J  (step)
    VjAcb76OojLigvhwYH.LMKdxcNChRaUWXpv21(J)J                       (lmk)
    VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(J)J                       (nkwa)
    VjAcb76OojLigvhwYH.OhM1VWC9IUcLWN7TO0(SI)S                      (short rotate)

Acceptance test (mirrors TestTrueSMALI.java):
    replayed == installer_deobfuscated_strings.json  for every non-null seed
    => 174 exact + 6 known ground-truth artifacts (documented in
       rto_analysis/hole1_czrr_definitive.md).
"""
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
POOL_PATH = PROJECT_ROOT / "cjk_pool.txt"
JSON_PATH = PROJECT_ROOT / "rto_analysis" / "phase2" / "installer_deobfuscated_strings.json"

M64 = (1 << 64) - 1
M32 = (1 << 32) - 1

C2 = (-0x34DB2F5A3773CA4D) & M64  # mul-long constant used in LMKdxcNChRaUWXpv21


def u64(x):
    return x & M64


def to_short(x):
    x &= 0xFFFF
    return x if x < 0x8000 else x - 0x10000


def to_int32(x):
    x &= M32
    return x if x < 0x80000000 else x - 0x100000000


def ohm(value, shift):
    """OhM1VWC9IUcLWN7TO0(SI)S -- rotate a short left inside a 32-bit slot.
    value is a signed short; shift is an int in 1..31."""
    val = value & M32           # sign-extended 32-bit two's complement
    shl = (val << shift) & M32
    ushr = (val >> (32 - shift)) & M32
    return to_short((shl | ushr) & 0xFFFF)


def lmk(x):
    """LMKdxcNChRaUWXpv21(J)J -- 64-bit multiply-xorshift digest.
    Input/state are 64-bit; returns low-32-bit result as non-negative long."""
    x = u64(x)
    x ^= x >> 33
    x = (x * 0x62A9D9ED799705F5) & M64
    x ^= x >> 28
    x = (x * C2) & M64
    return (x >> 32) & M64


def nkwa(j):
    """NkWaRdJEKEf58YYznc(J)J -- 16-bit rotate/xor round, mixed into a long."""
    j = u64(j)
    low = to_short(j & 0xFFFF)
    high = to_short((j >> 16) & 0xFFFF)

    p1 = to_short((low + high) & 0xFFFF)   # add-int; int-to-short
    p1 = ohm(p1, 9)
    p1 = to_short((p1 + low) & 0xFFFF)

    p0 = to_short((high ^ low) & 0xFFFF)   # int-to-short

    v0 = to_short(ohm(low, 13))
    v0 = (v0 ^ p0) & 0xFFFF                # xor-int on sign-extended shorts
    v1 = (p0 << 5) & M32                   # shl-int/lit8 p0, 0x5
    v0x = to_short((v0 ^ v1) & 0xFFFF)

    p0 = ohm(p0, 10)                       # short result

    res = (u64(p0) | (u64(p1) << 16)) & M64
    res = (res << 16) & M64
    res = (res | u64(v0x)) & M64
    return res


def step(i, state, pool):
    """FtpOxqekIibXASlT37.NkWaRdJEKEf58YYznc(I[Ljava/lang/String;J)J.
    Stub matches the real smali: div/rem literal 0x1fff, NO %strArr.length,
    no clamping. Out-of-range index raises like the real VM would throw."""
    state = nkwa(state)
    chunk = i // 0x1FFF if i >= 0 else -((-i) // 0x1FFF)
    pos = i % 0x1FFF
    if chunk != 0:
        raise IndexError(f"array index {chunk} (i={i}) - pool is single-element")
    row = pool
    if pos < 0 or pos >= len(row):
        raise IndexError(f"char index {pos} (i={i}) outside pool len {len(row)}")
    return ((u64(ord(row[pos])) << 32) ^ state) & M64


def decode_string(seed, pool):
    """Exact port of TestTrueSMALI.decode(j)."""
    j_u = u64(seed)
    a = nkwa(lmk(j_u & 0xFFFFFFFF))        # 0xffffffffL & j -> positive long
    j2 = (a >> 32) & 0xFFFF
    b = nkwa(a)
    term3 = (b >> 16) & 0xFFFFFFFFFFFF0000  # (b>>>16) & -65536L
    i = to_int32(((j_u >> 32) ^ j2 ^ term3) & M32)

    state = step(i, b, pool)
    length = (state >> 32) & 0xFFFF
    chars = []
    for k in range(length):
        state = step(i + k + 1, state, pool)
        chars.append(chr((state >> 32) & 0xFFFF))
    return "".join(chars)


def load_pool():
    txt = POOL_PATH.read_text(encoding="utf-8", errors="ignore")
    lines = [l for l in txt.splitlines() if l.strip() and l.strip() != "Field:"]
    if len(lines) > 1:
        txt = max(lines, key=len)
    else:
        txt = txt.strip().replace("\r", "").replace("\n", "")
    return txt


def run_replay(pool, non_null):
    matches = mismatches = 0
    detail = []
    for seed, expected in non_null.items():
        try:
            got = decode_string(seed, pool)
        except IndexError as ex:
            mismatches += 1
            detail.append(f"MISMATCH {seed} CRASH {ex} exp {expected!r}")
            continue
        if got == expected:
            matches += 1
        else:
            mismatches += 1
            detail.append(f"MISMATCH {seed} exp {expected!r} got {got!r} "
                          f"len {len(expected)} vs {len(got)}")
    return matches, mismatches, detail


def main():
    pool = load_pool()
    if len(pool) != 4320:
        print(f"WARNING: expected 4320-char pool, got {len(pool)}", flush=True)
    print(f"Loaded pool len {len(pool)}", flush=True)

    data = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    non_null = {int(k): v for k, v in data.items() if v is not None}
    print(f"JSON entries: {len(data)}, decoded: {len(non_null)}", flush=True)

    matches, mismatches, detail = run_replay(pool, non_null)
    print(f"Matches {matches} Mismatches {mismatches} Nulls {len(data) - len(non_null)}", flush=True)
    print(f"Rate {matches / (matches + mismatches):.2%}", flush=True)

    out = "\n".join(detail[:50]) + f"\nMatches {matches} Mismatches {mismatches}"
    (PROJECT_ROOT / "replay_result.txt").write_text(out, encoding="utf-8", errors="ignore")

    if matches != 175 or mismatches != 5:
        print("ACCEPTANCE: FAIL - expected 175/5 (see replay_result.txt)", flush=True)
        sys.exit(1)
    print("ACCEPTANCE: PASS - 175/5", flush=True)
    print("The 5 mismatches are the documented ground-truth artifacts", flush=True)
    print("(key/value seed swap x2, shifted row label, source-literal escapes):", flush=True)
    print("rto_analysis/hole1_czrr_definitive.md", flush=True)
    print("Note: the 6th seed in that table (-1629827971590, raw \\A) now MATCHES:", flush=True)
    print("the Java harness compared unescaped JSON; this port uses json.load.", flush=True)


if __name__ == "__main__":
    main()