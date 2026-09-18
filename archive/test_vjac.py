MASK64=(1<<64)-1
def to_short(x): x&=0xFFFF; return x if x<0x8000 else x-0x10000
def rotate_S(s,i):
    s_int = s & 0xFFFFFFFF
    shl = (s_int << i) & 0xFFFFFFFF
    ushr = (s_int & 0xFFFFFFFF) >> (32 - i)
    res = (shl | ushr) & 0xFFFFFFFF
    return to_short(res & 0xFFFF)
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

t2 = 0xFFFE3B6
# Actually t2 as signed 64 is -117194? Let's use the value we printed: 0xFFFFFFFFFFFE3B6 = -117194? 
# But t2 as Python int -117194? Let's use the printed t2: ffffffffffffe3b6 as 64-bit sign-extended
# That's 0xFFFFFFFFFFFE3B6 = -117194? Let's compute
t2_val = 0xFFFFFFFFFFFE3B6
# Convert to signed 64
if t2_val & (1<<63):
    t2_val -= 1<<64
print(f"t2 {t2_val &MASK64:016x} {t2_val}")
v = NkWa(t2_val)
print(f"NkWa(t2) {v &MASK64:016x} high {(v &MASK64>>32)&0xFFFF:04x} {(v>>32)&0xFFFF if v>=0 else (v &MASK64>>32)&0xFFFF:04x}")
# Actually v is signed 32, as 64 it's sign-extended
v_u = v & MASK64
print(f"v_u {v_u:016x} high {(v_u>>32)&0xFFFF:04x} low {v_u &0xFFFFFFFF:08x}")
# For t2 = 0xFFFE3B6 as unsigned 32, what is NkWa?
t2_unsigned = 0xFFFE3B6
v2 = NkWa(t2_unsigned)
print(f"NkWa(0xFFFE3B6 unsigned) {v2 &MASK64:016x}")
