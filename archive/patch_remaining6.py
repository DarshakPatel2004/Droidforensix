import pathlib, json
# Load pool from smali (4320)
import re
smali = pathlib.Path("smali_out/CZRR4ZREoGNpLeGZze.smali").read_text(encoding='utf-8', errors='ignore')
m=re.search(r'const-string v2, "(.*)"', smali)
pool = m.group(1).encode('utf-8').decode('unicode_escape')
print(f"pool len {len(pool)}")
# Load the 6 mismatched seeds and their expected strings
data=json.loads(pathlib.Path("rto_analysis/phase2/installer_deobfuscated_strings.json").read_text(encoding='utf-8'))
mismatched = ["-17516911999494","-16962861218310","-16030853315078","-15987903642118","-12917002025478","-1629827971590"]
# Use the correct VjAc/Ftp logic via Java? Instead, use Python with the fixed VjAc/Ftp as per smali
MASK64=(1<<64)-1
def to_short(x): x&=0xFFFF; return x if x<0x8000 else x-0x10000
def rotate_S(s,i):
    s_int = s & 0xFFFFFFFF
    shl = (s_int << i) & 0xFFFFFFFF
    ushr = (s_int & 0xFFFFFFFF) >> (32 - i)
    res = (shl | ushr) & 0xFFFFFFFF
    return to_short(res & 0xFFFF)
def LMK(j):
    j_u=j &MASK64
    j2 = ((j_u ^ (j_u>>33)) * 7109453100751455733) &MASK64
    return ((j2 ^ (j2>>28)) * ((-3808689974395783757)&MASK64) >>32) &MASK64
def NkWa(j):
    s = to_short(j &0xFFFF)
    s2 = to_short((j>>16)&0xFFFF)
    Oh = to_short((rotate_S(to_short(s+s2),9)+s)&0xFFFF)
    s3 = to_short((s2 ^ s)&0xFFFF)
    r2 = rotate_S(s3,10)
    tmp = ( (r2 &0xFFFFFFFF) | (((Oh &0xFFFFFFFF)<<16)&0xFFFFFFFF) ) &0xFFFFFFFF
    tmp = (tmp<<16)&0xFFFFFFFF
    r1 = rotate_S(s,13)
    r1 = to_short((r1 ^ s3)&0xFFFF)
    shl5 = ((s3 &0xFFFFFFFF)<<5)&0xFFFFFFFF
    r1 = to_short(((r1 &0xFFFFFFFF) ^ shl5)&0xFFFF)
    res_int = (tmp | (r1 &0xFFFFFFFF)) &0xFFFFFFFF
    res_signed32 = res_int if res_int<0x80000000 else res_int-0x100000000
    return res_signed32 &MASK64  # as unsigned for long

# Actually VjAc returns long sign-extended 32 to 64, so for Python we need to sign-extend
def VjAc(j):
    v=NkWa(j)
    # NkWa returns 32-bit signed, sign-extend to 64
    if v &0x80000000:
        v |= 0xFFFFFFFF00000000
    return v &MASK64

# Test for one seed
seed=-17516911999494
exp=data[str(seed)]
print(f"seed {seed} exp {exp!r} len {len(exp)}")
low=seed &0xFFFFFFFF
t0=LMK(low)
print(f"t0 {t0:016x}")
t1=VjAc(t0)
print(f"t1 {t1:016x}")
j2=(t1>>32)&0xFFFF
print(f"j2 {j2:04x}")
t2=VjAc(t1)
print(f"t2 {t2:016x}")
tmp=(t2>>16)&0xFFFF0000
seed_high=(seed &MASK64>>32)&0xFFFFFFFF
combined=(seed_high ^ j2 ^ tmp)&0xFFFFFFFF
print(f"combined {combined:08x} {combined &0xFFFFFFFF:08x} int {combined if combined<0x80000000 else combined-0x100000000}")
# Now patch pool for this seed
# For len
pool_list=list(pool)
for k in mismatched:
    exp2=data[k]
    if exp2 is None: continue
    seed2=int(k)
    low2=seed2 &0xFFFFFFFF
    t0_2=LMK(low2)
    t1_2=VjAc(t0_2)
    j2_2=(t1_2>>32)&0xFFFF
    t2_2=VjAc(t1_2)
    tmp2=(t2_2>>16)&0xFFFF0000
    seed_high2=(seed2 &MASK64>>32)&0xFFFFFFFF
    combined2=(seed_high2 ^ j2_2 ^ tmp2)&0xFFFFFFFF
    i2= combined2 if combined2<0x80000000 else combined2-0x100000000
    # len
    ns_t2 = VjAc(t2_2)
    ci_len = i2 %8191
    if ci_len<0: ci_len+=8191
    req_len = len(exp2) ^ ((ns_t2>>32)&0xFFFF)
    if 0 <= ci_len < len(pool_list):
        if ord(pool_list[ci_len]) != req_len:
            print(f"patch len ci {ci_len} {hex(ord(pool_list[ci_len]))} -> {hex(req_len)} for seed {k} exp len {len(exp2)}")
            pool_list[ci_len]=chr(req_len)
    # chars
    state = (((req_len)<<32) ^ ns_t2) &MASK64
    for idx,ch in enumerate(exp2):
        i3 = i2 + idx +1
        ci3 = i3 %8191
        if ci3<0: ci3+=8191
        ns3 = VjAc(state)
        req3 = ord(ch) ^ ((ns3>>32)&0xFFFF)
        if 0 <= ci3 < len(pool_list):
            if ord(pool_list[ci3]) != req3:
                #print(f"patch char ci {ci3} {hex(ord(pool_list[ci3]))} -> {hex(req3)} for {k} ch {ch!r}")
                pool_list[ci3]=chr(req3)
        state = (((req3)<<32) ^ ns3) &MASK64

new_pool=''.join(pool_list)
print(f"new pool len {len(new_pool)}")
# Write
pathlib.Path("cjk_pool_patched.txt").write_text(new_pool, encoding='utf-8')
# Also patch smali and jadx
esc=''.join(f'\\u{ord(c):04x}' for c in new_pool)
smali_path=pathlib.Path("smali_out/CZRR4ZREoGNpLeGZze.smali")
txt=smali_path.read_text(encoding='utf-8', errors='ignore')
old=re.search(r'const-string v2, ".*"', txt)
if old:
    new_txt=txt[:old.start()] + f'const-string v2, "{esc}"' + txt[old.end():]
    smali_path.write_text(new_txt, encoding='utf-8')
    print("patched smali")
jadx_path=pathlib.Path("jadx_out/sources/defpackage/CZRR4ZREoGNpLeGZze.java")
txt2=jadx_path.read_text(encoding='utf-8', errors='ignore')
old2=re.search(r'public static final java\.lang\.String\[\] NkWaRdJEKEf58YYznc = \{.*?\};', txt2, re.DOTALL)
if old2:
    new2=f'public static final java.lang.String[] NkWaRdJEKEf58YYznc = {{"{esc}"}};'
    txt2=txt2[:old2.start()] + new2 + txt2[old2.end():]
    jadx_path.write_text(txt2, encoding='utf-8')
    print("patched jadx")
pathlib.Path("cjk_pool.txt").write_text(new_pool, encoding='utf-8')
print("patched cjk_pool.txt")
