import pathlib

# Load pool from smali (4320)
import re
smali = pathlib.Path("smali_out/CZRR4ZREoGNpLeGZze.smali").read_text(encoding='utf-8', errors='ignore')
m=re.search(r'const-string v2, "(.*)"', smali)
esc=m.group(1)
pool = esc.encode('utf-8').decode('unicode_escape')
print(f"original pool len {len(pool)}")
# Patch the 6 mismatched indices
# From TestDebug3, we have for the 6 seeds:
# -17516 i 4078 req 4fbc pool 4fba -> need 4fbc
# -16962 i 3949 req 4fbc pool 4f84 -> need 4fbc
# -16030 i 3732 req 4fbc pool 4fbe -> need 4fbc
# -15987 i 3722 req 4fbc pool 4fbc -> already match for len, but char0 mismatch
# Actually for -15987, len matched, but char0 at 3723 pool 76d8 vs req 76e1
# Let's just patch all required from the 6 seeds by recomputing via Java logic
# Use the Java to compute required pool for those 6

# Instead, just patch the pool at those indices to the required values we computed
# From previous run:
# more_info at 4078: need 4fbc, have 4fba -> patch 4078 to 4fbc
# bug_fixes at 3949: need 4fbc, have 4f84 -> patch 3949 to 4fbc
# Novedades at 3732: need 4fbc, have 4fbe -> patch 3732 to 4fbc
# whats_new at 3722: len already match, but char0 at 3723 need 76e1 vs 76d8 -> patch 3723 to 76e1
# For the long string and \A, they already matched for len and first char, so no need

# Let's patch those 4
patches = {
    4078: 0x4fbc,
    3949: 0x4fbc,
    3732: 0x4fbc,
    3723: 0x76e1,
    # Also need to patch the char at 3723 for whats_new's first char
    # For whats_new, i=3722, char0 at 3723, req 76e1, actual 76d8
    # For more_info, need also patch 4079 for its first char 'm' ?
    # Let's compute all required for those 6 via the Java solver we already have
    # For now, just patch these 4 and test
}
lst=list(pool)
for idx, val in patches.items():
    if 0 <= idx < len(lst):
        lst[idx]=chr(val)
        print(f"patched {idx} to {hex(val)}")
new_pool=''.join(lst)
print(f"new pool len {len(new_pool)}")
# Write to cjk_pool.txt and also patch the smali and the CZRR Java
pathlib.Path("cjk_pool.txt").write_text(new_pool, encoding='utf-8')
print("written cjk_pool.txt")
# Also patch the smali file
smali_path = pathlib.Path("smali_out/CZRR4ZREoGNpLeGZze.smali")
txt = smali_path.read_text(encoding='utf-8', errors='ignore')
# Replace the const-string line with new pool
escaped = ''.join(f'\\u{ord(c):04x}' for c in new_pool)
old = re.search(r'const-string v2, ".*"', txt)
if old:
    new_txt = txt[:old.start()] + f'const-string v2, "{escaped}"' + txt[old.end():]
    smali_path.write_text(new_txt, encoding='utf-8')
    print("patched smali")
# Also patch the jadx CZRR Java
jadx_path = pathlib.Path("jadx_out/sources/defpackage/CZRR4ZREoGNpLeGZze.java")
txt2 = jadx_path.read_text(encoding='utf-8', errors='ignore')
old2 = re.search(r'public static final java\.lang\.String\[\] NkWaRdJEKEf58YYznc = \{.*?\};', txt2, re.DOTALL)
if old2:
    new2 = f'public static final java.lang.String[] NkWaRdJEKEf58YYznc = {{"{escaped}"}};'
    txt2 = txt2[:old2.start()] + new2 + txt2[old2.end():]
    jadx_path.write_text(txt2, encoding='utf-8')
    print("patched jadx")
