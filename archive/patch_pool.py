import pathlib, re
smali_path = pathlib.Path("smali_out/CZRR4ZREoGNpLeGZze.smali")
txt = smali_path.read_text(encoding='utf-8', errors='ignore')
m = re.search(r'const-string v2, "(.*)"', txt)
if m:
    esc = m.group(1)
    # Decode escapes
    pool = esc.encode('utf-8').decode('unicode_escape')
    print(f"original pool len {len(pool)}")
    # Check char at 2131
    # Use ord only, not repr
    print(f"pool[2131] {ord(pool[2131]):04x}")
    lst = list(pool)
    lst[2131] = chr(0x4FB5)
    new_pool = ''.join(lst)
    print(f"new pool[2131] {ord(new_pool[2131]):04x}")
    # Escape for smali: smali uses \uXXXX for non-ascii, but we can just write the raw string with escapes
    # The smali file uses \uXXXX escapes, we need to re-escape
    escaped = ''.join(f'\\u{ord(c):04x}' if ord(c) > 127 or c in ['\"', '\\'] else c for c in new_pool)
    # Replace in smali
    new_txt = txt[:m.start(1)] + escaped + txt[m.end(1):]
    smali_path.write_text(new_txt, encoding='utf-8')
    print("patched smali")
    # Also need to update cjk_pool.txt for our Java tests
    pathlib.Path("cjk_pool.txt").write_text(new_pool, encoding='utf-8')
    print("updated cjk_pool.txt")
else:
    print("not found")
