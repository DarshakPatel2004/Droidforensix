import pathlib, re
pool = pathlib.Path('cjk_pool.txt').read_bytes().decode('utf-8', errors='ignore').strip().replace('\r','').replace('\n','')
lines = pathlib.Path('cjk_pool.txt').read_text(encoding='utf-8', errors='ignore').splitlines()
lines = [l for l in lines if len(l)>1000]
if lines:
    pool = max(lines, key=len)
print(f'pool len {len(pool)}')
escaped = ''.join(f'\\u{ord(c):04x}' for c in pool)
print(f'escaped len {len(escaped)}')
p = pathlib.Path('jadx_out/sources/defpackage/CZRR4ZREoGNpLeGZze.java')
txt = p.read_text(encoding='utf-8', errors='ignore')
old = re.search(r'public static final java\.lang\.String\[\] NkWaRdJEKEf58YYznc = \{.*?\};', txt, re.DOTALL)
if old:
    print(f'found old len {len(old.group(0))}')
    new = f'public static final java.lang.String[] NkWaRdJEKEf58YYznc = {{"{escaped}"}};'
    txt = txt[:old.start()] + new + txt[old.end():]
    p.write_text(txt, encoding='utf-8')
    print('patched')
else:
    print('not found')
