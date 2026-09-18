import pathlib, re
smali = pathlib.Path("smali_out/CZRR4ZREoGNpLeGZze.smali").read_text(encoding='utf-8', errors='ignore')
m = re.search(r'const-string v2, "(.*)"', smali)
if m:
    esc = m.group(1)
    # esc contains \uXXXX sequences, need to decode
    # Python's unicode_escape
    txt = esc.encode('utf-8').decode('unicode_escape')
    print(f"smali pool len {len(txt)}")
    # Compare with cjk_pool.txt
    pool2 = pathlib.Path("cjk_pool.txt").read_bytes().decode('utf-8', errors='ignore').strip().replace('\r','').replace('\n','')
    # For cjk_pool.txt, we need to handle reading correctly
    raw = pathlib.Path("cjk_pool.txt").read_bytes()
    # The file was written with 4321, but smali is 4320, check
    print(f"cjk_pool len {len(pool2)}")
    print(f"smali first 20 {txt[:20]!r}")
    print(f"pool2 first 20 {pool2[:20]!r}")
    print(f"match {txt==pool2}")
    # Write smali pool to file for Java
    pathlib.Path("smali_pool.txt").write_text(txt, encoding='utf-8')
    print("written smali_pool.txt")
else:
    print("not found")
