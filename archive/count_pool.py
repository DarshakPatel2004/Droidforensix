import pathlib, re
smali = pathlib.Path("smali_out/CZRR4ZREoGNpLeGZze.smali").read_text(encoding='utf-8', errors='ignore')
m = re.search(r'const-string v2, "(.*)"', smali)
if m:
    esc = m.group(1)
    # Count \u
    cnt = esc.count('\\u')
    print(f"smali esc count \\u {cnt} len esc {len(esc)}")
    # Decode
    txt = esc.encode('utf-8').decode('unicode_escape')
    print(f"decoded len {len(txt)}")
    # Also count via androguard
    from androguard.core.dex import DEX
    with open(r'D:\DroidForensix\uploads\44b10841-c0ac-4d21-8979-7227d154896f\rto_extracted\phase4_payload\installer_extracted\classes.dex','rb') as f:
        data=f.read()
    dex=DEX(data)
    s=dex.strings[3564].get_data()
    if isinstance(s, bytes):
        txt2=s.decode('utf-8', errors='ignore')
    else:
        txt2=s
    print(f"androguard len {len(txt2)}")
    # Compare
    print(f"smali==androguard {txt==txt2}")
    # Check first 10 chars
    print(f"smali first 5 {[hex(ord(c)) for c in txt[:5]]}")
    print(f"andro first 5 {[hex(ord(c)) for c in txt2[:5]]}")
