import pathlib, re, struct
from androguard.core.dex import DEX
with open(r'D:\DroidForensix\uploads\44b10841-c0ac-4d21-8979-7227d154896f\rto_extracted\phase4_payload\installer_extracted\classes.dex','rb') as f:
    data=f.read()
# manual parse for idx 3564
string_ids_size = struct.unpack('<I', data[0x38:0x3C])[0]
string_ids_off = struct.unpack('<I', data[0x3C:0x40])[0]
off = struct.unpack('<I', data[string_ids_off + 3564*4 : string_ids_off + 3564*4+4])[0]
pos=off
result=0
shift=0
while True:
    b=data[pos]
    result |= (b & 0x7F) << shift
    pos+=1
    if (b & 0x80)==0:
        break
    shift+=7
print(f"uleb {result}")
end = data.find(b'\x00', pos)
raw = data[pos:end]
txt = raw.decode('utf-8', errors='ignore')
print(f"txt len {len(txt)} raw len {len(raw)}")
pool = txt
# patch
escaped = ''.join(f'\\u{ord(c):04x}' for c in pool)
p = pathlib.Path('jadx_out/sources/defpackage/CZRR4ZREoGNpLeGZze.java')
txt2 = p.read_text(encoding='utf-8', errors='ignore')
old = re.search(r'public static final java\.lang\.String\[\] NkWaRdJEKEf58YYznc = \{.*?\};', txt2, re.DOTALL)
if old:
    new = f'public static final java.lang.String[] NkWaRdJEKEf58YYznc = {{"{escaped}"}};'
    txt2 = txt2[:old.start()] + new + txt2[old.end():]
    p.write_text(txt2, encoding='utf-8')
    print('patched 4320')
