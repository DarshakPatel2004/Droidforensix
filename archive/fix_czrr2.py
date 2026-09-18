import pathlib, re
from androguard.core.dex import DEX
with open(r'D:\DroidForensix\uploads\44b10841-c0ac-4d21-8979-7227d154896f\rto_extracted\phase4_payload\installer_extracted\classes.dex','rb') as f:
    data=f.read()
dex=DEX(data)
# Find pool string at idx 3564
s = dex.strings[3564].get_data()
if isinstance(s, bytes):
    txt = s.decode('utf-8', errors='ignore')
else:
    txt = s
print(f"pool len {len(txt)}")
# Also check via manual parsing for 4320
import struct
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
print(f"uleb len {result} pos {pos} off {off}")
raw = data[pos:pos+result*3]  # approximate
# Actually need to find null terminator
end = data.find(b'\x00', pos)
raw2 = data[pos:end]
print(f"raw2 len {len(raw2)}")
try:
    txt2 = raw2.decode('utf-8')
    print(f"txt2 len {len(txt2)}")
except:
    txt2 = raw2.decode('utf-8', errors='ignore')
    print(f"txt2 len {len(txt2)}")

# Use txt (from androguard) as pool, but ensure no newline
pool = txt.strip().replace('\r','').replace('\n','')
print(f"final pool len {len(pool)}")
escaped = ''.join(f'\\u{ord(c):04x}' for c in pool)
print(f"escaped len {len(escaped)}")
p = pathlib.Path('jadx_out/sources/defpackage/CZRR4ZREoGNpLeGZze.java')
txt2 = p.read_text(encoding='utf-8', errors='ignore')
old = re.search(r'public static final java\.lang\.String\[\] NkWaRdJEKEf58YYznc = \{.*?\};', txt2, re.DOTALL)
if old:
    new = f'public static final java.lang.String[] NkWaRdJEKEf58YYznc = {{"{escaped}"}};'
    txt2 = txt2[:old.start()] + new + txt2[old.end():]
    p.write_text(txt2, encoding='utf-8')
    print('patched2')
