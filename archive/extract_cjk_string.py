from androguard.core.dex import DEX
import logging
logging.disable(logging.CRITICAL)
with open(r'D:\DroidForensix\uploads\44b10841-c0ac-4d21-8979-7227d154896f\rto_extracted\phase4_payload\installer_extracted\classes.dex','rb') as f:
    data=f.read()
dex=DEX(data)
longs=[]
for idx,s in enumerate(dex.strings):
    try:
        raw=s.get_data()
        if isinstance(raw, bytes):
            try:
                txt=raw.decode('utf-8')
            except:
                txt=raw.decode('utf-8', errors='ignore')
            tl=len(txt)
            rl=len(raw)
        else:
            txt=raw
            tl=len(txt)
            rl=len(txt.encode('utf-8'))
        if tl>1000 or rl>3000:
            longs.append((idx, rl, tl, txt[:50].replace('\n','\\n')))
            print(f"idx {idx} raw_len {rl} txt_len {tl} {txt[:80]!r}")
    except Exception as e:
        print(f"err {idx}: {e}")
        continue
print(f"found {len(longs)} long strings")
# check dex.strings access via dex.get_strings?
# also check via dex.strings vs dex.get_strings
with open('long_strings.txt','w',encoding='utf-8',errors='ignore') as out:
    for idx, rl, tl, pref in longs:
        out.write(f"{idx} {rl} {tl} {pref}\n")
