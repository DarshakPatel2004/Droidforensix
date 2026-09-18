from androguard.core.dex import DEX
import logging
logging.disable(logging.CRITICAL)
with open(r'D:\DroidForensix\uploads\44b10841-c0ac-4d21-8979-7227d154896f\rto_extracted\phase4_payload\installer_extracted\classes.dex','rb') as f:
    data=f.read()
dex=DEX(data)
for idx,s in enumerate(dex.strings):
    raw=s.get_data()
    if isinstance(raw, bytes):
        rl=len(raw)
        if rl>8000:
            print(f"idx {idx} raw_len {rl}")
            # decode MUTF-8: use utf-8 with surrogatepass
            try:
                txt=raw.decode('utf-8')
            except:
                txt=raw.decode('utf-8', errors='ignore')
            print(f"txt_len {len(txt)}")
            open('cjk_pool.txt','w',encoding='utf-8',errors='ignore').write(txt)
            print("written txt_len",len(txt))
            open('cjk_pool_raw.bin','wb').write(raw)
            print("written raw")
            break
