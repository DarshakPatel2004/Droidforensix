MASK64=(1<<64)-1
t2a = 0xFFFFFFFFFFFE3B6 & MASK64
t2b = 0xFFFE3B6 & MASK64
print(f"t2a {t2a:016x} low16 {t2a &0xFFFF:04x} high16 {(t2a>>16)&0xFFFF:04x} low32 {t2a &0xFFFFFFFF:08x}")
print(f"t2b {t2b:016x} low16 {t2b &0xFFFF:04x} high16 {(t2b>>16)&0xFFFF:04x} low32 {t2b &0xFFFFFFFF:08x}")
# Also for t1
t1 = 0xFFFFFFFFFFFEE96 & MASK64
print(f"t1 {t1:016x} low16 {t1 &0xFFFF:04x} high16 {(t1>>16)&0xFFFF:04x}")
