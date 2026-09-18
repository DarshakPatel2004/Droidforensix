import struct
with open(r'D:\DroidForensix\uploads\44b10841-c0ac-4d21-8979-7227d154896f\rto_extracted\phase4_payload\installer_extracted\classes.dex','rb') as f:
    data=f.read()
# Find string id for pool: look for string with len 4320
# Need to find its index
# Parse header to get string_ids
string_ids_size = struct.unpack('<I', data[0x38:0x3C])[0]
string_ids_off = struct.unpack('<I', data[0x3C:0x40])[0]
pool_idx=None
for i in range(string_ids_size):
    off = struct.unpack('<I', data[string_ids_off + i*4 : string_ids_off + i*4+4])[0]
    # parse uleb128
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
    if result==4320:
        # check if raw bytes look like CJK (mostly 0xE0-0xEF)
        raw=data[pos:pos+20]
        if raw[0] & 0xF0 == 0xE0:
            print(f"Found pool idx {i} strlen {result} off {off} raw0 {raw[:20].hex()}")
            pool_idx=i
            break
print(f"pool_idx {pool_idx}")

# Now find class LCZRR4ZREoGNpLeGZze
# Find class_defs
class_defs_size = struct.unpack('<I', data[0x60:0x64])[0]
class_defs_off = struct.unpack('<I', data[0x64:0x68])[0]
print(f"class_defs {class_defs_size} off {class_defs_off}")
for i in range(class_defs_size):
    off = class_defs_off + i*32
    class_idx, access, super_idx, interfaces_off, source_idx, annotations_off, class_data_off, static_values_off = struct.unpack('<8I', data[off:off+32])
    # get class name via type_ids
    type_ids_off = struct.unpack('<I', data[0x44:0x48])[0]
    # type id is index to string? Actually type_ids are 4 bytes each, value is string idx
    # class_idx is type index
    type_val = struct.unpack('<I', data[type_ids_off + class_idx*4 : type_ids_off + class_idx*4+4])[0]
    # string for type
    # string pool lookup
    # For type "LCZRR4ZREoGNpLeGZze;" need to find its string
    # Instead just check via androguard's known index 20, but we need to find which class def corresponds
    # Let's just brute: check all classes via androguard's list but we can also just search for class_data that contains pool_idx reference
    pass

# Alternative: directly search for code that contains const-string with pool_idx
# Search for bytes 0x1A (const-string) with string idx = pool_idx (little endian 16-bit)
if pool_idx is not None:
    target = struct.pack('<H', pool_idx)
    # const-string encoding: opcode 0x1A, then 8-bit reg, then 16-bit string idx
    # So pattern: 0x1A, reg, low, high
    for pos in range(len(data)-4):
        if data[pos]==0x1A and data[pos+2]==target[0] and data[pos+3]==target[1]:
            print(f"Found const-string at file offset {hex(pos)} reg {data[pos+1]} string idx {pool_idx}")
            # dump surrounding 20 bytes
            print(data[pos-10:pos+20].hex())
            # Find which method this belongs to: look for code_item boundaries?
            # We can search for class_data that points to code containing this offset
            # For now just print
            break
