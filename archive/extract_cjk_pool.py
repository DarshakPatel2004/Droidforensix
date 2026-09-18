from androguard.core.dex import DEX, EncodedArray
import logging
import struct
logging.disable(logging.CRITICAL)

# Read the DEX file into memory
with open(r'D:\DroidForensix\uploads\44b10841-c0ac-4d21-8979-7227d154896f\rto_extracted\phase4_payload\installer_extracted\classes.dex', 'rb') as f:
    data = f.read()

dex = DEX(data)

header = dex.header
map_off = header.map_off
print(f'Map offset: {map_off}')

# Read map size from the DEX raw data
map_size = struct.unpack('<I', data[map_off:map_off+4])[0]
print(f'Map size: {map_size}')

# Parse the map
pos = map_off + 4
cjk_pool_found = False
for i in range(map_size):
    item_type, unused, item_size, item_off = struct.unpack('<HHII', data[pos:pos+12])
    pos += 12
    if item_type == 0x100C:  # ENCODED_ARRAY_ITEM
        print(f'Found encoded array #{i} at offset {item_off}, size {item_size}')
        enc_arr = EncodedArray(dex, item_off)
        try:
            values = enc_arr.get_values()
            print(f'  Values count: {len(values)}')
            if len(values) > 0:
                print(f'  First value len: {len(values[0])}')
                print(f'  First value: {values[0][:200]}...' if len(values[0]) > 200 else f'  First value: {values[0]}')
                if len(values) > 1:
                    print(f'  Second value len: {len(values[1])}')
            if len(values) > 8000:  # CJK pool has 8191 chars per row
                print(f'  *** CJK POOL CANDIDATE! ***')
                with open('cjk_pool.txt', 'w', encoding='utf-8') as f:
                    for v in values:
                        f.write(v + '\n')
                print(f'  Written to cjk_pool.txt')
                cjk_pool_found = True
                break
        except Exception as e:
            print(f'  Error: {e}')

if not cjk_pool_found:
    print('CJK pool not found in encoded arrays')