"""Quick test for ELF string deobfuscation."""
import struct
from backend.elf_analyzer import ELFBreaker


def make_elf64():
    e_ident = b'\x7fELF' + bytes([2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    e_type = struct.pack('<H', 2)
    e_machine = struct.pack('<H', 0x28)
    e_version = struct.pack('<I', 1)
    e_entry = struct.pack('<Q', 0x1000)
    zeros = struct.pack('<Q', 0)
    e_flags = struct.pack('<I', 0)
    e_ehsize = struct.pack('<H', 64)
    e_zero = struct.pack('<H', 0)
    return (e_ident + e_type + e_machine + e_version + e_entry +
            zeros + zeros + e_flags + e_ehsize + e_zero + e_zero + e_zero + e_zero + e_zero)


# Use keys that produce NON-printable bytes (0x80-0xFF range) so they look obfuscated
KEY1 = 0xC3
KEY2 = 0x8F
SUB_KEY = 0x4E

obfuscated = bytes(b ^ KEY1 for b in b'http://malware.example.com/payload')
high_entropy = bytes(b ^ KEY2 for b in b'192.168.1.1:8080/shell')
sub_cipher = bytes((b - SUB_KEY) & 0xFF for b in b'https://c2.malware.cc/gate')

# Use realistic padding (noise, not nulls)
import random
random.seed(42)
noise = bytes([random.randint(0, 255) for _ in range(256)])

content = make_elf64() + noise + obfuscated + noise + high_entropy + noise + sub_cipher

breaker = ELFBreaker('test.so', content)

# Debug the raw scan directly
print('Debug raw scan:')
for i in range(len(content) - 32):
    chunk = content[i:i + 32]
    ascii_r = sum(1 for b in chunk if 0x20 <= b <= 0x7e) / len(chunk)
    null_r = sum(1 for b in chunk if b == 0) / len(chunk)
    if ascii_r < 0.3 and null_r < 0.4:
        ent = breaker._compute_entropy(chunk)
        if 5.0 <= ent <= 7.8:
            print(f'  @0x{i:x} ent={ent:.2f} ascii={ascii_r:.2f} null={null_r:.2f}')

print()
print('Check at offset of obfuscated data (0x140 = 320):')
chunk = content[320:352]
print(f'  ascii_r={sum(1 for b in chunk if 0x20 <= b <= 0x7e)/len(chunk):.2f}')
print(f'  null_r={sum(1 for b in chunk if b==0)/len(chunk):.2f}')
print(f'  ent={breaker._compute_entropy(chunk):.2f}')

candidates = breaker._find_obfuscated_arrays()
print(f'\nCandidates found: {len(candidates)}')
for i, (offset, data) in enumerate(candidates[:15]):
    ent = breaker._compute_entropy(data)
    ascii_r = sum(1 for b in data if 0x20 <= b <= 0x7e) / len(data)
    print(f'  [{i}] @0x{offset:x} len={len(data)} ent={ent:.2f} ascii={ascii_r:.2f}')
if len(candidates) > 15:
    print(f'  ... ({len(candidates) - 15} more)')

# Test XOR brute force
print()
print('Direct XOR test (KEY1=0xC3):')
decoded = bytes(b ^ KEY1 for b in obfuscated)
print(f'  score={breaker._score_readable(decoded):.2f} -> "{decoded.decode("ascii", errors="ignore")}"')

print('Direct XOR test (KEY2=0x8F):')
decoded2 = bytes(b ^ KEY2 for b in high_entropy)
print(f'  score={breaker._score_readable(decoded2):.2f} -> "{decoded2.decode("ascii", errors="ignore")}"')

print('Direct SUB test (key=0x4E):')
decoded3 = bytes((b - SUB_KEY) & 0xFF for b in sub_cipher)
print(f'  score={breaker._score_readable(decoded3):.2f} -> "{decoded3.decode("ascii", errors="ignore")}"')

result = breaker.analyze()
deob = result.get('deobfuscated_strings', [])
print(f'\nDeobfuscated strings found: {len(deob)}')
for d in deob:
    print(f'  [{d["technique"]}] key={d.get("key","?")} -> "{d["decoded"][:80]}"')

print()
print(f'Risk score: {result["risk_score"]}')
print(f'Suspicious strings: {len(result.get("suspicious_strings", []))}')
