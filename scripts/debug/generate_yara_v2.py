import json, os, re, collections, base64
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
WORK_DIR = str(BASE_DIR / "analysis" / "work")
OUTPUT = str(BASE_DIR / "analysis" / "yara_rules.yar")
META = str(BASE_DIR / "sample_metadata.csv")

families = {}
with open(META, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith("sample_name"):
            continue
        parts = line.split(",")
        if len(parts) >= 5:
            sha = parts[1]
            family = parts[3]
            families[sha] = family

all_encodings = []
all_payloads = []
all_c2 = []
sample_count = 0

for d in os.listdir(WORK_DIR):
    dpath = os.path.join(WORK_DIR, d)
    if not os.path.isdir(dpath):
        continue

    sha = d
    family = families.get(sha, "unknown")

    # Read step3 encodings
    epath = os.path.join(dpath, "step3_encodings.json")
    if os.path.isfile(epath):
        try:
            with open(epath, "r", encoding="utf-8") as f:
                data = json.load(f)
            for e in data.get("encodings", []):
                e["_sample_id"] = sha
                e["_family"] = family
                all_encodings.append(e)
        except:
            pass

    # Read step4 payloads
    ppath = os.path.join(dpath, "step4_payloads.json")
    if os.path.isfile(ppath):
        try:
            with open(ppath, "r", encoding="utf-8") as f:
                data = json.load(f)
            for p in data.get("payloads", []):
                p["_sample_id"] = sha
                p["_family"] = family
                all_payloads.append(p)
        except:
            pass

    # Read step5 c2s
    cpath = os.path.join(dpath, "step5_c2s.json")
    if os.path.isfile(cpath):
        try:
            with open(cpath, "r", encoding="utf-8") as f:
                data = json.load(f)
            for c in data.get("c2_infrastructure", []):
                c["_sample_id"] = sha
                c["_family"] = family
                all_c2.append(c)
        except:
            pass

    sample_count += 1

print(f"Samples: {sample_count}")
print(f"Encodings: {len(all_encodings)}")
print(f"Payloads: {len(all_payloads)}")
print(f"C2 entries: {len(all_c2)}")

# Collect patterns
xor_patterns = collections.defaultdict(list)
base64_patterns = []
payload_magic_patterns = collections.defaultdict(list)
c2_domain_patterns = collections.defaultdict(list)

for e in all_encodings:
    etype = e.get("type", "").lower()
    orig = e.get("original_string", "")
    key = e.get("xor_key", None)
    conf = e.get("confidence", 0)
    family = e.get("_family", "unknown")
    sid = e.get("_sample_id", "")
    entropy = e.get("entropy", 0)

    if etype == "xor" and key is not None and isinstance(key, int) and len(orig) > 4:
        xor_patterns[key].append((orig, family, sid, entropy, conf))

    if etype == "base64" and len(orig) > 8:
        base64_patterns.append((orig, family, sid))

for p in all_payloads:
    content = p.get("decoded_content", "")
    magic = p.get("magic_bytes", []) or []
    family = p.get("_family", "unknown")
    sid = p.get("_sample_id", "")

    if isinstance(magic, str):
        magic = [magic]
    for m in magic:
        if isinstance(m, str) and len(m) >= 4:
            payload_magic_patterns[m].append((content[:64], family, sid))

    if content and len(content) > 32:
        pass

for c in all_c2:
    domain = c.get("domain", "")
    raw_url = c.get("raw_url", "")
    family = c.get("_family", "unknown")
    sid = c.get("_sample_id", "")

    if domain and domain.count(".") >= 1 and not domain.startswith("%"):
        parts = domain.split(".")
        reg_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain
        c2_domain_patterns[reg_domain].append((domain, family, sid))

rules = []

header = f"""/*
 * DroidForensix - YARA Detection Rules
 * Generated from Android malware analysis pipeline results
 * 
 * Date: 2026-06-16
 * Samples analyzed: {sample_count}
 * Encodings found: {len(all_encodings)}
 * Payloads decoded: {len(all_payloads)}
 * C2 indicators: {len(all_c2)}
 *
 * These rules detect patterns found in analyzed APK samples
 * including XOR-encoded strings, base64-encoded payloads,
 * decoded payload magic bytes, and C2 infrastructure patterns.
 */

"""

rules.append(header)

# --- XOR Key Rules ---
for key in sorted(xor_patterns.keys()):
    entries = xor_patterns[key]
    families_set = set(e[1] for e in entries)
    samples_set = set(e[3] for e in entries)
    family_name = "multi-family" if len(families_set) > 1 else families_set.pop() if families_set else "unknown"

    hex_strings = []
    for orig, fam, sid, ent, conf in entries[:12]:
        raw = orig.encode("utf-8", errors="replace")
        hex_part = raw[:16].hex()
        if len(hex_part) >= 8:
            hex_strings.append(hex_part)

    hex_strings = list(set(hex_strings))
    if not hex_strings:
        continue

    rule_name = "XOR_Key_%d_%s" % (key, re.sub(r'[^a-zA-Z0-9]', '_', family_name[:30]))
    rule_name = re.sub(r'_+', '_', rule_name).strip('_')

    r = []
    r.append(f"rule {rule_name} {{")
    r.append("    meta:")
    r.append(f'        description = "XOR key {key} encoded strings found in {family_name}"')
    r.append('        author = "DroidForensix Pipeline"')
    r.append('        date = "2026-06-16"')
    r.append(f'        sample_count = "{len(samples_set)}"')
    r.append(f'        family = "{family_name}"')
    r.append(f'        xor_key = "{key}"')
    r.append('        confidence = "high"')
    r.append("")
    r.append("    strings:")

    for i, h in enumerate(hex_strings):
        h_limited = h[:40]
        fmt = " ".join(h_limited[j:j+2] for j in range(0, len(h_limited), 2))
        r.append(f'        $xor_{i} = {{ {fmt} }}')

    r.append("")
    r.append("    condition:")
    r.append(f"        uint16(0) == {key} or any of them")
    r.append("}")
    r.append("")
    rules.append("\n".join(r))

# --- Payload Magic Byte Rules ---
for magic, entries in sorted(payload_magic_patterns.items()):
    families_set = set(e[1] for e in entries)
    samples_set = set(e[2] for e in entries)
    family_name = "multi-family" if len(families_set) > 1 else families_set.pop() if families_set else "unknown"

    rule_name = "Payload_Magic_%s" % re.sub(r'[^a-zA-Z0-9]', '_', magic[:20])
    rule_name = re.sub(r'_+', '_', rule_name).strip('_')

    r = []
    r.append(f"rule {rule_name} {{")
    r.append("    meta:")
    r.append(f'        description = "Decoded payload with magic bytes {magic}"')
    r.append('        author = "DroidForensix Pipeline"')
    r.append('        date = "2026-06-16"')
    r.append(f'        sample_count = "{len(samples_set)}"')
    r.append(f'        family = "{family_name}"')
    r.append(f'        magic_bytes = "{magic}"')
    r.append('        confidence = "high"')
    r.append("")
    r.append("    strings:")

    try:
        mb = int(magic, 16)
        h = format(mb, 'x')
        if len(h) % 2:
            h = "0" + h
        fmt = " ".join(h[j:j+2] for j in range(0, len(h), 2))
        r.append(f'        $magic = {{ {fmt} }}')
    except:
        r.append(f'        $magic = "{{ {magic} }}"')

    r.append("")
    r.append("    condition:")
    r.append("        $magic")
    r.append("}")
    r.append("")
    rules.append("\n".join(r))

# --- C2 Domain Rules ---
for domain in sorted(c2_domain_patterns.keys()):
    entries = c2_domain_patterns[domain]
    families_set = set(e[1] for e in entries)
    samples_set = set(e[2] for e in entries)
    family_name = "multi-family" if len(families_set) > 1 else families_set.pop() if families_set else "unknown"

    d_clean = domain.replace(".", "_").replace("-", "_")
    rule_name = "C2_Domain_%s" % d_clean[:30]
    rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', rule_name)

    r = []
    r.append(f"rule {rule_name} {{")
    r.append("    meta:")
    r.append(f'        description = "C2 domain pattern for {family_name}"')
    r.append('        author = "DroidForensix Pipeline"')
    r.append('        date = "2026-06-16"')
    r.append(f'        sample_count = "{len(samples_set)}"')
    r.append(f'        family = "{family_name}"')
    r.append(f'        c2_domain = "{domain}"')
    r.append('        confidence = "medium"')
    r.append("")
    r.append("    strings:")
    r.append(f'        $domain = "{domain}"')
    r.append("")
    r.append("    condition:")
    r.append("        $domain")
    r.append("}")
    r.append("")
    rules.append("\n".join(r))

with open(OUTPUT, "w", encoding="utf-8") as f:
    f.write("\n".join(rules))

print(f"\nWritten {len(rules)-1} rules to {OUTPUT}")

# Summary stats
xor_keys = sorted(xor_patterns.keys())
print(f"\nXOR keys found: {len(xor_keys)} ({xor_keys})")
print(f"Payload magic patterns: {len(payload_magic_patterns)}")
print(f"C2 domains: {len(c2_domain_patterns)}")
