import json, os, base64, re, collections
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
sample_packages = {}

for d in os.listdir(WORK_DIR):
    jpath = os.path.join(WORK_DIR, d, "pipeline_result.json")
    if not os.path.isfile(jpath):
        continue
    try:
        with open(jpath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except:
        continue
    sample_count += 1
    sha = data.get("sample_id", d)
    pkg = data.get("metadata", {}).get("package_name", "unknown")
    sample_packages[sha] = pkg
    family = families.get(sha, "unknown")
    
    encs = data.get("encodings", []) or []
    for e in encs:
        e["_sample_id"] = sha
        e["_family"] = family
        e["_package"] = pkg
        all_encodings.append(e)
    
    plds = data.get("payloads", []) or []
    for p in plds:
        p["_sample_id"] = sha
        p["_family"] = family
        p["_package"] = pkg
        all_payloads.append(p)
    
    c2s = data.get("c2_infrastructure", []) or []
    for c in c2s:
        c["_sample_id"] = sha
        c["_family"] = family
        all_c2.append(c)

print(f"Samples: {sample_count}")
print(f"Encodings: {len(all_encodings)}")
print(f"Payloads: {len(all_payloads)}")
print(f"C2 entries: {len(all_c2)}")

# Collect unique xor keys and their encoded strings
xor_patterns = collections.defaultdict(list)
base64_text_patterns = []
payload_magic_patterns = collections.defaultdict(list)
c2_domain_patterns = collections.defaultdict(list)
c2_url_patterns = collections.defaultdict(list)

for e in all_encodings:
    etype = e.get("type", "").lower()
    orig = e.get("original_string", "")
    key = e.get("xor_key", None)
    decoded = e.get("decoded_preview", "")
    conf = e.get("confidence", 0)
    family = e.get("_family", "unknown")
    
    if etype == "xor" and key is not None and isinstance(key, int) and len(orig) > 4:
        xor_patterns[key].append((orig, decoded, family, e["_sample_id"]))
    
    if etype == "base64" and len(orig) > 8:
        base64_text_patterns.append((orig, decoded, family, e["_sample_id"]))

for p in all_payloads:
    content = p.get("decoded_content", "")
    magic = p.get("magic_bytes", []) or []
    artifacts = p.get("artifacts", []) or []
    family = p.get("_family", "unknown")
    
    for m in magic:
        if isinstance(m, str) and len(m) >= 4:
            payload_magic_patterns[m].append((content, family, p["_sample_id"]))
    
    if content and len(content) > 16:
        # detect if it looks like a URL or IP or executable
        pass

for c in all_c2:
    domain = c.get("domain", "")
    ip = c.get("ip", "")
    path = c.get("path", "")
    protocol = c.get("protocol", "")
    raw_url = c.get("raw_url", "")
    family = c.get("_family", "unknown")
    
    if domain:
        parts = domain.split(".")
        if len(parts) >= 2:
            tld = parts[-1]
            reg_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain
            c2_domain_patterns[reg_domain].append((domain, family, c["_sample_id"]))
    
    if raw_url:
        c2_url_patterns[raw_url[:80]].append((raw_url, family, c["_sample_id"]))

rules = []

# Header
header = """/*
 * DroidForensix - YARA Detection Rules
 * Generated from Android malware analysis pipeline results
 * 
 * Date: 2026-06-16
 * Samples analyzed: %d
 * Encodings found: %d
 * Payloads decoded: %d
 * C2 indicators: %d
 *
 * These rules detect patterns found in analyzed APK samples
 * including XOR-encoded strings, base64-encoded payloads,
 * decoded payload magic bytes, and C2 infrastructure patterns.
 */
""" % (sample_count, len(all_encodings), len(all_payloads), len(all_c2))

rules.append(header)

# Rule 1: XOR key detection
# Group xor patterns by key
idx = 1
for key in sorted(xor_patterns.keys()):
    entries = xor_patterns[key]
    families_set = set(e[2] for e in entries)
    samples_set = set(e[3] for e in entries)
    family_name = families_set.pop() if len(families_set) == 1 else "multi-family"
    
    # Build hex patterns from encoded strings (first 8 bytes)
    hex_strings = []
    for orig, decoded, fam, sid in entries[:10]:
        raw = orig.encode("utf-8", errors="replace")
        hex_part = raw[:16].hex()
        if len(hex_part) >= 8:
            hex_strings.append(hex_part)
    
    # Deduplicate
    hex_strings = list(set(hex_strings))
    
    if not hex_strings:
        continue
    
    # Build rule
    rule_name = "XOR_Key_%d_%s" % (key, family_name.replace(".", "_").replace("-", "_")[:30])
    # sanitize rule name
    rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', rule_name)
    
    rule_lines = []
    rule_lines.append("rule %s {" % rule_name)
    rule_lines.append("    meta:")
    rule_lines.append('        description = "XOR key %d encoded strings found in %s"' % (key, family_name))
    rule_lines.append('        author = "DroidForensix Pipeline"')
    rule_lines.append('        date = "2026-06-16"')
    rule_lines.append('        sample_count = "%d"' % len(samples_set))
    rule_lines.append('        family = "%s"' % family_name)
    rule_lines.append('        xor_key = "%d"' % key)
    rule_lines.append('        confidence = "high"')
    rule_lines.append('')
    rule_lines.append("    strings:")
    
    for i, h in enumerate(hex_strings):
        vname = "$xor_%d" % i
        # Limit to 30 hex chars for Yara string
        h_limited = h[:40]
        rule_lines.append('        %s = { %s }' % (vname, ' '.join(h_limited[j:j+2] for j in range(0, len(h_limited), 2))))
    
    rule_lines.append('')
    rule_lines.append("    condition:")
    rule_lines.append("        uint16(0) == %d or any of them" % key)
    rule_lines.append("}")
    rule_lines.append("")
    
    rules.append("\n".join(rule_lines))
    idx += 1

# Rule 2: Payload magic bytes
for magic, entries in payload_magic_patterns.items():
    families_set = set(e[1] for e in entries)
    samples_set = set(e[2] for e in entries)
    family_name = families_set.pop() if len(families_set) == 1 else "multi-family"
    
    rule_name = "Payload_Magic_%s" % re.sub(r'[^a-zA-Z0-9_]', '_', magic[:20])
    
    rule_lines = []
    rule_lines.append("rule %s {" % rule_name)
    rule_lines.append("    meta:")
    rule_lines.append('        description = "Decoded payload with magic bytes %s"' % magic)
    rule_lines.append('        author = "DroidForensix Pipeline"')
    rule_lines.append('        date = "2026-06-16"')
    rule_lines.append('        sample_count = "%d"' % len(samples_set))
    rule_lines.append('        family = "%s"' % family_name)
    rule_lines.append('        magic_bytes = "%s"' % magic)
    rule_lines.append('        confidence = "high"')
    rule_lines.append('')
    rule_lines.append("    strings:")
    
    if magic.startswith("0x"):
        try:
            mb = int(magic, 16)
            h = format(mb, 'x')
            rule_lines.append('        $magic = { %s }' % ' '.join(h[j:j+2] for j in range(0, len(h), 2)))
        except:
            rule_lines.append('        $magic = "%s"' % magic)
    else:
        rule_lines.append('        $magic = "%s"' % magic)
    
    rule_lines.append('')
    rule_lines.append("    condition:")
    rule_lines.append("        $magic")
    rule_lines.append("}")
    rule_lines.append("")
    
    rules.append("\n".join(rule_lines))
    idx += 1

# Rule 3: C2 Domains
for domain, entries in c2_domain_patterns.items():
    families_set = set(e[1] for e in entries)
    samples_set = set(e[2] for e in entries)
    family_name = families_set.pop() if len(families_set) == 1 else "multi-family"
    
    d_clean = domain.replace(".", "_").replace("-", "_")
    rule_name = "C2_Domain_%s" % d_clean[:30]
    rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', rule_name)
    
    rule_lines = []
    rule_lines.append("rule %s {" % rule_name)
    rule_lines.append("    meta:")
    rule_lines.append('        description = "C2 domain pattern for %s"' % family_name)
    rule_lines.append('        author = "DroidForensix Pipeline"')
    rule_lines.append('        date = "2026-06-16"')
    rule_lines.append('        sample_count = "%d"' % len(samples_set))
    rule_lines.append('        family = "%s"' % family_name)
    rule_lines.append('        c2_domain = "%s"' % domain)
    rule_lines.append('        confidence = "medium"')
    rule_lines.append('')
    rule_lines.append("    strings:")
    rule_lines.append('        $domain = "%s"' % domain)
    rule_lines.append('')
    rule_lines.append("    condition:")
    rule_lines.append("        $domain")
    rule_lines.append("}")
    rule_lines.append("")
    
    rules.append("\n".join(rule_lines))
    idx += 1

# Rule 4: If no payloads/encodings found, create informational rules based on packages
pkg_rules_added = set()
for sha, pkg in sample_packages.items():
    family = families.get(sha, "unknown")
    if family == "unknown":
        continue
    pkg_key = family.replace(".", "_")
    if pkg_key in pkg_rules_added:
        continue
    pkg_rules_added.add(pkg_key)
    
    # Check if this package has any related samples with xor/encodings
    has_xor = any(e.get("_family") == family for e in all_encodings)
    if has_xor:
        continue  # already covered by xor rule
    
    rule_name = "Pkg_%s" % pkg_key[:40]
    rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', rule_name)
    
    rule_lines = []
    rule_lines.append("rule %s {" % rule_name)
    rule_lines.append("    meta:")
    rule_lines.append('        description = "Package pattern for %s"' % family)
    rule_lines.append('        author = "DroidForensix Pipeline"')
    rule_lines.append('        date = "2026-06-16"')
    rule_lines.append('        family = "%s"' % family)
    rule_lines.append('        package_name = "%s"' % pkg)
    rule_lines.append('        confidence = "low"')
    rule_lines.append('')
    rule_lines.append("    strings:")
    rule_lines.append('        $pkg = "%s"' % pkg)
    rule_lines.append('')
    rule_lines.append("    condition:")
    rule_lines.append("        $pkg")
    rule_lines.append("}")
    rule_lines.append("")
    
    rules.append("\n".join(rule_lines))
    idx += 1

# Write output
with open(OUTPUT, "w", encoding="utf-8") as f:
    f.write("\n".join(rules))

print(f"\nWritten {len(rules)} rules to {OUTPUT}")
print(f"Total rules: {len(rules) - 1}")  # minus header
