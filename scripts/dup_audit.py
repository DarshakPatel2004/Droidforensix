"""Duplicate audit: hash twins (byte-verified) + name twins + package twins."""
import hashlib
import re
import sys
from collections import defaultdict
from pathlib import Path

from loguru import logger

logger.remove()
logger.add(sys.stderr, level="ERROR")

from androguard.core.apk import APK

ROOT = Path("PENDRIVE DATA")

files = sorted(p for p in ROOT.rglob("*.apk") if p.is_file())
print(f"[i] {len(files)} .apk files on disk", file=sys.stderr)

by_hash = defaultdict(list)
for p in files:
    h = hashlib.sha256(p.read_bytes()).hexdigest()
    by_hash[h].append(p)

dup_groups = {h: ps for h, ps in by_hash.items() if len(ps) > 1}

print(f"[i] {len(by_hash)} unique sha256; {len(dup_groups)} hashes with >1 file", file=sys.stderr)

print("== HASH TWINS (byte-verified with cmp) ==")
true_dup_files = set()
for h, ps in sorted(dup_groups.items(), key=lambda kv: kv[1][0].name):
    base = ps[0].read_bytes()
    all_identical = all(p.read_bytes() == base for p in ps[1:])
    tag = "TRUE-DUP" if all_identical else "HASH-COLLISION?!"
    if all_identical:
        true_dup_files.update(ps[1:])
    print(f"\n[{tag}] sha256={h[:16]}… size={len(base)}")
    for p in ps:
        print(f"    {p}")

def stem(name: str) -> str:
    s = name[:-4] if name.lower().endswith(".apk") else name
    s = re.sub(r"\s*\(\d+\)\s*$", "", s)
    s = re.sub(r"-\d+$", "", s)
    return s.strip().lower()

print("\n== NAME TWINS, DIFFERENT HASH (looks like a dup, isn't) ==")
by_stem = defaultdict(list)
for h, ps in by_hash.items():
    by_stem[stem(ps[0].name)].append((h, ps))
for s, entries in sorted(by_stem.items()):
    if len(entries) > 1:
        print(f"\n[{s}]")
        for h, ps in entries:
            print(f"    sha256={h[:16]}… size={ps[0].stat().st_size}  {ps[0]}")

print("\n== PACKAGE-LEVEL ANALYSIS (androguard) ==")
seen_pkgs = defaultdict(list)
for h, ps in sorted(by_hash.items(), key=lambda kv: kv[1][0].name):
    p = ps[0]
    try:
        a = APK(str(p))
        pkg = a.get_package()
        ver = f"{a.get_androidversion_name()} ({a.get_androidversion_code()})"
        app = a.get_app_name()
    except Exception as e:
        pkg, ver, app = f"PARSE-FAIL:{type(e).__name__}", "-", "-"
    seen_pkgs[pkg].append((h, len(ps), p.name, ver, app))

for pkg, rows in sorted(seen_pkgs.items()):
    if len(rows) > 1:
        print(f"\nPKG {pkg}  ({len(rows)} distinct hashes)")
        for h, n, name, ver, app in rows:
            print(f"    sha256={h[:16]}… x{n} copies  ver={ver}  app={app!r}  file={name}")

print(f"\n[SUMMARY] files={len(files)} unique_sha256={len(by_hash)} "
      f"dup_hashes={len(dup_groups)} redundant_copies={len(true_dup_files)}", file=sys.stderr)
