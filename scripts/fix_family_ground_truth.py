"""
fix_family_ground_truth.py — Correct the family labels in ground_truth_check_all.csv.

Resolution priority (most authoritative first):
  1. filename prefix  — the family name embedded in the sample filename
     (Drebin/MalwareBazaar source naming; agrees with MB signatures 94.3%)
  2. MB signature     — MalwareBazaar's own family signature
  3. GT specific      — existing ground_truth_all.csv family (non-catch-all)
  4. VT recheck       — VirusTotal top-family vote (non-catch-all)
  5. Pipeline sig     — signature_v3 identification verified against raw
     C2/string evidence (e.g. NGate with nfck.loseyourip.com in step5_c2s)
  6. MB tags          — MalwareBazaar tags mapped to known campaign families

Catch-all labels (AndroidOS, GenericKD, Agent, Banker, Gen, Adware, ...) are
never accepted as a family.

Writes family_corrected + family_source columns into ground_truth_check_all.csv
and prints a before/after summary.
"""

import csv
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GT_CHECK_CSV = ROOT / "ground_truth_check_all.csv"
CACHE_PATH = ROOT / "evaluation" / "gt_recheck_cache.json"
WORK_DIR = ROOT / "analysis" / "work"

CATCH_ALL = {
    "androidos", "generickd", "agent", "banker", "gen", "adware", "linux",
    "backdoor", "a", "dropper", "trojan", "trojan-banker", "trojan-dropper",
    "generic", "riskware", "unknown", "general", "detected", "exploit",
    "hacktool", "spyware", "trojan ( 005cbb901 )", "trojan ( 005cf1d81 )",
    "trojan ( 0001140e1 )", "application", "andraware", "andro",
}

# Canonical family names for the filename prefixes (Drebin/MB naming)
PREFIX_FAMILY = {
    "adrd": "Adrd", "adsms": "Adsms", "basebridge": "BaseBridge",
    "boxer": "Boxer", "copycat": "Copycat", "dougalek": "Dougalek",
    "droiddream": "DroidDream", "droidkungfu": "DroidKungFu",
    "ermac": "Ermac", "escobar": "Escobar", "exobot": "Exobot",
    "exploitlinuxlotoor": "ExploitLinuxLotoor", "faceniff": "FaceNiff",
    "fakedoc": "FakeDoc", "fakeinstaller": "FakeInstaller",
    "fakerun": "FakeRun", "faketimer": "FakeTimer", "flubot": "FluBot",
    "geinimi": "Geinimi", "ginmaster": "GinMaster", "hamob": "Hamob",
    "hydra": "Hydra", "iconosys": "Iconosys", "imlog": "Imlog",
    "kmin": "Kmin", "konfety": "Konfety", "lemon": "Lemon",
    "mobiletx": "MobileTx", "nandrobox": "Nandrobox", "nickspy": "NickiSpy",
    "nisev": "Nisev", "nyleaker": "Nyleaker", "opfake": "Opfake",
    "penetho": "Penetho", "pixrevolution": "PixRevolution",
    "plankton": "Plankton", "sendpay": "SendPay", "serbg": "Serbg",
    "smforw": "SmForw", "smsreg": "SMSreg", "spitmo": "Spitmo",
    "spyhasb": "SpyHasb", "spynote": "SpyNote", "stiniter": "Stiniter",
    "teabot": "TeaBot", "typstu": "Typstu", "zsone": "Zsone",
}

# MB tag -> campaign family mapping
TAG_FAMILY = {
    "mparivahan": "mParivahan", "goi": "mParivahan",
    "indusind credit card": "Indusind", "icici": "ICICI",
    "hdfc": "Aversefalc", "aversefalc": "Aversefalc",
    "eventbot": "Eventbot", "tiramisu": "Tiramisu", "antidot": "Antidot",
    "faketelegram": "FakeTelegram", "faketiktok": "FakeTikTok",
    "tiktok": "FakeTikTok", "beatbanker": "BeatBanker",
    "fakechrome": "FakeChrome", "latam": "Latam", "ollvm": "Ollvm",
    "nfc": "NGate", "mirai": "Mirai", "spyagent": "SpyAgent",
}


def norm(family: str) -> str:
    f = (family or "").strip().lower()
    f = re.sub(r"^android[./]", "", f)
    f = f.replace("trojan:", "").replace("gen:", "").replace("win32/", "")
    f = f.replace("heuristic", "").replace("apk:", "")
    return re.sub(r"[.\s_/-]", " ", f).strip()


def is_catchall(family: str) -> bool:
    n = norm(family)
    if not n or n == "unknown":
        return True
    if n in CATCH_ALL or n.split()[0] in CATCH_ALL:
        return True
    return False


def get_prefix(sample_name: str) -> str:
    m = re.match(r"^([A-Za-z0-9]+)_[0-9a-f]{64}\.apk$", sample_name)
    if not m:
        return ""
    p = m.group(1).lower()
    if p == "unknown":
        return ""
    return p


def has_ngate_evidence(sha256: str) -> bool:
    """Check the raw step5_c2s.json for the NGate C2 domain."""
    d = WORK_DIR / sha256
    c2f = d / "step5_c2s.json"
    if not c2f.exists():
        return False
    try:
        text = json.dumps(json.loads(c2f.read_text())).lower()
    except Exception:
        return False
    return "nfck.loseyourip.com" in text


def family_from_tags(tags) -> str:
    lowered = [t.lower() for t in (tags or [])]
    for tag in sorted(lowered, key=len, reverse=True):
        if tag in TAG_FAMILY:
            return TAG_FAMILY[tag]
    return ""


def resolve_family(row: dict, cache: dict) -> tuple:
    """Return (family, source) for one row, or ('', 'unresolved')."""
    sha = row["sha256"].lower()
    entry = cache.get(sha, {})
    mb_sig = entry.get("family", "") if entry.get("engine") == "malwarebazaar" else ""
    gt_fam = row["family"]
    rc_fam = row["recheck_family"]

    # 1. filename prefix (authoritative source naming)
    prefix = get_prefix(row["sample_name"])
    if prefix:
        return PREFIX_FAMILY.get(prefix, prefix), "filename_prefix"

    # 2. MB signature
    if mb_sig and not is_catchall(mb_sig):
        return mb_sig, "mb_signature"

    # 3. GT specific (non-catch-all)
    if gt_fam and not is_catchall(gt_fam):
        return gt_fam, "gt_specific"

    # 4. VT recheck specific
    if rc_fam and not is_catchall(rc_fam):
        return rc_fam, "vt_recheck"

    # 5. Pipeline NGate signature with verified C2 evidence
    if has_ngate_evidence(sha):
        return "NGate", "pipeline_sig_verified"

    # 6. MB tags -> campaign family
    tag_fam = family_from_tags(entry.get("tags", []))
    if tag_fam:
        return tag_fam, "mb_tags"

    return "", "unresolved"


def main():
    cache = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    with open(GT_CHECK_CSV, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    fieldnames = list(rows[0].keys())
    if "family_corrected" not in fieldnames:
        fieldnames += ["family_corrected", "family_source"]

    before = Counter()
    after = Counter()
    changed = 0
    for row in rows:
        before[row["family"] or "unknown"] += 1
        fam, source = resolve_family(row, cache)
        row["family_corrected"] = fam
        row["family_source"] = source
        after[fam or "unknown"] += 1
        if (fam or "unknown") != (row["family"] or "unknown"):
            changed += 1

    with open(GT_CHECK_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    print("=" * 60)
    print("Family label correction complete")
    print("=" * 60)
    print(f"Rows updated:          {len(rows)}")
    print(f"Families changed:      {changed}")
    print(f"Unresolved (unknown):  {after.get('unknown', 0)}")

    print("\nResolution sources:")
    src = Counter(r["family_source"] for r in rows)
    for s, n in src.most_common():
        print(f"  {s:22} {n}")

    print("\nTop 20 families after correction:")
    for fam, n in after.most_common(20):
        print(f"  {fam:18} {n}")


if __name__ == "__main__":
    main()