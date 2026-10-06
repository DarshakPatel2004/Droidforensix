"""Rebuild ground-truth apk_path values after the 2026-10-06 sample offload.

Rules (agreed 2026-10-06):
  * modern_eval rows: keep only genuinely-encrypted APKs (path now under
    _offload/); drop every other modern_eval row.
  * all other rows: leave untouched if apk_path already resolves; otherwise
    re-point by sha256 to a surviving copy (samples/ > data/ > uploads/),
    then try the /home/kali/DroidForensix -> D:\\DroidForensix prefix rewrite;
    if neither works the row is kept unchanged and reported as unresolved.

"Encrypted" follows scripts/triage.py's rule: an entry with the zip
encryption bit whose content still fails to read after the flag-lie is
defused (real crypto/corrupt ciphertext). Flag-set entries that read fine
are dropper flag-lies, not encryption.
"""

import csv
import pathlib
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
INVENTORY = pathlib.Path(
    r"C:\Users\darsh\AppData\Local\Temp\opencode\apk_hash_inventory.csv"
)
OFFLOAD_MODERN = ROOT / "_offload" / "malware" / "modern_eval"
KALI_PREFIX = "/home/kali/DroidForensix/"
WINDOWS_ROOT = "D:\\DroidForensix\\"

GT_FILES = [
    "ground_truth_all.csv",
    "ground_truth_all_corrected.csv",
    "ground_truth_v1.5.csv",
    "ground_truth_all_corrected_100legit.csv",
]

# samples/ > data/ > uploads/ : first existing candidate wins
SOURCE_ORDER = ("\\samples\\", "\\data\\", "\\uploads\\")


def is_genuinely_encrypted(path: pathlib.Path) -> bool:
    """True if some zip member fails to read after defusing the flag-lie."""
    try:
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if not info.flag_bits & 0x1:
                    continue
                info.flag_bits &= ~0x1  # defuse flag-lie (triage.py _open_member)
                try:
                    with zf.open(info) as fh:
                        while fh.read(1 << 20):
                            pass
                except Exception:
                    return True
    except zipfile.BadZipFile:
        return False  # corrupt/non-zip is not encryption (RTO.apk opens fine)
    return False


def resolve(raw: str, sha: str, by_sha: dict) -> str:
    """Existing path for a row: as-is, then by sha256, then kali-prefix."""
    if raw:
        p = pathlib.Path(raw) if pathlib.Path(raw).is_absolute() else ROOT / raw
        if p.exists():
            return raw
    for cand in by_sha.get(sha, []):
        return str(cand)
    if raw.startswith(KALI_PREFIX):
        p = pathlib.Path(WINDOWS_ROOT + raw[len(KALI_PREFIX):])
        if p.exists():
            return str(p)
    return ""


def main() -> int:
    # hash -> existing paths, ordered samples > data > uploads
    by_sha: dict = {}
    if INVENTORY.exists():
        with INVENTORY.open(newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                p = pathlib.Path(row["Path"])
                if p.exists():
                    by_sha.setdefault(row["Hash"].lower(), []).append(p)
    def rank(p: pathlib.Path) -> int:
        s = str(p).lower()
        hits = [i for i, b in enumerate(SOURCE_ORDER) if b in s]
        return hits[0] if hits else len(SOURCE_ORDER)

    for lst in by_sha.values():
        lst.sort(key=rank)

    # genuinely-encrypted modern_eval APKs (sha -> offload path)
    encrypted = {
        p.stem.lower(): p
        for p in sorted(OFFLOAD_MODERN.glob("*.apk"))
        if is_genuinely_encrypted(p)
    }
    print(f"genuinely-encrypted modern_eval APKs: {len(encrypted)}")

    for name in GT_FILES:
        path = ROOT / name
        with path.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames
            rows = list(reader)

        kept, dropped, repaired, unresolved = [], 0, 0, []
        for row in rows:
            sha = (row.get("sha256") or "").lower()
            if (row.get("source") or "") == "modern_eval":
                if sha in encrypted:
                    row["apk_path"] = str(encrypted[sha])
                    kept.append(row)
                else:
                    dropped += 1
                continue
            fixed = resolve(row.get("apk_path") or "", sha, by_sha)
            if fixed and fixed != row.get("apk_path"):
                row["apk_path"] = fixed
                repaired += 1
            elif not fixed:
                unresolved.append((sha[:12], row.get("apk_path", "")[:70]))
            kept.append(row)

        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\r\n")
            writer.writeheader()
            writer.writerows(kept)

        n_enc = sum(1 for r in kept if r.get("source") == "modern_eval")
        print(
            f"{name}: {len(rows)} -> {len(kept)} "
            f"(dropped modern={dropped}, encrypted kept={n_enc}, repaired={repaired})"
        )
        for sha, old in unresolved:
            print(f"  UNRESOLVED {sha} {old}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
