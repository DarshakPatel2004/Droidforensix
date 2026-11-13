"""Place one sample from a password-protected archive without touching other samples.

Download scripts share a samples folder. Extracting into that folder and then renaming or
deleting "the first other file" destroyed previously downloaded samples (audit R2/R3).
Here the archive is extracted into a private staging directory, and only the entry that
belongs to this hash is moved into place.
"""
import os
import shutil
import tempfile
from pathlib import Path
from typing import Callable

ZIP_PASSWORD = b"infected"


def place_sample(
    archive: Path,
    dest: Path,
    sha256: str,
    extract: Callable[[Path, Path], None],
) -> bool:
    """Extract `archive` into staging and move only the entry for `sha256` to `dest`.

    Returns False (and moves nothing) when no entry clearly belongs to this hash.
    Never renames or deletes files outside its own staging directory.
    """
    staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=dest.parent))
    try:
        try:
            extract(archive, staging)
        except Exception as exc:
            print(f"[!] Extraction failed for {sha256}: {exc}", flush=True)
            return False

        files = [p for p in staging.iterdir() if p.is_file()]
        chosen = next((p for p in files if p.name.lower().startswith(sha256.lower())), None)
        if chosen is None and len(files) == 1:
            chosen = files[0]  # archive held one unnamed entry: it is this sample
        if chosen is None:
            print(f"[!] No entry matching {sha256} in archive ({len(files)} files)", flush=True)
            return False

        os.replace(chosen, dest)
        return True
    finally:
        shutil.rmtree(staging, ignore_errors=True)
