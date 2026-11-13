"""Tamper-evident chain-of-custody log for one analysis run.

Each entry stores the SHA-256 of the previous entry, so editing or removing a
line breaks every hash after it. A verified chain proves the log was not
altered after it was written. It does not prove the analysis was correct, and
it cannot detect removal of the final entries on its own: compare ``head_hash``
against a copy recorded elsewhere (for example in a signed report).
"""

import hashlib
import json
import os
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

CUSTODY_NAME = "custody.jsonl"
GENESIS_HASH = "0" * 64

if os.name == "nt":
    import msvcrt

    def _lock_file(handle) -> None:
        # LK_LOCK gives up after ~10 s, so keep retrying until the holder releases.
        handle.seek(0)
        while True:
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
                return
            except OSError:
                continue

    def _unlock_file(handle) -> None:
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def _lock_file(handle) -> None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)

    def _unlock_file(handle) -> None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def _exclusive(sample_dir: Path) -> Iterator[None]:
    """Hold an OS-level lock on the sample's custody log while one writer appends (A1-46)."""
    sample_dir.mkdir(parents=True, exist_ok=True)
    with open(sample_dir / (CUSTODY_NAME + ".lock"), "a+b") as handle:
        _lock_file(handle)
        try:
            yield
        finally:
            _unlock_file(handle)


def _digest(seq: int, ts: str, event: str, data: Dict[str, Any], prev_hash: str) -> str:
    body = json.dumps(
        {"seq": seq, "ts": ts, "event": event, "data": data, "prev": prev_hash},
        sort_keys=True, separators=(",", ":"), default=str,
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def digest_value(value: Any) -> str:
    """SHA-256 of a step's output in canonical JSON form."""
    body = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def file_digest(path: Path) -> str:
    """SHA-256 of a file's bytes."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_entries(sample_dir: Path) -> List[Dict[str, Any]]:
    """Return the log entries in order. Missing log -> empty list."""
    path = Path(sample_dir) / CUSTODY_NAME
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def append_event(sample_dir: Path, event: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Append one event to the sample's custody log and return the entry."""
    sample_dir = Path(sample_dir)
    with _exclusive(sample_dir):
        # Read and append under one lock so two writers cannot pick the same seq.
        entries = read_entries(sample_dir)
        seq = len(entries)
        prev_hash = entries[-1]["hash"] if entries else GENESIS_HASH
        ts = datetime.now(timezone.utc).isoformat()
        entry = {
            "seq": seq,
            "ts": ts,
            "event": event,
            "data": data,
            "prev": prev_hash,
            "hash": _digest(seq, ts, event, data, prev_hash),
        }
        with open(sample_dir / CUSTODY_NAME, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True, default=str) + "\n")
    return entry


def verify(sample_dir: Path) -> Dict[str, Any]:
    """Recompute the chain. Returns validity, entry count, head hash, and the first broken seq."""
    entries = read_entries(sample_dir)
    if not entries:
        return {"valid": False, "entries": 0, "head_hash": None, "broken_at": None,
                "reason": "no custody log"}
    prev_hash = GENESIS_HASH
    for index, entry in enumerate(entries):
        expected = _digest(entry.get("seq"), entry.get("ts"), entry.get("event"),
                           entry.get("data"), entry.get("prev"))
        if entry.get("seq") != index or entry.get("prev") != prev_hash or entry.get("hash") != expected:
            return {"valid": False, "entries": len(entries), "head_hash": entries[-1].get("hash"),
                    "broken_at": index, "reason": "entry does not match its hash chain"}
        prev_hash = entry["hash"]
    return {"valid": True, "entries": len(entries), "head_hash": prev_hash,
            "broken_at": None, "reason": "ok"}


def main(argv: Optional[List[str]] = None) -> int:
    """CLI: python -m analysis.custody <sample_dir>. Exit 0 when the chain verifies."""
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m analysis.custody <work_dir>/<sha256>", file=sys.stderr)
        return 2
    result = verify(Path(args[0]))
    print(json.dumps(result, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
