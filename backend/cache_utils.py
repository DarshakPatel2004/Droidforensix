"""Bounded, invalidation-aware in-memory caches for the backend routes (audit B2-23)."""

import json
import os
import tempfile
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any, Hashable, Optional


class StampedLRU:
    """Least-recently-used map whose entries are valid only while their stamp matches.

    The stamp is the source's identity (for example pipeline_result.json mtime plus
    the family knowledge-base stamp), so a re-run or a KB change invalidates the
    entry without a TTL. The size cap bounds memory regardless of how many samples
    are viewed.
    """

    def __init__(self, max_entries: int) -> None:
        self._max_entries = max_entries
        self._data: "OrderedDict[Hashable, tuple]" = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: Hashable, stamp: Any) -> Optional[Any]:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            if entry[0] != stamp:
                del self._data[key]
                return None
            self._data.move_to_end(key)
            return entry[1]

    def put(self, key: Hashable, stamp: Any, value: Any) -> None:
        with self._lock:
            self._data[key] = (stamp, value)
            self._data.move_to_end(key)
            while len(self._data) > self._max_entries:
                self._data.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)


def store_timed(cache: dict, key: Any, value: Any, now: float, ttl: float, max_entries: int) -> None:
    """Insert ``(value, now)`` into a TTL dict, first evicting expired and overflowing entries.

    Expired entries were previously only skipped on read, so the dict grew without bound.
    """
    for stale_key, (_, stamped_at) in list(cache.items()):
        if now - stamped_at >= ttl:
            cache.pop(stale_key, None)
    while len(cache) >= max_entries:
        oldest = next(iter(cache), None)
        if oldest is None:
            break
        cache.pop(oldest, None)
    cache[key] = (value, now)


def atomic_write_json(path: Path, data: Any) -> None:
    """Write JSON to a unique temp file in the same directory, then rename it into place.

    A reader never sees a half-written file, and concurrent writers never share a temp name.
    """
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
