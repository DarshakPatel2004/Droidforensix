"""SQLite-backed cache and result store for the forum scraper.

Raw scrape payloads are cached by key so re-runs never re-query the APIs.
Final links are stored in a results table and exported to CSV by main.py.
"""

import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

RESULTS_COLUMNS = [
    "c2_indicator",
    "forum_url",
    "date",
    "username",
    "snippet",
    "confidence",
    "source",
]


class Storage:
    """SQLite persistence for scrapes, caches, and final links."""

    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self._lock = threading.Lock()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS cache (
                        key TEXT PRIMARY KEY,
                        payload TEXT NOT NULL,
                        fetched_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS results (
                        c2_indicator TEXT NOT NULL,
                        forum_url TEXT NOT NULL,
                        date TEXT,
                        username TEXT,
                        snippet TEXT,
                        confidence REAL,
                        source TEXT,
                        PRIMARY KEY (c2_indicator, forum_url)
                    )
                    """
                )

    def get_cache(self, key: str) -> Optional[List[Dict[str, Any]]]:
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT payload FROM cache WHERE key = ?", (key,)
                ).fetchone()
        if row is None:
            return None
        try:
            return json.loads(row["payload"])
        except json.JSONDecodeError:
            logger.warning("Corrupt cache entry for %s; ignoring", key)
            return None

    def set_cache(self, key: str, payload: List[Dict[str, Any]]) -> None:
        blob = json.dumps(payload)
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO cache (key, payload, fetched_at)
                    VALUES (?, ?, ?)
                    """,
                    (key, blob, now),
                )

    def store_results(self, rows: List[Dict[str, Any]]) -> int:
        if not rows:
            return 0
        with self._lock:
            with self._connect() as conn:
                conn.executemany(
                    f"""
                    INSERT OR REPLACE INTO results
                    ({", ".join(RESULTS_COLUMNS)})
                    VALUES ({", ".join("?" for _ in RESULTS_COLUMNS)})
                    """,
                    [
                        tuple(row.get(col, "") if col != "confidence" else float(row.get(col, 0.0))
                             for col in RESULTS_COLUMNS)
                        for row in rows
                    ],
                )
        return len(rows)

    def load_results(self) -> List[Dict[str, Any]]:
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    f"SELECT {', '.join(RESULTS_COLUMNS)} FROM results"
                ).fetchall()
        return [dict(row) for row in rows]
