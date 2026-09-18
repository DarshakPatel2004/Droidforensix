"""
Cross-sample method signature similarity index.

Persistent storage for method-signature hashes across all analyzed APKs.
Used by family clustering to match new samples against previously seen
malware families.

Data is stored as JSON at settings.WORK_DIR / cross_sample_index.json.

NOTE: This index has no file lock. It relies on pipeline execution being
sequential. Before parallelizing the pipeline, a file lock is required.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

from backend.config import settings

logger = logging.getLogger(__name__)

INDEX_PATH = settings.WORK_DIR / "cross_sample_index.json"


def load_index() -> Dict[str, Any]:
    if INDEX_PATH.exists():
        try:
            with open(INDEX_PATH, "r", encoding="utf-8") as f:
                index = json.load(f)
            if index.get("version", 1) < 2:
                logger.info("Index version %d is outdated; starting fresh", index.get("version", 1))
                return {"samples": {}, "version": 2}
            return index
        except Exception as e:
            logger.warning("Failed to load cross-sample index: %s", e)
    return {"samples": {}, "version": 2}


def save_index(index: Dict[str, Any]):
    index["version"] = 2
    try:
        INDEX_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(INDEX_PATH, "w", encoding="utf-8") as f:
            json.dump(index, f, indent=2)
    except Exception as e:
        logger.warning("Failed to save cross-sample index: %s", e)


def add_to_index(sample_id: str, family: str, signature: Dict[str, Any]):
    index = load_index()
    index["samples"][sample_id] = {
        "family": family or "unknown",
        "method_signatures": signature.get("method_signatures", []),
        "minhash_values": signature.get("minhash_values", []),
        "signature_count": signature.get("total_methods", 0),
    }
    save_index(index)
