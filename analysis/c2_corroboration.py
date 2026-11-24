"""Single definition of when a C2 record counts as corroborated.

A record is corroborated when it is a full URL seen in code, scored at or above
the threshold, and carries an endpoint path. Bare domains (fallback records) never
qualify. A path only counts if its last segment looks like a real endpoint: a
truncated prefix such as "/bot" (from "https://api.telegram.org/bot<token>/...")
or a generic segment such as "/api" does not.

Sanity checks in step 7 and the report model both call this function, so they
cannot disagree about what is corroborated.
"""

from typing import Any, Dict

CORROBORATION_MIN_CONFIDENCE = 0.8

# Last path segments too generic to identify an endpoint on their own.
GENERIC_PATH_SEGMENTS = frozenset({"bot", "api", "v1", "v2", "rest", "index", "data", "app"})
MIN_ENDPOINT_SEGMENT_LENGTH = 4


def is_endpoint_path(path: Any) -> bool:
    """True when the path ends in a segment specific enough to name an endpoint."""
    if not path or not isinstance(path, str) or path == "/":
        return False
    segments = [s for s in path.split("/") if s]
    if not segments:
        return False
    last = segments[-1].lower()
    if last in GENERIC_PATH_SEGMENTS:
        return False
    return len(last) >= MIN_ENDPOINT_SEGMENT_LENGTH


def is_corroborated_endpoint(record: Dict[str, Any],
                             min_confidence: float = CORROBORATION_MIN_CONFIDENCE) -> bool:
    """True when a C2 record is a full URL from code with a real endpoint path."""
    if record.get("is_fallback"):
        return False
    if (record.get("confidence") or 0) < min_confidence:
        return False
    return is_endpoint_path(record.get("path"))
