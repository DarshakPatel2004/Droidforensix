"""Helpers shared by the sample download and corpus scripts."""
import hashlib
from pathlib import Path


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sanitize_filename(name: str) -> str:
    """Make a string safe to use in a filename."""
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)
    return safe.strip("._") or "unknown"


def safe_error(exc: Exception, secret: str = "") -> str:
    """Remove API credentials from third-party request errors."""
    message = str(exc)
    if secret:
        message = message.replace(secret, "<redacted>")
    return message
