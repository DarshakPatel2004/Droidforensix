"""What gets attacked: member discovery, filters, and honest content extraction.

Two rules drive this module.

* **Never trust a ZIP flag.** A packer can set the "encrypted" bit on a member whose
  bytes are plaintext (usually a DEFLATE stream), and ``zipfile`` then refuses to read
  it. We parse the local header ourselves, inflate, and accept the member only when
  ``crc32(content) == central directory CRC``. A genuine ZipCrypto member cannot pass
  that check and is typed ``SKIPPED_ZIPCRYPTO`` instead of being attacked or misread.
* **Attack scope equals reporting scope.** Every member we attack gets a coverage row,
  and members we deliberately did not consider are counted, so the books close:
  ``members_total == len(records) + members_ignored_dirs + members_out_of_scope``.
"""
from __future__ import annotations

import io
import struct
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from packers.framework import shannon_entropy

RECOVERED = "RECOVERED"
E_KDF_EXHAUSTED = "E-KDF-EXHAUSTED"
E_KDF_BUDGET = "E-KDF-BUDGET"
SKIPPED_PLAINTEXT = "SKIPPED_PLAINTEXT"
SKIPPED_ZIPCRYPTO = "SKIPPED_ZIPCRYPTO"
SKIPPED_FILTER = "SKIPPED_FILTER"
SKIPPED_SIZE = "SKIPPED_SIZE"
PENDING = "pending"

# Sniffing is deliberately narrower than probing: a ciphertext blob can begin with "{"
# by chance, and skipping it would be a silent miss. "{" is only used as a probe/validate
# magic, where a false positive costs an attempt and is counted.
PLAINTEXT_MAGICS: tuple[tuple[bytes, str], ...] = (
    (b"PK\x03\x04", "zip"),
    (b"dex\n", "dex"),
    (b"\x7fELF", "elf"),
    (b"\x1f\x8b", "gzip"),
    (b"\x00\x01\x00\x00", "ttf"),
)
PROBE_MAGICS: tuple[tuple[bytes, str], ...] = PLAINTEXT_MAGICS + ((b"{", "json"),)

SKIP_DIRS: tuple[str, ...] = ("res/", "meta-inf/", "lib/", "dexopt/")
SKIP_EXTENSIONS: frozenset[str] = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico",
    ".mp3", ".ogg", ".flac", ".m4a", ".wav", ".mp4", ".3gp", ".avi", ".mkv",
    ".ttf", ".otf", ".woff", ".woff2",
    ".arsc", ".dex", ".so",
    ".xml", ".html", ".htm", ".js", ".css", ".txt", ".json", ".properties",
    ".yml", ".yaml", ".csv", ".ini", ".md",
})
MIN_BLOB_SIZE = 512
ENTROPY_SAMPLE = 65_536
DETAIL_LIMIT = 120

ZIP_LOCAL_SIG = b"PK\x03\x04"


@dataclass(frozen=True)
class Blob:
    """A member's real content, ready to be attacked, plus its own coverage row.

    The row travels with the blob so that repeated member names (legal in ZIP) can never
    collide on a name-keyed lookup and leave an unreported row behind.
    """

    member: str
    data: bytes
    content: str  # "stored" | "inflated"
    depth: int
    record: "MemberRecord"


@dataclass
class MemberRecord:
    """One coverage row. The engine fills the attempt fields in place."""

    name: str
    size: int
    outcome: str
    depth: int
    entropy: float
    detail: str = ""
    attempts: int = 0
    space_size: int = 0
    truncation: str = "none"
    probe_false_positives: int = 0


@dataclass
class BlobCollection:
    blobs: list[Blob] = field(default_factory=list)
    records: list[MemberRecord] = field(default_factory=list)
    plaintext: list[tuple[str, bytes]] = field(default_factory=list)
    recurse: list[tuple[str, bytes]] = field(default_factory=list)
    members_total: int = 0
    members_ignored_dirs: int = 0
    members_out_of_scope: int = 0


def collect_apk(path: Path | str) -> BlobCollection:
    return collect_from_zip(Path(path).read_bytes(), depth=0)


def collect_from_zip(data: bytes, *, depth: int, prefix: str = "") -> BlobCollection:
    collection = BlobCollection()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        collection.members_total = len(infos)
        for info in infos:
            if info.filename.endswith("/") or _in_ignored_dir(info.filename):
                collection.members_ignored_dirs += 1
                continue
            if not _is_in_scope(info.filename, info.flag_bits):
                collection.members_out_of_scope += 1
                continue
            name = prefix + info.filename
            content, kind, detail = _member_content(data, archive, info)
            record = MemberRecord(
                name=name,
                size=info.file_size,
                outcome=SKIPPED_ZIPCRYPTO if content is None else PENDING,
                depth=depth,
                entropy=0.0,
                detail=detail,
            )
            if content is not None:
                _classify(collection, name, content, kind, depth, info.filename, record)
            collection.records.append(record)
    collection.blobs.sort(key=lambda blob: (-len(blob.data), blob.member))
    collection.records.sort(key=lambda record: record.name)
    return collection


def _in_ignored_dir(file_name: str) -> bool:
    lowered = file_name.lower()
    return any(lowered.startswith(skip_dir) for skip_dir in SKIP_DIRS)


def _is_in_scope(file_name: str, flag_bits: int) -> bool:
    if flag_bits & 0x1:
        return True
    return file_name.lower().startswith("assets/") or "/" not in file_name


def _member_content(
    raw: bytes, archive: zipfile.ZipFile, info: zipfile.ZipInfo
) -> tuple[bytes | None, str, str]:
    if info.flag_bits & 0x1:
        return _flagged_content(raw, info)
    try:
        content = archive.read(info.filename)
    except Exception as exc:  # zipfile raises a variety of types for broken members
        return None, "", f"unreadable: {type(exc).__name__}: {exc}"[:DETAIL_LIMIT]
    kind = "stored" if info.compress_type == zipfile.ZIP_STORED else "inflated"
    return content, kind, ""


def _flagged_content(raw: bytes, info: zipfile.ZipInfo) -> tuple[bytes | None, str, str]:
    """Read a member whose encrypted flag is set, deciding by content, not by the flag."""
    offset = info.header_offset
    if raw[offset:offset + 4] != ZIP_LOCAL_SIG:
        return None, "", "no local-file header at the recorded offset"
    name_len, extra_len = struct.unpack("<HH", raw[offset + 26:offset + 30])
    data_at = offset + 30 + name_len + extra_len
    stored = raw[data_at:data_at + info.compress_size]
    if len(stored) != info.compress_size:
        return None, "", "member data runs past end of file"
    if info.compress_type == zipfile.ZIP_STORED:
        candidate, kind = stored, "stored"
    else:
        try:
            candidate = zlib.decompress(stored, -15)
        except zlib.error as exc:
            return None, "", f"inflate failed: {exc}"[:DETAIL_LIMIT]
        kind = "inflated"
    if zlib.crc32(candidate) != info.CRC:
        return None, "", "crc mismatch: content is not the member payload"
    return candidate, kind, ""


def _classify(
    collection: BlobCollection,
    name: str,
    content: bytes,
    kind: str,
    depth: int,
    file_name: str,
    record: MemberRecord,
) -> None:
    record.size = len(content)
    magic = _magic_kind(content)
    if magic is not None:
        # Content classification comes first: a plaintext member is identified (and mined, and
        # recursed into when it is a container) whatever its extension or size, because those
        # two filters are about attack-worthiness, not about identity. Real .dex/.so members
        # are the richest seed sources we have.
        record.outcome = SKIPPED_PLAINTEXT
        record.detail = f"plaintext {magic}"
        collection.plaintext.append((name, content))
        if magic == "zip":
            collection.recurse.append((name, content))
        return
    if PurePosixPath(file_name).suffix.lower() in SKIP_EXTENSIONS:
        record.outcome = SKIPPED_FILTER
        return
    if len(content) < MIN_BLOB_SIZE:
        record.outcome = SKIPPED_SIZE
        return
    record.entropy = shannon_entropy(content[:ENTROPY_SAMPLE])
    collection.blobs.append(
        Blob(member=name, data=content, content=kind, depth=depth, record=record)
    )


def _magic_kind(content: bytes) -> str | None:
    for signature, kind in PLAINTEXT_MAGICS:
        if content.startswith(signature):
            return kind
    return None
