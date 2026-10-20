"""Static evidence extraction from recovered payloads.

Design authority: ``docs/plans/specs/2026-10-16-recovered-payload-evidence-design.md``.
The collector reads classes, manifest permissions and native libraries from a
recovered payload ZIP, entirely in memory. It is static (nothing is executed),
bounded (size, count and wall-clock caps below), and
``collect_payload_evidence`` never raises: a payload that fails to parse
contributes nothing and is recorded in ``errors`` instead.
"""

import io
import logging
import re
import time
import zipfile
from dataclasses import dataclass, field
from typing import Sequence

logger = logging.getLogger(__name__)

# Caps (spec section 6). Exposed as keyword parameters of the collector.
MAX_PAYLOAD_BYTES = 64 * 1024 * 1024  # total payload bytes analysed per sample
MAX_MEMBER_BYTES = 32 * 1024 * 1024   # per-member skip threshold
MAX_DEX_MEMBERS = 64                  # dex members parsed per payload
EVIDENCE_BUDGET_S = 20.0              # wall-clock guard for the whole walk

ZIP_MAGIC = b"PK\x03\x04"
ELF_MAGIC = b"\x7fELF"
HEAD_PROBE_BYTES = 4  # enough to sniff the ELF magic without inflating a member
DEX_SUFFIX = ".dex"
MANIFEST_SUFFIX = "androidmanifest.xml"
PERMISSION_RE = re.compile(r'<uses-permission[^>]*android:name="([^"]+)"')
LIB_DIR_RE = re.compile(r"(?:^|/)lib/")  # a lib/ path component, not only a leading one


def class_count_from_dex(data: bytes) -> int:
    """Class count of one dex member; raises whatever androguard raises."""
    from androguard.core.dex import DEX  # lazy: step1 imports it lazily too
    return len(list(DEX(data).get_classes()))


def permissions_from_binary_manifest(data: bytes) -> list[str]:
    """Sorted unique ``<uses-permission>`` names in a binary (AXML) manifest."""
    from androguard.core.axml import AXMLPrinter
    try:
        xml = AXMLPrinter(data).get_xml()
    except Exception as exc:  # androguard fails with TypeError on non-AXML input
        raise ValueError("not a binary (AXML) manifest") from exc
    if xml is None:
        raise ValueError("not a binary (AXML) manifest")
    text = xml.decode("utf-8", "ignore") if isinstance(xml, (bytes, bytearray)) else str(xml)
    return sorted(set(PERMISSION_RE.findall(text)))


def native_lib_names(member_name: str, head: bytes) -> list[str]:
    """Return ``[member_name]`` when the member is a native library, else ``[]``.

    Native means a path with a ``lib/`` component (case-insensitive), a name ending in
    ``.so``, or a head whose first bytes are the ELF magic. The magic check catches
    stripped libraries renamed without an extension. A directory entry (trailing slash)
    is a container, not a library.
    """
    lowered = member_name.lower()
    if lowered.endswith("/"):
        return []
    if LIB_DIR_RE.search(lowered) or lowered.endswith(".so") or head[:4] == ELF_MAGIC:
        return [member_name]
    return []


def _error_text(name: str, exc: Exception) -> str:
    """One diagnostics line for a member that failed to be read or parsed."""
    return f"{name}: {type(exc).__name__}: {str(exc)[:80]}"


def _member_head(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    """Read only the first bytes of a member (a streaming probe, no full inflate)."""
    with archive.open(info) as member:
        return member.read(HEAD_PROBE_BYTES)


def _dex_class_count(archive: zipfile.ZipFile, info: zipfile.ZipInfo, errors: list[str]) -> int:
    """Class count of one dex member, recording the failure instead of raising."""
    try:
        with archive.open(info) as member:
            return class_count_from_dex(member.read())
    except Exception as exc:
        errors.append(_error_text(info.filename, exc))
        return 0


def _member_permissions(
    archive: zipfile.ZipFile, info: zipfile.ZipInfo, errors: list[str]
) -> list[str]:
    """Permissions of one binary-manifest member, recording the failure instead of raising."""
    try:
        with archive.open(info) as member:
            return permissions_from_binary_manifest(member.read())
    except Exception as exc:
        errors.append(_error_text(info.filename, exc))
        return []


@dataclass(frozen=True)
class _Limits:
    """Bounds for one evidence walk (spec section 6)."""

    max_payload_bytes: int
    max_member_bytes: int
    max_dex_members: int
    budget_s: float


@dataclass
class _Tally:
    """Accumulators for one evidence walk; becomes the spec section 8 record."""

    payloads: int = 0
    members_scanned: int = 0
    members_skipped: int = 0
    class_count: int = 0
    charged: int = 0
    truncated: str = "none"
    permissions: set[str] = field(default_factory=set)
    native_libs: set[str] = field(default_factory=set)
    errors: list[str] = field(default_factory=list)

    def cap(self, reason: str) -> None:
        """Record the first cap that bites."""
        if self.truncated == "none":
            self.truncated = reason

    def record(self) -> dict:
        """The sorted evidence record (spec section 8)."""
        return {
            "payloads": self.payloads,
            "members_scanned": self.members_scanned,
            "members_skipped": self.members_skipped,
            "class_count": self.class_count,
            "permissions": sorted(self.permissions),
            "native_libs": sorted(self.native_libs),
            "truncated": self.truncated,
            "errors": self.errors,
        }


def _scan_members(
    archive: zipfile.ZipFile,
    members: list[zipfile.ZipInfo],
    tally: _Tally,
    limits: _Limits,
    started: float,
) -> bool:
    """Walk one payload's members into ``tally``; True asks to stop the whole walk."""
    dex_parsed = 0  # per payload, so a multi-payload recovery is not truncated cumulatively
    for info in members:
        if time.monotonic() - started >= limits.budget_s:
            tally.cap("budget")
            return True
        tally.members_scanned += 1
        if info.file_size > limits.max_member_bytes:
            tally.members_skipped += 1
            tally.cap("bytes")
            continue
        if tally.charged + info.file_size > limits.max_payload_bytes:
            tally.members_skipped += 1
            tally.cap("bytes")
            return True  # over the per-sample budget: stop the whole walk
        # Only members admitted for analysis are charged: a member rejected by the
        # per-member size cap above is never read, so it is not "bytes analysed"
        # (spec section 6). Do not move this above that check.
        tally.charged += info.file_size
        try:
            head = _member_head(archive, info)
        except Exception as exc:
            tally.members_skipped += 1
            tally.errors.append(_error_text(info.filename, exc))
            continue
        tally.native_libs.update(native_lib_names(info.filename, head))
        if info.file_size == 0:
            continue  # a 0-byte member (the observed classes.dex stub) holds no evidence
        name = info.filename.lower()
        if name.endswith(DEX_SUFFIX):
            if dex_parsed >= limits.max_dex_members:
                tally.members_skipped += 1
                tally.cap("members")
                continue
            dex_parsed += 1
            tally.class_count += _dex_class_count(archive, info, tally.errors)
        elif name.endswith(MANIFEST_SUFFIX):
            tally.permissions.update(_member_permissions(archive, info, tally.errors))
    return False


def collect_payload_evidence(
    payloads: Sequence[bytes],
    *,
    max_payload_bytes: int = MAX_PAYLOAD_BYTES,
    max_member_bytes: int = MAX_MEMBER_BYTES,
    max_dex_members: int = MAX_DEX_MEMBERS,
    budget_s: float = EVIDENCE_BUDGET_S,
) -> dict:
    """Collect classes, permissions and native libraries from recovered payloads.

    Payloads are analysed one ZIP level deep; nested ZIPs are counted but not
    opened (spec 4.2). Caps are per-sample for bytes and per-payload for the dex
    count. The returned record is the spec section 8 evidence record. This
    function never raises: every failure becomes an ``errors`` entry.
    """
    limits = _Limits(
        max_payload_bytes=max_payload_bytes,
        max_member_bytes=max_member_bytes,
        max_dex_members=max_dex_members,
        budget_s=budget_s,
    )
    tally = _Tally()
    started = time.monotonic()

    for index, payload in enumerate(payloads):
        if time.monotonic() - started >= budget_s:
            tally.cap("budget")
            break
        if payload[:len(ZIP_MAGIC)] != ZIP_MAGIC:
            continue  # not a ZIP at all: the breaker's structural validation owns this
        try:
            archive = zipfile.ZipFile(io.BytesIO(payload))
            members = archive.infolist()  # inside the try: a hostile ZIP must not raise
        except Exception as exc:
            tally.errors.append(f"payload {index}: {type(exc).__name__}: {str(exc)[:80]}")
            continue
        tally.payloads += 1  # a ZIP-magic payload counts only once its listing succeeded
        with archive:
            if _scan_members(archive, members, tally, limits, started):
                break

    return tally.record()


_EVIDENCE_SIGNAL_KEYS = ("class_count", "permissions", "native_libs")


def _require_signal_keys(evidence: dict) -> None:
    """Fail fast with a message naming what is missing; the pipeline guard logs it.

    ``.get()`` defaults were rejected in review: a record missing a key is a collector
    bug, and merging nothing silently would hide it.
    """
    missing = [key for key in _EVIDENCE_SIGNAL_KEYS if key not in evidence]
    if missing:
        raise ValueError(
            "recovered evidence record is missing required keys: " + ", ".join(missing)
        )


def merge_evidence(extraction: dict, evidence: dict | None) -> dict:
    """Additively merge recovered-payload ``evidence`` into ``extraction`` (spec 4.3).

    Returns a new dict; the input is never mutated. Each signal merges only when the
    evidence carries it: the class count as ``max`` of stub and payload (spec 4.4), the
    others as sorted unions. The full evidence record is kept under
    ``recovered_payload_evidence`` for provenance whenever ``evidence`` is truthy. A
    falsy ``evidence`` (``{}`` or ``None``) returns a copy of ``extraction`` unchanged.

    The class-count ``max`` is the subject of spec 4.4's documented fallback: the
    evaluation A/B measures it, and if that shows it hurts the metric the class-count
    merge is dropped downstream - the payload's count then survives only in
    ``recovered_payload_evidence["class_count"]``, a key no signature band consumes.
    That decision is downstream; this function always applies ``max``.
    """
    if not evidence:
        return dict(extraction)
    _require_signal_keys(evidence)
    merged = dict(extraction)
    if evidence["class_count"]:
        merged["decompiled_classes"] = max(
            merged.get("decompiled_classes", 0), evidence["class_count"]
        )
    if evidence["native_libs"]:
        merged["native_libs_found"] = sorted(
            set(merged.get("native_libs_found", [])) | set(evidence["native_libs"])
        )
    manifest_info = dict(merged.get("manifest_info", {}))
    if evidence["permissions"]:
        manifest_info["uses_permissions"] = sorted(
            set(manifest_info.get("uses_permissions", [])) | set(evidence["permissions"])
        )
    merged["manifest_info"] = manifest_info
    merged["recovered_payload_evidence"] = evidence
    return merged
