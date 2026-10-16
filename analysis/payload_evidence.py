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


def class_count_from_dex(data: bytes) -> int:
    """Class count of one dex member; raises whatever androguard raises."""
    from androguard.core.dex import DEX  # lazy: step1 imports it lazily too
    return len(list(DEX(data).get_classes()))


def permissions_from_binary_manifest(data: bytes) -> list[str]:
    """Sorted unique ``<uses-permission>`` names in a binary (AXML) manifest."""
    from androguard.core.axml import AXMLPrinter
    xml = AXMLPrinter(data).get_xml()  # raises on non-AXML input
    text = xml.decode("utf-8", "ignore") if isinstance(xml, (bytes, bytearray)) else str(xml)
    return sorted(set(PERMISSION_RE.findall(text)))


def native_lib_names(member_name: str, head: bytes) -> list[str]:
    """Return ``[member_name]`` when the member is a native library, else ``[]``.

    Native means a path under ``lib/`` (case-insensitive), a name ending in
    ``.so``, or a head whose first bytes are the ELF magic. The magic check
    catches stripped libraries renamed without an extension.
    """
    lowered = member_name.lower()
    if lowered.startswith("lib/") or lowered.endswith(".so") or head[:4] == ELF_MAGIC:
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
    started = time.monotonic()
    truncated = "none"

    def cap(reason: str) -> None:
        nonlocal truncated
        if truncated == "none":  # the first cap that bites wins
            truncated = reason

    analysed = 0
    scanned = 0
    skipped = 0
    class_count = 0
    charged = 0  # declared member bytes charged to the per-sample budget
    permissions: set[str] = set()
    native_libs: set[str] = set()
    errors: list[str] = []
    stop = False

    for index, payload in enumerate(payloads):
        if time.monotonic() - started >= budget_s:
            cap("budget")
            break
        if payload[:len(ZIP_MAGIC)] != ZIP_MAGIC:
            continue  # not a ZIP at all: the breaker's structural validation owns this
        try:
            archive = zipfile.ZipFile(io.BytesIO(payload))
        except Exception as exc:
            errors.append(f"payload {index}: {type(exc).__name__}: {str(exc)[:80]}")
            continue
        analysed += 1
        dex_parsed = 0  # per payload, so a multi-payload recovery is not truncated cumulatively

        with archive:
            for info in archive.infolist():
                if time.monotonic() - started >= budget_s:
                    cap("budget")
                    stop = True
                    break
                scanned += 1
                if info.file_size > max_member_bytes:
                    skipped += 1
                    cap("bytes")
                    continue
                if charged + info.file_size > max_payload_bytes:
                    skipped += 1
                    cap("bytes")
                    stop = True
                    break  # over the per-sample budget: stop the whole walk
                charged += info.file_size
                try:
                    head = _member_head(archive, info)
                except Exception as exc:
                    skipped += 1
                    errors.append(_error_text(info.filename, exc))
                    continue
                native_libs.update(native_lib_names(info.filename, head))
                if info.file_size == 0:
                    continue  # a 0-byte member (the observed classes.dex stub) holds no evidence
                name = info.filename.lower()
                if name.endswith(DEX_SUFFIX):
                    if dex_parsed >= max_dex_members:
                        skipped += 1
                        cap("members")
                        continue
                    dex_parsed += 1
                    class_count += _dex_class_count(archive, info, errors)
                elif name.endswith(MANIFEST_SUFFIX):
                    permissions.update(_member_permissions(archive, info, errors))
        if stop:
            break

    return {
        "payloads": analysed,
        "members_scanned": scanned,
        "members_skipped": skipped,
        "class_count": class_count,
        "permissions": sorted(permissions),
        "native_libs": sorted(native_libs),
        "truncated": truncated,
        "errors": errors,
    }
