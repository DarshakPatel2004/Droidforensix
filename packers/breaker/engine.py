"""The search engine: probe cheaply, validate strongly, then attack inside a budget.

Validation is deliberately two-stage. The probe decrypts a 16-byte-aligned prefix and
looks for a payload magic, which is cheap enough to run hundreds of thousands of times
but can match by chance (roughly one in 2^16 for a two-byte magic). Only a probe match
earns a full decrypt plus :func:`validate_payload`, and only strong validation can
produce a hit. Probe matches that fail validation are counted, never reported.
"""
from __future__ import annotations

import hashlib
import io
import json
import struct
import time
import zipfile
import zlib
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path

from packers.breaker.blobs import (
    E_KDF_BUDGET,
    E_KDF_EXHAUSTED,
    PENDING,
    PROBE_MAGICS,
    RECOVERED,
    Blob,
    MemberRecord,
    collect_from_zip,
)
from packers.breaker.schemes import (
    Scheme,
    decrypt,
    derive,
    matrix_schemes,
    prior_schemes,
    single_byte_xor_schemes,
)
from packers.breaker.seeds import (
    SeedPlan,
    name_variants,
    numeric_candidates,
    plan_from_collection,
)
from packers.framework import validate_dex, validate_zip

PROBE_LEN = 48
BLOCK_SIZE = 16
ARTIFACT_CAP = 50
OUT_DIR_DIGEST_CHARS = 16
EOCD_SEARCH_WINDOW = 65557
ZIP_EOCD_SIG = b"PK\x05\x06"
DEX_MAGIC = b"dex\n"
ELF_MAGIC = b"\x7fELF"
TTF_MAGIC = b"\x00\x01\x00\x00"
JSON_MAGIC = b"{"


@dataclass(frozen=True)
class Validation:
    """What a successful candidate turned out to be, and how strongly we know it."""

    kind: str
    evidence: str


def probe_matches(scheme: Scheme, data: bytes) -> bool:
    """Decrypt a 16-byte-aligned prefix of ``data`` and look for a payload magic."""
    if len(data) < BLOCK_SIZE:
        return False
    length = PROBE_LEN if len(data) >= PROBE_LEN else len(data) - (len(data) % BLOCK_SIZE)
    if length < BLOCK_SIZE:
        return False
    try:
        plaintext = decrypt(scheme, data[:length])
    except (ValueError, TypeError):
        return False
    return any(plaintext.startswith(signature) for signature, _kind in PROBE_MAGICS)


def validate_payload(data: bytes) -> Validation | None:
    """Strong structural validation, strongest evidence first. Never raises."""
    zip_evidence = _zip_evidence(data)
    if zip_evidence:
        return Validation("zip", zip_evidence)
    dex_evidence = _dex_evidence(data)
    if dex_evidence:
        return Validation("dex", dex_evidence)
    if _is_gzip(data):
        return Validation("gzip", "gzip")
    if _is_elf(data):
        return Validation("elf", "elf")
    if _is_json(data):
        return Validation("json", "json")
    if data.startswith(TTF_MAGIC):
        return Validation("ttf", "ttf-magic")
    return None


def _zip_evidence(data: bytes) -> str | None:
    if data[:4] != b"PK\x03\x04":
        return None
    try:
        ok, _info = validate_zip(data)
    except Exception:
        # zipfile can raise struct/OS errors on hostile input; a broken payload must never
        # abort a batch run. Fall through to the weaker evidence level instead.
        ok = False
    if ok:
        return "zip-strict"
    if ZIP_EOCD_SIG in data[-EOCD_SEARCH_WINDOW:]:
        return "zip-eocd"
    return None


def _dex_evidence(data: bytes) -> str | None:
    if not validate_dex(data):
        return None
    if len(data) >= 36 and struct.unpack("<I", data[32:36])[0] == len(data):
        return "dex-header"
    return "dex-magic"


def _is_gzip(data: bytes) -> bool:
    if data[:2] != b"\x1f\x8b":
        return False
    try:
        zlib.decompress(data, 16 + zlib.MAX_WBITS)
    except Exception:
        # Any malformed or hostile stream is simply not a gzip payload; validation must never
        # propagate an exception into the search loop.
        return False
    return True


def _is_elf(data: bytes) -> bool:
    return data.startswith(ELF_MAGIC) and len(data) > 64 and data[4] in (1, 2)


def _is_json(data: bytes) -> bool:
    if data[:1] != JSON_MAGIC:
        return False
    try:
        json.loads(data)
    except Exception:
        # ValueError covers malformed JSON, UnicodeDecodeError bad encodings, and RecursionError
        # a deeply nested payload. None of them is a reason to abort a run.
        return False
    return True


@dataclass
class Hit:
    """A recovered payload. ``key_hex``/``iv_hex`` are key material: local files only."""

    member: str
    content: str
    seed: str
    provenance: list[str]
    scheme: dict
    key_sha256: str
    key_hex: str
    iv_hex: str | None
    payload_sha256: str
    validation: str
    artifacts: list[dict]
    artifacts_total: int
    children: list["Hit"] = field(default_factory=list)


@dataclass
class ApkResult:
    apk: str
    sha256: str
    hits: list[Hit]
    members: list[MemberRecord]
    scheme_count: int
    wall_s: float
    outcome: str
    ciphertext_members: int
    attempts_total: int
    truncated: str


@dataclass
class _Budget:
    """One wall clock and one attempt cap for the whole APK. First shortage wins."""

    attempts_cap: int
    deadline: float
    attempts: int = 0
    truncated: str = "none"

    def spend(self) -> bool:
        if self.attempts >= self.attempts_cap:
            self._mark("attempts")
            return False
        if time.monotonic() >= self.deadline:
            self._mark("time")
            return False
        self.attempts += 1
        return True

    def _mark(self, reason: str) -> None:
        if self.truncated == "none":
            self.truncated = reason


@dataclass
class _BlobOutcome:
    hit: Hit | None
    payload: bytes | None
    enumerated: int


# A blob to attack and the parent hit when it came out of a recovered container.
_WorkItem = tuple[Blob, Hit | None]


def break_apk(
    apk_path: Path | str,
    out_dir: Path | str,
    *,
    attempts_cap: int = 200_000,
    budget_s: float = 300.0,
    depth: int = 3,
    seeds_extra: Path | str | None = None,
    max_strings: int = 2000,
) -> ApkResult:
    """Attack every candidate member of one APK and write the honesty-preserving outputs."""
    started = time.monotonic()
    apk_path = Path(apk_path)
    raw = apk_path.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    collection = collect_from_zip(raw, depth=0)
    plan = plan_from_collection(collection, extra_path=seeds_extra, max_strings=max_strings)
    budget = _Budget(attempts_cap=attempts_cap, deadline=started + budget_s)
    hits, scheme_count = _sweep(collection.blobs, plan, budget, depth, collection)
    _close_books(collection)
    collection.records.sort(key=lambda record: record.name)
    result = ApkResult(
        apk=str(apk_path),
        sha256=sha256,
        hits=hits,
        members=collection.records,
        scheme_count=scheme_count,
        wall_s=time.monotonic() - started,
        outcome=_outcome(hits, budget),
        ciphertext_members=sum(
            1 for record in collection.records
            if record.outcome in (RECOVERED, E_KDF_EXHAUSTED, E_KDF_BUDGET)
        ),
        attempts_total=budget.attempts,
        truncated=budget.truncated,
    )
    _write_outputs(Path(out_dir), result, collection)
    return result


def _outcome(hits: list[Hit], budget: _Budget) -> str:
    if hits:
        return RECOVERED
    return E_KDF_BUDGET if budget.truncated != "none" else E_KDF_EXHAUSTED


def _candidate_stream(stem: str, plan: SeedPlan, tier: str) -> Iterator[Scheme]:
    """Candidates for one member, split into the cheap tier and the deep tier.

    ``cheap`` is the closed-form known recipes (a few hundred probes each); ``deep`` is the
    combinatorial matrix and the degenerate sweeps. The tiers are disjoint: the sweep runs a
    member's cheap tier before any member's deep tier, so the deep tier must not re-probe what
    the cheap tier already tried - that would double the budget and the ``space_size`` count.
    """
    if tier == "cheap":
        yield from prior_schemes(stem)
        return
    for candidate in name_variants(stem):
        yield from matrix_schemes(candidate.material, candidate.provenance)
    for candidate in plan.mined:
        yield from matrix_schemes(candidate.material, candidate.provenance)
    for candidate in plan.extra:
        yield from matrix_schemes(candidate.material, candidate.provenance)
    yield from single_byte_xor_schemes()
    for candidate in numeric_candidates(stem):
        yield Scheme(seed=candidate.material, cipher="java-lcg", provenance=candidate.provenance)


def _sweep(
    blobs: list[Blob],
    plan: SeedPlan,
    budget: _Budget,
    depth: int,
    collection,
) -> tuple[list[Hit], int]:
    """Attack a list of blobs cheapest-first, and return the hits found.

    Work is a FIFO queue drained in two phases: every member's closed-form recipes (a few
    hundred probes each) run before any member starts its combinatorial deep search, and that
    holds across recovered containers too. Without the ordering a single member's deep sweep
    - or a recovered container's inline nested sweep - starves every other member's known
    recipe, which is exactly what the corpus measurement showed: a 274 KB pinned member went
    unprobed while an earlier member spent the whole APK budget.
    """
    found: list[Hit] = []
    enumerated = 0
    cheap: list[_WorkItem] = [(blob, None) for blob in blobs]
    while cheap:
        deep: list[_WorkItem] = []
        while cheap:
            blob, parent = cheap.pop(0)
            record = blob.record
            if record.outcome == RECOVERED:
                continue
            outcome = _attack_blob(blob, plan, budget, record, tier="cheap")
            enumerated += outcome.enumerated
            deep.append((blob, parent))
            if outcome.hit is None:
                continue
            _attach(found, parent, outcome.hit)
            cheap.extend(_nested_entries(outcome, blob, depth, plan, collection))
        while deep:
            blob, parent = deep.pop(0)
            record = blob.record
            if record.outcome == RECOVERED:
                continue
            outcome = _attack_blob(blob, plan, budget, record, tier="deep")
            enumerated += outcome.enumerated
            if outcome.hit is None:
                continue
            _attach(found, parent, outcome.hit)
            cheap.extend(_nested_entries(outcome, blob, depth, plan, collection))
    return found, enumerated


def _attach(found: list[Hit], parent: Hit | None, hit: Hit) -> None:
    if parent is None:
        found.append(hit)
    else:
        parent.children.append(hit)


def _close_books(collection) -> None:
    """Assert the two coverage invariants before any output is written.

    A leftover ``PENDING`` row means a member was probed (or skipped) without a verdict, and an
    unbalanced member count means members vanished from the report. Both are bugs, not
    conditions to paper over, so they raise instead of shipping a dishonest coverage file.
    """
    pending = sorted(record.name for record in collection.records if record.outcome == PENDING)
    if pending:
        raise RuntimeError(f"coverage rows left unresolved: {pending[:5]}")
    accounted = (
        len(collection.records)
        + collection.members_ignored_dirs
        + collection.members_out_of_scope
    )
    if accounted != collection.members_total:
        raise RuntimeError(
            f"member book does not balance: {accounted} accounted != "
            f"{collection.members_total} total"
        )


def _nested_entries(
    outcome: _BlobOutcome,
    blob: Blob,
    depth: int,
    plan: SeedPlan,
    collection,
) -> list[_WorkItem]:
    """Next-depth work items for a recovered container: fold in its rows and mine its strings."""
    if outcome.payload is None or blob.depth + 1 >= depth:
        return []
    if outcome.hit.validation not in ("zip-strict", "zip-eocd"):
        return []
    try:
        children = collect_from_zip(outcome.payload, depth=blob.depth + 1, prefix=outcome.hit.member + "!")
    except Exception:
        # zip-eocd passed the weak evidence check but the payload is not readable (zipfile
        # raises on hostile input). The hit stands; it simply has no members to recurse into.
        return []
    collection.members_total += children.members_total
    collection.members_ignored_dirs += children.members_ignored_dirs
    collection.members_out_of_scope += children.members_out_of_scope
    collection.records.extend(children.records)
    for _name, data in children.plaintext:
        plan.add_strings(data)
    return [(child_blob, outcome.hit) for child_blob in children.blobs]


def _attack_blob(
    blob: Blob,
    plan: SeedPlan,
    budget: _Budget,
    record: MemberRecord,
    *,
    tier: str = "deep",
) -> _BlobOutcome:
    """Probe every distinct candidate for one blob and update its coverage row.

    Dedupe is per member: a key that already failed against this ciphertext is not worth
    spending again, but the very same key must still be tried against every other member.
    """
    start_attempts = budget.attempts
    enumerated = 0
    seen: set[tuple[str, str, str]] = set()
    hit: Hit | None = None
    payload: bytes | None = None
    for scheme in _candidate_stream(_stem_of(blob.member), plan, tier):
        enumerated += 1
        key, iv = derive(scheme)
        identity = (scheme.cipher, key.hex(), iv.hex())
        if identity in seen:
            continue
        seen.add(identity)
        if not budget.spend():
            record.truncation = budget.truncated
            break
        matched = _probe_candidate(blob, scheme, key, iv, record)
        if matched is not None:
            hit, payload = matched
            break
    record.space_size += enumerated
    record.attempts += budget.attempts - start_attempts
    record.outcome = (
        RECOVERED if hit is not None
        else E_KDF_BUDGET if budget.truncated != "none"
        else E_KDF_EXHAUSTED
    )
    return _BlobOutcome(hit=hit, payload=payload, enumerated=enumerated)


def _probe_candidate(
    blob: Blob, scheme: Scheme, key: bytes, iv: bytes, record: MemberRecord
) -> tuple[Hit, bytes] | None:
    if not probe_matches(scheme, blob.data):
        return None
    try:
        payload = decrypt(scheme, blob.data)
    except (ValueError, TypeError):
        record.probe_false_positives += 1
        return None
    validation = validate_payload(payload)
    if validation is None:
        record.probe_false_positives += 1
        return None
    return _build_hit(blob, scheme, key, iv, payload, validation), payload


def _build_hit(
    blob: Blob, scheme: Scheme, key: bytes, iv: bytes, plaintext: bytes, validation: Validation
) -> Hit:
    artifacts, artifacts_total = _payload_artifacts(plaintext)
    return Hit(
        member=blob.member,
        content=blob.content,
        seed=scheme.seed,
        provenance=[scheme.provenance] if scheme.provenance else [],
        scheme={
            "cipher": scheme.cipher,
            "key_hash": scheme.key_hash,
            "key_len": scheme.key_len,
            "iv": scheme.iv,
            "xor_mode": scheme.xor_mode,
            "seed": scheme.seed,
            "provenance": scheme.provenance,
        },
        key_sha256=hashlib.sha256(key).hexdigest(),
        key_hex=key.hex(),
        iv_hex=iv.hex() if iv else None,
        payload_sha256=hashlib.sha256(plaintext).hexdigest(),
        validation=validation.evidence,
        artifacts=artifacts,
        artifacts_total=artifacts_total,
    )


def _payload_artifacts(data: bytes) -> tuple[list[dict], int]:
    """List the files inside a recovered ZIP payload (capped); empty for other payloads."""
    if data[:4] != b"PK\x03\x04":
        return [], 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = [info.filename for info in archive.infolist() if not info.filename.endswith("/")]
            artifacts = []
            for name in names[:ARTIFACT_CAP]:
                try:
                    member = archive.read(name)
                except Exception:
                    continue
                artifacts.append(
                    {"file": name, "sha256": hashlib.sha256(member).hexdigest(), "size": len(member)}
                )
            return artifacts, len(names)
    except Exception:
        return [], 0


def _stem_of(member: str) -> str:
    """The packer's own name for this member: strip any recursion prefix, then the directory."""
    return member.rsplit("!", 1)[-1].rsplit("/", 1)[-1]


def _write_outputs(out_dir: Path, result: ApkResult, collection) -> None:
    target = out_dir / result.sha256[:OUT_DIR_DIGEST_CHARS]
    target.mkdir(parents=True, exist_ok=True)
    hits_payload = {"apk": result.apk, "sha256": result.sha256, "hits": [asdict(h) for h in result.hits]}
    (target / "hit.json").write_text(json.dumps(hits_payload, indent=2), encoding="utf-8")
    coverage = {
        "apk": result.apk,
        "sha256": result.sha256,
        "wall_s": result.wall_s,
        "outcome": result.outcome,
        "truncated": result.truncated,
        "scheme_count": result.scheme_count,
        "attempts_total": result.attempts_total,
        "ciphertext_members": result.ciphertext_members,
        "members_total": collection.members_total,
        "members_ignored_dirs": collection.members_ignored_dirs,
        "members_out_of_scope": collection.members_out_of_scope,
        "members": [asdict(record) for record in result.members],
    }
    (target / "coverage.json").write_text(json.dumps(coverage, indent=2), encoding="utf-8")
