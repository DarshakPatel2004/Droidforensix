"""Where candidate seed material comes from.

Four providers, cheapest and most likely first:

* P1 ``name_variants`` - the member's own name, which packers reuse as a key.
* P2 ``mine_strings`` / ``SeedPlan`` - printable strings in members we can already read.
* P3 ``load_extra_seeds`` - seeds supplied from outside (for example a ``key_log`` recorded
  by static tracing or an emulator run). This module only reads that file; it never runs a
  sample.
* P4 ``numeric_candidates`` - a purely numeric member name, which is how the Java-LCG
  family derives its seed (verified: asset 3664888858717845462 -> +0xFFFF).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

MAX_STRINGS_DEFAULT = 2000
MIN_STRING_LEN = 4
MAX_STRING_LEN = 96
PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{4,}")
EXTRA_SEED_KINDS = ("getBytes", "digest")
U32_MASK = 0xFFFFFFFF
SIGNED64_MASK = (1 << 64) - 1
SIGNED64_SIGN = 1 << 63


@dataclass(frozen=True)
class SeedCandidate:
    material: str
    provenance: str
    numeric: bool = False


def mine_strings(
    data: bytes, *, min_len: int = MIN_STRING_LEN, max_len: int = MAX_STRING_LEN
) -> list[bytes]:
    """Printable ASCII runs of a useful length, in order of first appearance."""
    out: list[bytes] = []
    seen: set[bytes] = set()
    for match in PRINTABLE_RUN.finditer(data):
        run = match.group(0)
        if not min_len <= len(run) <= max_len or run in seen:
            continue
        seen.add(run)
        out.append(run)
    return out


def name_variants(stem: str) -> list[SeedCandidate]:
    candidates = [(stem, "name:stem"), (stem.lower(), "name:lower"), (stem.upper(), "name:upper")]
    candidates += [(f"{stem}{digit}", f"name:+{digit}") for digit in "0123456789"]
    out: list[SeedCandidate] = []
    seen: set[str] = set()
    for material, provenance in candidates:
        if material in seen:
            continue
        seen.add(material)
        out.append(SeedCandidate(material, provenance))
    return out


def numeric_candidates(stem: str) -> list[SeedCandidate]:
    """Seed deltas for a numeric member name; used by the Java-LCG family only."""
    if not stem.isdigit():
        return []
    value = int(stem)
    deltas = [
        (value, "numeric:n"),
        (value + 1, "numeric:+1"),
        (value - 1, "numeric:-1"),
        (value + 0xFFFF, "numeric:+0xffff"),
        (value - 0xFFFF, "numeric:-0xffff"),
        (value + 0x10000, "numeric:+0x10000"),
        (value & U32_MASK, "numeric:u32"),
    ]
    out: list[SeedCandidate] = []
    seen: set[str] = set()
    for delta, provenance in deltas:
        material = str(_signed64(delta))
        if material in seen:
            continue
        seen.add(material)
        out.append(SeedCandidate(material, provenance, numeric=True))
    return out


def _signed64(value: int) -> int:
    masked = value & SIGNED64_MASK
    return masked - (SIGNED64_MASK + 1) if masked >= SIGNED64_SIGN else masked


def load_extra_seeds(path: Path | str) -> list[SeedCandidate]:
    """Read seeds from outside: a JSON array, ``{"seeds": [...]}`` or ``{"key_log": [...]}``."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return [SeedCandidate(item, "extra") for item in payload if isinstance(item, str)]
    if not isinstance(payload, dict):
        raise ValueError(f"unsupported extra-seed file shape: {type(payload).__name__}")
    if "seeds" in payload:
        return [SeedCandidate(item, "extra") for item in payload["seeds"] if isinstance(item, str)]
    if "key_log" not in payload:
        raise ValueError("extra-seed file has neither 'seeds' nor 'key_log'")
    out: list[SeedCandidate] = []
    for entry in payload["key_log"]:
        if not isinstance(entry, (list, tuple)) or len(entry) != 2:
            continue
        kind, value = entry
        if kind not in EXTRA_SEED_KINDS:
            continue
        material = _coerce_material(value)
        if material is not None:
            out.append(SeedCandidate(material, f"extra:{kind}"))
    return out


def _coerce_material(value: object) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, list) and value and all(isinstance(byte, int) for byte in value):
        try:
            return bytes(value).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None
    return None


@dataclass
class SeedPlan:
    """Every seed the engine will feed into the scheme matrix for one APK."""

    mined: list[SeedCandidate] = field(default_factory=list)
    extra: list[SeedCandidate] = field(default_factory=list)

    def add_strings(self, data: bytes, *, cap: int = MAX_STRINGS_DEFAULT) -> None:
        if len(self.mined) >= cap:
            return
        seen = {candidate.material for candidate in self.mined}
        for run in mine_strings(data):
            if len(self.mined) >= cap:
                return
            material = run.decode("latin-1")
            if material in seen:
                continue
            seen.add(material)
            self.mined.append(SeedCandidate(material, "mined"))


def plan_from_collection(collection, *, extra_path=None, max_strings: int = MAX_STRINGS_DEFAULT) -> SeedPlan:
    plan = SeedPlan()
    for _name, data in collection.plaintext:
        plan.add_strings(data, cap=max_strings)
    if extra_path is not None:
        plan.extra.extend(load_extra_seeds(extra_path))
    return plan
