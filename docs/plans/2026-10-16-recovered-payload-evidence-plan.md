# Recovered Payload Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Merge the real class count, manifest permissions, and native libraries of a breaker-recovered payload into the classifier's inputs, additively and statically.

**Architecture:** A new pure module `analysis/payload_evidence.py` walks each recovered payload ZIP in memory (androguard `DEX` for class counts, `AXMLPrinter` for the binary manifest, a path/ELF-magic sniff for natives) behind four named caps, and returns a provenance record. `analysis/step0_master_key.py` attaches that record when the second chance recovers a ZIP payload; `analysis/pipeline.py` merges it into the single `extraction` dict that `family_id` and both result assemblies already read.

**Tech Stack:** Python 3.11 via `.venv\Scripts\python.exe`; pytest; androguard 4.1.4 (already required by Step 1, imported lazily inside functions); stdlib `zipfile`/`io`/`re`/`time`. No new dependency.

**Spec:** `docs/plans/specs/2026-10-16-recovered-payload-evidence-design.md`

## Global Constraints

- Additive only: `max()` for the class count, sorted unions for permissions and native libraries. Never delete a stub value.
- Caps, as named constants with parameter defaults: `MAX_PAYLOAD_BYTES = 64 * 1024 * 1024`, `MAX_MEMBER_BYTES = 32 * 1024 * 1024`, `MAX_DEX_MEMBERS = 64`, `EVIDENCE_BUDGET_S = 20.0`.
- `MAX_DEX_MEMBERS` is **per payload** (the counter resets for each payload), unlike `MAX_PAYLOAD_BYTES`, which is per sample. Measured reason: PNB ONE ACTIVATION's `assets/trustifying` alone carries 63 dex members and the sample's seven ZIP payloads carry 65, so a per-sample counter at 64 silently dropped the 1146-class `assets/wyvhtvmqlcbfmi9w/bhtn0kbg` payload (measured 5866 classes, `truncated == "members"`) instead of the true 7012 classes with `truncated == "none"`.
- `collect_payload_evidence` never raises: every parser failure contributes nothing and is recorded as a string in `errors`.
- Static only: payload code is never executed; no new dependency; no new files on disk (evidence lives in memory and in the result dict).
- No key material in the evidence record or in the returned master-key report (`key_hex` stays in the gitignored `analysis/master_key_breaker/<sha16>/hit.json`).
- `ecode` never carries a breaker or evidence outcome.
- Analyzed payloads are ZIP-validated breaker hits only (`hit.validation.startswith("zip")`). Non-ZIP recoveries (the `json`/`dex` ones) and dispatcher (`_attempt_unpack`) recoveries produce no evidence.
- Untouched: `packers/breaker/*`, `scripts/unpack.py`, the unpack recovery path, `enrich_strings_with_recovered` (string enrichment stays ZIP-only and unchanged).
- Only ZIP members at the payload's top level are analyzed; nested members (e.g. `payload_split*.apk` inside a myg0N `kit.zip`) are a documented follow-up.
- Suite gate: `pytest tests/ -m "not slow"` green (bare `pytest` fails on pre-existing collection errors). PowerShell shell; commits use the repo's lowercase `scope: summary` style.

## Review Focus

Inputs a person running this on a packed APK will hit that the spec implies but no single step's happy path exercises. Each line's test is added to the task that owns the code.

1. **A payload whose dex/permissions live in nested `.apk` members** (the myg0N `kit.zip` shape: measured 5 classes / 0 permissions / 0 natives for `analysis/unpack_baseline/348f8b090b51ba27/kit.zip`). Expected: nothing is extracted, no error. Task 1: `test_nested_apk_members_contribute_nothing`.
2. **A payload whose dex members sum past 64 MiB** (no local sample does — PNB ONE ACTIVATION's seven ZIP payloads total 10.1 MB of dex — but a decompression bomb or a 100 MB multidex app would). Expected: a partial class count, `truncated == "bytes"`, no crash. Task 1: `test_collect_stops_at_the_total_bytes_cap`.
3. **A recovered class count far outside the stub-calibrated bands** (measured 5448-7012 classes for real recovered apps). Expected: `classes:` signature signals can disappear; only the measured A/B reveals whether that helps. Task 5: the off/on delta and the §4.4 fallback.
4. **Payload native libraries flipping `native:no` to `native:yes`.** Expected: faithful to the real app. Task 4: `test_real_recovered_app_yields_native_library_evidence`, plus Task 5's per-sample report.
5. **A hostile or corrupt ZIP payload** (valid `PK` magic, broken central directory, or a member whose declared size exceeds the caps). Expected: no evidence, an `errors` entry, no unbounded read. Tasks 1: `test_collect_records_a_broken_zip_and_keeps_going`, `test_collect_stops_at_the_per_member_size_cap`.

---

### Task 1: The evidence collector

**Files:**
- Create: `analysis/payload_evidence.py`
- Test: `tests/test_payload_evidence.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `class_count_from_dex(data: bytes) -> int` — class count of one dex member; raises whatever androguard raises on undecodable input (the collector isolates it).
  - `permissions_from_binary_manifest(data: bytes) -> list[str]` — sorted unique `android:name` values of `<uses-permission>` in a binary (AXML) manifest; raises on undecodable input.
  - `native_lib_names(member_name: str, head: bytes) -> list[str]` — `[member_name]` when the member is a native library, else `[]`. Native means: path under `lib/` (case-insensitive), name ends in `.so`, or `head[:4] == b"\x7fELF"`.
  - `collect_payload_evidence(payloads: Sequence[bytes], *, max_payload_bytes: int = MAX_PAYLOAD_BYTES, max_member_bytes: int = MAX_MEMBER_BYTES, max_dex_members: int = MAX_DEX_MEMBERS, budget_s: float = EVIDENCE_BUDGET_S) -> dict` — the record documented in spec §8:
    `{"payloads": int, "members_scanned": int, "members_skipped": int, "class_count": int, "permissions": [str], "native_libs": [str], "truncated": "none"|"bytes"|"members"|"budget", "errors": [str]}`, with `permissions`/`native_libs` sorted and `class_count` the sum over parsed dex members. `max_dex_members` is applied per payload; `max_payload_bytes` per sample.

- [x] **Step 1: Write the failing helper tests**

Create `tests/test_payload_evidence.py`:

```python
"""Unit tests for analysis/payload_evidence.py (spec 2026-10-16)."""
import io
import zipfile

import pytest

from analysis import payload_evidence as pe


def _zip(members: dict[str, bytes]) -> bytes:
    """A payload ZIP; infolist() preserves this insertion order."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def test_native_lib_names_matches_lib_path_so_suffix_and_elf_magic():
    assert pe.native_lib_names("lib/arm64-v8a/libx.so", b"") == ["lib/arm64-v8a/libx.so"]
    assert pe.native_lib_names("assets/x.so", b"") == ["assets/x.so"]
    assert pe.native_lib_names("arm64-v8a", b"\x7fELFrest") == ["arm64-v8a"]
    assert pe.native_lib_names("res/drawable/icon.png", b"\x89PNG") == []


def test_class_count_from_dex_rejects_undecodable_bytes():
    with pytest.raises(Exception):
        pe.class_count_from_dex(b"not a dex at all")


def test_permissions_from_binary_manifest_rejects_non_axml():
    with pytest.raises(Exception):
        pe.permissions_from_binary_manifest(b"not xml")
```

- [x] **Step 2: Run the helper tests to verify they fail**

Run: `.venv\Scripts\python.exe -m pytest tests/test_payload_evidence.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'analysis.payload_evidence'`.

- [x] **Step 3: Implement the helpers**

Create `analysis/payload_evidence.py`. Module docstring points at the spec path and says evidence is static, bounded, and never raises from `collect_payload_evidence`. Define the four constants and:

```python
ZIP_MAGIC = b"PK\x03\x04"
ELF_MAGIC = b"\x7fELF"
PERMISSION_RE = re.compile(r'<uses-permission[^>]*android:name="([^"]+)"')

def class_count_from_dex(data: bytes) -> int:
    from androguard.core.dex import DEX          # lazy: step1 imports it lazily too
    return len(list(DEX(data).get_classes()))

def permissions_from_binary_manifest(data: bytes) -> list[str]:
    from androguard.core.axml import AXMLPrinter
    xml = AXMLPrinter(data).get_xml()            # raises on non-AXML input
    text = xml.decode("utf-8", "ignore") if isinstance(xml, (bytes, bytearray)) else str(xml)
    return sorted(set(PERMISSION_RE.findall(text)))
```

`native_lib_names(member_name, head)` is a one-line predicate returning `[member_name]` or `[]`, per the Interfaces block. Use `logging.getLogger(__name__)` for the module logger.

- [x] **Step 4: Run the helper tests to verify they pass**

Run: `.venv\Scripts\python.exe -m pytest tests/test_payload_evidence.py -v`
Expected: 3 passed. (androguard logs through loguru; the `DEX`/`AXMLPrinter` debug lines are noise, not failures.)

- [x] **Step 5: Write the failing collector tests**

Append to `tests/test_payload_evidence.py`:

```python
def test_collect_ignores_payloads_without_zip_magic():
    evidence = pe.collect_payload_evidence([b"not a zip at all"])
    assert evidence["payloads"] == 0
    assert evidence["members_scanned"] == 0
    assert evidence["truncated"] == "none"
    assert evidence["errors"] == []


def test_collect_records_a_broken_zip_and_keeps_going():
    broken = b"PK\x03\x04" + b"garbage-central-directory"
    good = _zip({"lib/armeabi-v7a/libx.so": b"\x7fELF" + b"\x00" * 8})
    evidence = pe.collect_payload_evidence([broken, good])
    assert evidence["payloads"] == 1
    assert evidence["native_libs"] == ["lib/armeabi-v7a/libx.so"]
    assert any("BadZipFile" in e or "payload 0" in e for e in evidence["errors"])


def test_collect_skips_zero_byte_dex_without_an_error():
    evidence = pe.collect_payload_evidence([_zip({"classes.dex": b""})])
    assert evidence["class_count"] == 0
    assert evidence["errors"] == []
    assert evidence["members_scanned"] == 1


def test_collect_records_dex_and_manifest_parse_failures():
    payload = _zip({"classes.dex": b"x" * 16, "AndroidManifest.xml": b"nope"})
    evidence = pe.collect_payload_evidence([payload])
    assert evidence["class_count"] == 0
    assert evidence["permissions"] == []
    assert len(evidence["errors"]) == 2


def test_collect_finds_natives_by_path_and_by_elf_magic():
    payload = _zip({
        "lib/armeabi-v7a/libx.so": b"\x00" * 8,
        "assets/arm64": b"\x7fELF" + b"\x00" * 8,
        "res/raw/a.bin": b"data",
    })
    evidence = pe.collect_payload_evidence([payload])
    assert evidence["native_libs"] == ["assets/arm64", "lib/armeabi-v7a/libx.so"]
    assert evidence["members_scanned"] == 3


def test_collect_stops_at_the_per_member_size_cap():
    payload = _zip({"classes.dex": b"x" * 16, "assets/big.bin": b"y" * 16})
    evidence = pe.collect_payload_evidence([payload], max_member_bytes=8)
    assert evidence["truncated"] == "bytes"
    assert evidence["members_scanned"] == 2
    assert evidence["members_skipped"] == 2
    assert evidence["class_count"] == 0


def test_collect_stops_at_the_total_bytes_cap():
    payload = _zip({"classes.dex": b"x" * 16, "assets/big.bin": b"y" * 16})
    evidence = pe.collect_payload_evidence([payload], max_payload_bytes=8)
    assert evidence["truncated"] == "bytes"
    assert evidence["members_scanned"] == 1
    assert evidence["members_skipped"] == 1


def test_collect_caps_dex_members_without_stopping_other_members():
    members = {f"classes{i}.dex": b"x" * 16 for i in range(3)}
    members["lib/armeabi-v7a/libx.so"] = b"\x00" * 8
    evidence = pe.collect_payload_evidence([_zip(members)], max_dex_members=1)
    assert evidence["truncated"] == "members"
    assert evidence["members_skipped"] == 2
    assert evidence["native_libs"] == ["lib/armeabi-v7a/libx.so"], "natives still collected"


def test_dex_cap_is_per_payload():
    # A per-sample counter would skip the second payload's dex too (members_skipped == 2).
    first = _zip({"a.dex": b"x" * 4, "b.dex": b"x" * 4})
    second = _zip({"c.dex": b"x" * 4})
    evidence = pe.collect_payload_evidence([first, second], max_dex_members=1)
    assert evidence["payloads"] == 2
    assert evidence["members_skipped"] == 1, "the second payload gets its own dex budget"


def test_collect_stops_at_the_budget_cap():
    evidence = pe.collect_payload_evidence([_zip({"classes.dex": b"x" * 4})], budget_s=0.0)
    assert evidence["truncated"] == "budget"
    assert evidence["members_scanned"] == 0
    assert evidence["payloads"] == 0


def test_truncated_keeps_the_first_cap_that_bites():
    # member-size cap bites on the first member; the dex cap must not overwrite it
    payload = _zip({"a.bin": b"y" * 16, "classes.dex": b"x" * 4})
    evidence = pe.collect_payload_evidence([payload], max_member_bytes=8, max_dex_members=0)
    assert evidence["truncated"] == "bytes"
    assert evidence["members_skipped"] == 2


def test_nested_apk_members_contribute_nothing():
    payload = _zip({"payload_split0.apk": _zip({"classes.dex": b"x" * 16})})
    evidence = pe.collect_payload_evidence([payload])
    assert evidence["class_count"] == 0
    assert evidence["permissions"] == []
    assert evidence["errors"] == []
    assert evidence["members_scanned"] == 1


def test_collect_is_deterministic():
    payload = _zip({"lib/x.so": b"\x00", "classes.dex": b"x" * 8})
    first = pe.collect_payload_evidence([payload])
    assert first == pe.collect_payload_evidence([payload])
```

- [x] **Step 6: Run the collector tests to verify they fail**

Run: `.venv\Scripts\python.exe -m pytest tests/test_payload_evidence.py -v`
Expected: FAIL — `AttributeError: module 'analysis.payload_evidence' has no attribute 'collect_payload_evidence'`.

- [x] **Step 7: Implement `collect_payload_evidence`**

Signature and return schema exactly as the Interfaces block. The algorithm, in this order (each rule is a decision the tests pin):

1. Record starts at zeros with `truncated="none"`, and `payloads` counts only ZIP-magic payloads that opened successfully.
2. `_cap(reason)` sets `truncated` only while it is still `"none"` — the first cap that bites wins.
3. Before each payload and before each member: if `time.monotonic() - started >= budget_s`, `_cap("budget")` and stop the whole walk.
4. A payload whose first 4 bytes are not `ZIP_MAGIC` is skipped (no `errors` entry — step 0 never passes one).
5. `zipfile.ZipFile(io.BytesIO(payload)).infolist()` inside `try`; on failure append `f"payload {index}: {type(exc).__name__}: {str(exc)[:80]}"` to `errors` and continue with the next payload.
6. `members_scanned` increments before any cap check for that member; members never reached because the walk stopped are neither scanned nor skipped.
7. A member with `info.file_size > max_member_bytes` is skipped (`members_skipped += 1`, `_cap("bytes")`) without reading its bytes.
8. Otherwise, if `charged + info.file_size > max_payload_bytes`, skip it and `_cap("bytes")`, then stop the whole walk. `charged` accumulates `info.file_size` for every member **admitted here**, i.e. every member that passed the per-member cap and is therefore analysed — spec §6 bounds `MAX_PAYLOAD_BYTES` by bytes *analysed* per sample, and a member rule 7 rejected is never read. The declared size is charged rather than the 4 bytes the head probe reads: conservative, since a hostile header can only make the cap bite sooner.
9. Read the member's head with `archive.open(info).read(4)` (a streaming 4-byte probe, no full inflate) inside `try`; on failure count it in `members_skipped` and append the exception name to `errors`.
10. Union `native_lib_names(info.filename, head)` into the native set.
11. `info.file_size == 0` contributes nothing further (no dex parse, no error).
12. A member whose lowercased name ends in `.dex`: if `dex_parsed >= max_dex_members`, skip it and `_cap("members")` (other members are still processed); otherwise read it fully and add `class_count_from_dex(data)`, appending any exception to `errors`. `dex_parsed` resets to 0 at the start of each payload — this cap is per payload, while `charged` is per sample.
13. A member whose lowercased name ends in `androidmanifest.xml`: read it fully and union `permissions_from_binary_manifest(data)`, appending any exception to `errors`.
14. Finish with `permissions`/`native_libs` sorted and `class_count` summed.

- [x] **Step 8: Run the collector tests to verify they pass**

Run: `.venv\Scripts\python.exe -m pytest tests/test_payload_evidence.py -v`
Expected: all pass.

- [x] **Step 9: Commit**

```powershell
git add analysis/payload_evidence.py tests/test_payload_evidence.py
git commit -m "payload-evidence: collect classes, permissions and natives from a recovered payload"
```

---

### Task 2: The additive merge

**Files:**
- Modify: `analysis/payload_evidence.py`
- Test: `tests/test_payload_evidence.py`

**Interfaces:**
- Consumes: the Task 1 record schema.
- Produces: `merge_evidence(extraction: dict, evidence: dict | None) -> dict` — a new dict, never the input, with:
  - `decompiled_classes = max(existing, evidence["class_count"])` — written only when `evidence["class_count"]` is truthy;
  - `native_libs_found = sorted(set(existing) | set(evidence["native_libs"]))` — written only when `evidence["native_libs"]` is non-empty;
  - `manifest_info["uses_permissions"] = sorted(set(existing) | set(evidence["permissions"]))` — written only when `evidence["permissions"]` is non-empty, creating `manifest_info` with the other keys absent when apktool failed;
  - `recovered_payload_evidence = evidence` — written whenever `evidence` is truthy, even when no signal was found;
  - falsy `evidence` (`{}`/`None`) returns `extraction` unchanged.

- [x] **Step 1: Write the failing merge tests**

Append to `tests/test_payload_evidence.py`:

```python
EVIDENCE = {
    "payloads": 1, "members_scanned": 64, "members_skipped": 0, "class_count": 5448,
    "permissions": ["android.permission.CALL_PHONE"],
    "native_libs": ["lib/arm64-v8a/libx.so"], "truncated": "none", "errors": [],
}


def _extraction():
    return {
        "decompiled_classes": 120,
        "native_libs_found": [],
        "manifest_info": {"uses_permissions": ["android.permission.INTERNET"]},
    }


def test_merge_takes_the_larger_class_count():
    assert pe.merge_evidence(_extraction(), EVIDENCE)["decompiled_classes"] == 5448


def test_merge_keeps_the_stub_count_when_it_is_larger():
    extraction = _extraction()
    extraction["decompiled_classes"] = 9000
    assert pe.merge_evidence(extraction, EVIDENCE)["decompiled_classes"] == 9000


def test_merge_unions_and_sorts_permissions_and_natives():
    merged = pe.merge_evidence(_extraction(), EVIDENCE)
    assert merged["native_libs_found"] == ["lib/arm64-v8a/libx.so"]
    assert merged["manifest_info"]["uses_permissions"] == [
        "android.permission.CALL_PHONE", "android.permission.INTERNET",
    ]


def test_merge_does_not_mutate_the_input_extraction():
    extraction = _extraction()
    pe.merge_evidence(extraction, EVIDENCE)
    assert extraction["decompiled_classes"] == 120
    assert extraction["manifest_info"]["uses_permissions"] == ["android.permission.INTERNET"]
    assert "recovered_payload_evidence" not in extraction


def test_merge_creates_manifest_info_when_apktool_failed():
    merged = pe.merge_evidence({"decompiled_classes": 0, "native_libs_found": []}, EVIDENCE)
    assert merged["manifest_info"]["uses_permissions"] == ["android.permission.CALL_PHONE"]


def test_merge_with_empty_evidence_returns_the_input_unchanged():
    extraction = _extraction()
    assert pe.merge_evidence(extraction, {}) == extraction
    assert pe.merge_evidence(extraction, None) == extraction


def test_merge_records_provenance_even_when_no_signal_was_found():
    extraction = _extraction()
    silent = {**EVIDENCE, "class_count": 0, "permissions": [], "native_libs": []}
    merged = pe.merge_evidence(extraction, silent)
    assert merged["decompiled_classes"] == extraction["decompiled_classes"]
    assert merged["native_libs_found"] == extraction["native_libs_found"]
    assert merged["manifest_info"] == extraction["manifest_info"]
    assert merged["recovered_payload_evidence"]["payloads"] == 1


def test_merge_is_idempotent():
    once = pe.merge_evidence(_extraction(), EVIDENCE)
    assert pe.merge_evidence(once, EVIDENCE) == once
```

- [x] **Step 2: Run the merge tests to verify they fail**

Run: `.venv\Scripts\python.exe -m pytest tests/test_payload_evidence.py -k merge -v`
Expected: FAIL — no attribute `merge_evidence`.

- [x] **Step 3: Implement `merge_evidence`**

Add to `analysis/payload_evidence.py`, with a docstring naming the spec's §4.3 merge policy (additive, `max` for the class count, sorted unions) and the fallback note from §4.4. Shallow-copy `extraction`, copy `manifest_info` before editing it, and gate each field write on the evidence value being truthy, per the Interfaces block.

- [x] **Step 4: Run all module tests to verify they pass**

Run: `.venv\Scripts\python.exe -m pytest tests/test_payload_evidence.py -v`
Expected: all pass.

- [x] **Step 5: Commit**

```powershell
git add analysis/payload_evidence.py tests/test_payload_evidence.py
git commit -m "payload-evidence: merge payload evidence into extraction, additively"
```

---

### Task 3: Wire the evidence into the classifier's inputs

**Files:**
- Modify: `analysis/step0_master_key.py` (`_breaker_second_chance` ~lines 163-246, `run_master_key_preprocess` ~lines 342-358)
- Modify: `analysis/pipeline.py` (import block lines 51-55; merge call after line 479)
- Test: `tests/test_step0_master_key.py`

**Interfaces:**
- Consumes: `collect_payload_evidence` and `merge_evidence` from `analysis.payload_evidence`.
- Produces:
  - `_breaker_second_chance` materializes every hit once into `(hit, payload)` pairs, analyzes the ZIP-validated ones, and adds `"recovered_evidence": <record>` to its RECOVERED report when at least one payload was analyzed (`record["payloads"] > 0`). The FAILED report is unchanged and gains no key.
  - `run_master_key_preprocess` puts that record on the returned report under `"recovered_evidence"` (only when present); misses, `SKIPPED` reports and dispatcher recoveries have no such key.
  - The pipeline merges it into `extraction` before result assembly.

- [x] **Step 1: Write the failing step 0 tests**

Add to `tests/test_step0_master_key.py` (reusing `packed_triage`, `_encrypt_like_myg0n`, `_write_apk`; the existing `_kit_payload()` is unchanged):

```python
# The breaker skips members under 512 bytes (packers/breaker/blobs.py MIN_BLOB_SIZE),
# so kit payloads must carry padding past that bound to ever be attacked.
KIT_NATIVE_PAD = 1024


def _kit_payload_with_native() -> bytes:
    """A minimal recovered kit that carries one native member and nothing else useful."""
    dex = b"dex\n035\x00" + b"\x00" * 12 + b"\x00" * KIT_NATIVE_PAD
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("lib/armeabi-v7a/libx.so", b"\x7fELF" + b"\x00" * 32)
        archive.writestr("bootstrap.dex", dex)
    return buffer.getvalue()


def test_recovery_attaches_recovered_evidence(packed_triage, tmp_path, monkeypatch):
    monkeypatch.setattr(step0, "BREAKER_EVIDENCE_DIR", tmp_path / "evidence")
    ciphertext, _padded = _encrypt_like_myg0n(_kit_payload_with_native())
    apk = tmp_path / "kit.apk"
    _write_apk(apk, ciphertext)

    master_key = step0.run_master_key_preprocess(str(apk), str(tmp_path / "work"))

    evidence = master_key["recovered_evidence"]
    assert evidence["payloads"] == 1
    assert evidence["members_scanned"] == 2
    assert evidence["native_libs"] == ["lib/armeabi-v7a/libx.so"]


def test_miss_has_no_recovered_evidence_key(packed_triage, tmp_path, monkeypatch):
    monkeypatch.setattr(step0, "BREAKER_EVIDENCE_DIR", tmp_path / "evidence")
    apk = tmp_path / "plain.apk"
    _write_apk(apk, blob=None)

    master_key = step0.run_master_key_preprocess(str(apk), str(tmp_path / "work"))

    assert "recovered_evidence" not in master_key


def test_non_zip_recovery_has_no_recovered_evidence(packed_triage, tmp_path, monkeypatch):
    monkeypatch.setattr(step0, "BREAKER_EVIDENCE_DIR", tmp_path / "evidence")
    ciphertext, _padded = _encrypt_like_myg0n(b"dex\n035\x00" + bytes(range(256)) * 3)
    apk = tmp_path / "dex.apk"
    _write_apk(apk, ciphertext)

    master_key = step0.run_master_key_preprocess(str(apk), str(tmp_path / "work"))

    assert master_key["verdict"] == "RECOVERED"
    assert "recovered_evidence" not in master_key


def test_every_zip_recovery_is_analysed_not_only_the_written_kit(packed_triage, tmp_path, monkeypatch):
    monkeypatch.setattr(step0, "BREAKER_EVIDENCE_DIR", tmp_path / "evidence")
    first = _kit_payload_with_native()
    second = _kit_payload_with_native()
    apk = tmp_path / "two.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"<manifest/>")
        archive.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 128)
        archive.writestr("assets/AAAA", _encrypt_like_myg0n(first, "AAAA")[0])
        archive.writestr("assets/BBBB", _encrypt_like_myg0n(second, "BBBB")[0])

    master_key = step0.run_master_key_preprocess(str(apk), str(tmp_path / "work"))

    assert len(master_key["artifacts"]) == 1, "only the first kit is materialised"
    assert master_key["recovered_evidence"]["payloads"] == 2, "both ZIP recoveries are analysed"


def test_recovered_evidence_is_not_bound_for_the_taxonomy(packed_triage, tmp_path, monkeypatch):
    monkeypatch.setattr(step0, "BREAKER_EVIDENCE_DIR", tmp_path / "evidence")
    ciphertext, _padded = _encrypt_like_myg0n(_kit_payload_with_native())
    apk = tmp_path / "kit.apk"
    _write_apk(apk, ciphertext)

    master_key = step0.run_master_key_preprocess(str(apk), str(tmp_path / "work"))

    # Evidence is additive: it changes no contract field and no taxonomy wording.
    assert master_key["ecode"] is None
    assert master_key["kt_taxonomy"].startswith("at-rest asset blob recovered on second chance")
```

The existing `test_result_never_carries_key_material` already dumps the whole report, so it now also covers the new key — do not weaken it.

**Amendment (measured during Task 3):** the un-padded `_kit_payload_with_native` body originally
specified above cannot work. The member the breaker attacks is the *outer* APK member
`assets/myg0N`, whose real content is the AES ciphertext of the whole kit ZIP, and `_classify`
(`packers/breaker/blobs.py:209-214`) applies `MIN_BLOB_SIZE` (512 B) to that content after the
extension filter (no extension → not filtered). Measured on the real code path: un-padded the kit
is 302 B and the outer member 304 B — skipped, so the run ends `FAILED` / `E-KDF-EXHAUSTED` with no
recovery and no evidence key; padded the outer member is 1328 B and the run reaches `RECOVERED`,
`payloads = 1`. The pre-existing `_kit_payload()` already sits over the bound via its own
`b"\x00" * 1024` filler, which is why no earlier test hit this. The padding changes no asserted
value.

- [x] **Step 2: Run the step 0 tests to verify they fail**

Run: `.venv\Scripts\python.exe -m pytest tests/test_step0_master_key.py -v`
Expected: the five new tests FAIL on a missing `recovered_evidence` key; the nine existing tests still pass.

- [x] **Step 3: Refactor `_breaker_second_chance` to materialize once and collect evidence**

Materialize every hit into a list of `(hit, payload)` pairs (skipping `None`), then use that list for the existing write loop (the `kit.zip`-wins `break` and the one-non-ZIP-file rule stay exactly as they are). Analyze `[payload for hit, payload in materialized if hit.validation.startswith("zip")]` through `collect_payload_evidence`, and add `"recovered_evidence": record` to the RECOVERED return only when `record["payloads"] > 0`. Import both functions at module level from `analysis.payload_evidence`.

- [x] **Step 4: Surface the record from `run_master_key_preprocess`**

After building the report dict, add the key when `effective.get("recovered_evidence")` is truthy. Do not add it otherwise (misses, `SKIPPED`, dispatcher recoveries). Add `"recovered_evidence"` to the docstring's returned-dict listing with the one-line contract (additive evidence from a breaker ZIP recovery; never key material).

- [x] **Step 5: Run the step 0 tests to verify they pass**

Run: `.venv\Scripts\python.exe -m pytest tests/test_step0_master_key.py -v`
Expected: all 14 pass.

- [x] **Step 6: Add the merge call to the pipeline**

In `analysis/pipeline.py`, extend the existing import block:

```python
try:
    from analysis.step0_master_key import run_master_key_preprocess, enrich_strings_with_recovered
    from analysis.payload_evidence import merge_evidence
except ImportError:
    run_master_key_preprocess = None
    enrich_strings_with_recovered = None
    merge_evidence = None
```

Then insert immediately after the enrichment block that ends at line 479:

```python
    # Recovered-payload evidence: classes/permissions/native libs of a breaker-recovered
    # payload are merged additively into `extraction`, the one dict family_id and the
    # result assembly read. See
    # docs/plans/specs/2026-10-16-recovered-payload-evidence-design.md §4.3.
    if master_key_result and merge_evidence:
        recovered_evidence = master_key_result.get("recovered_evidence")
        if recovered_evidence:
            try:
                extraction = merge_evidence(extraction, recovered_evidence)
            except Exception as e:
                logger.warning("MasterKey evidence merge failed: %s", e)
```

No new metric event, and no other pipeline change: line 636/773 (`manifest = extraction.get("manifest_info", {})`) and the result assemblies already read the merged values.

- [x] **Step 7: Verify imports and the whole fast suite**

Run: `.venv\Scripts\python.exe -m pytest tests/test_module_imports.py -v` then `.venv\Scripts\python.exe -m pytest tests/ -m "not slow"`
Expected: import test passes; suite green (Task 5 Step 4 is the behavioral check for this call site — there is no fast test that executes `run_pipeline`).

- [x] **Step 8: Commit**

```powershell
git add analysis/step0_master_key.py analysis/pipeline.py tests/test_step0_master_key.py
git commit -m "step0: merge recovered-payload evidence into the classifier inputs"
```

---

### Task 4: Opt-in real-payload coverage

**Files:**
- Modify: `tests/test_breaker_corpus.py`

**Interfaces:**
- Consumes: `collect_payload_evidence` (Task 1), `step0.run_master_key_preprocess` and `step0.BREAKER_EVIDENCE_DIR` (Task 3), and the file-level `pytestmark` in `tests/test_breaker_corpus.py` (slow + `DFX_BREAKER_ACCEPTANCE=1`).
- Produces: nothing other tasks consume. This is the last fast-to-run proof that the breaker → materialize → collect → attach chain works on genuine recovered apps.

Measured on this machine (2026-10-16) with these exact fixtures, androguard 4.1.4:

| fixture | dex members | classes | permissions | native libs |
|---|---|---|---|---|
| `analysis/recovered/myg0N_payload/payload_split1.apk` | 63 | 5768 | 22, incl. `android.permission.CALL_PHONE` | 0 |
| `analysis/recovered/PNB_One/payload_split1.apk` | 63 | 5448 | 0 | 0 |
| `analysis/recovered/PNB_One/miner.apk` | 1 | 2 | 6 | 2 |

and, end to end through the real breaker on `PENDRIVE DATA/PENDRIVE DATA/apk fraud/21/PNB ONE ACTIVATION.apk` (0.9 s, 20k attempts, 8 hits, 7 ZIP): `payloads == 7`, `members_scanned == 935`, `members_skipped == 0`, `class_count == 7012`, `truncated == "none"`, `errors == []`, `permissions` = those 22 (including `android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`), `native_libs == ["arm64-v8a", "armeabi-v7a", "lib/arm64-v8a/liblixhokfsmav.so", "lib/armeabi-v7a/liblixhokfsmav.so"]`.

**Correction to spec §9:** that payload set does **not** contain `android.permission.REQUEST_INSTALL_PACKAGES` (measured: 20 permissions in the full-APK payload, 22 after union), so the test below asserts the measured permissions instead. Spec §9 is corrected to match.

`analysis/recovered/` and `PENDRIVE DATA/` are gitignored, so these tests skip when the fixtures are absent (repo convention).

- [x] **Step 1: Write the failing opt-in tests**

Append to `tests/test_breaker_corpus.py` (import `collect_payload_evidence` from `analysis.payload_evidence`):

```python
RECOVERED = ROOT / "analysis" / "recovered"

# (payload, min classes, permission that must be present)
REAL_PAYLOAD_CASES = [
    (RECOVERED / "myg0N_payload" / "payload_split1.apk", 5000, "android.permission.CALL_PHONE"),
    (RECOVERED / "PNB_One" / "payload_split1.apk", 5000, None),
]


@pytest.mark.parametrize("payload_path,min_classes,permission", REAL_PAYLOAD_CASES,
                         ids=lambda value: getattr(value, "name", str(value)))
def test_real_recovered_app_yields_class_and_permission_evidence(payload_path, min_classes, permission):
    if not payload_path.exists():
        pytest.skip(f"payload absent: {payload_path}")
    evidence = collect_payload_evidence([payload_path.read_bytes()])
    assert evidence["payloads"] == 1
    assert evidence["truncated"] == "none", "the caps must not bite on a real recovered app"
    assert evidence["class_count"] > min_classes
    if permission:
        assert permission in evidence["permissions"]


def test_real_recovered_app_yields_native_library_evidence():
    payload_path = RECOVERED / "PNB_One" / "miner.apk"
    if not payload_path.exists():
        pytest.skip(f"payload absent: {payload_path}")
    evidence = collect_payload_evidence([payload_path.read_bytes()])
    assert len(evidence["native_libs"]) == 2
    assert all(name.lower().endswith(".so") or name.lower().startswith("lib/")
               for name in evidence["native_libs"])


def test_pnb_one_activation_evidence_end_to_end(tmp_path, monkeypatch):
    """The genuine sample spec §1 cites, through the real breaker and collector.

    Seven of its eight hits are ZIP payloads (the eighth is `ttf-magic`): one multidex
    payload (63 dex), one full APK with the manifest, one ELF-magic native payload.
    Triage and the dispatcher are stubbed, as in the MediaPlayer2 acceptance test; the
    breaker, materialisation, collection and report attachment all run for real.
    """
    from analysis import step0_master_key as step0

    apk = PENDRIVE / "apk fraud" / "21" / "PNB ONE ACTIVATION.apk"
    if not apk.exists():
        pytest.skip(f"sample absent: {apk}")
    monkeypatch.setattr(step0, "_load_triage",
                        lambda _apk: {"verdict": "packed_custom", "confidence": 1.0})
    monkeypatch.setattr(step0, "_attempt_unpack", lambda *a, **k: {
        "verdict": "FAILED", "ecode": "E-NATIVE-NO-RECOVERY", "artifacts": [],
        "route": "NATIVE", "family": None, "kdf": None, "iocs": {},
    })
    monkeypatch.setattr(step0, "BREAKER_EVIDENCE_DIR", tmp_path / "evidence")

    master_key = step0.run_master_key_preprocess(str(apk), str(tmp_path / "work"))

    assert master_key["verdict"] == "RECOVERED"
    assert master_key["ecode"] is None, "the recovered sample is no longer E-coded"
    evidence = master_key["recovered_evidence"]
    assert evidence["payloads"] == 7, "the ttf-magic hit is not analysed"
    assert evidence["truncated"] == "none", "the caps must not bite on this sample"
    assert evidence["class_count"] > 7000, "the 1146-class third dex payload is counted too"
    assert evidence["errors"] == []
    assert "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" in evidence["permissions"]
    assert "android.permission.SEND_SMS" in evidence["permissions"]
    assert evidence["native_libs"] == [
        "arm64-v8a",
        "armeabi-v7a",
        "lib/arm64-v8a/liblixhokfsmav.so",
        "lib/armeabi-v7a/liblixhokfsmav.so",
    ], "two of these are ELF-magic only - no lib/ path and no .so suffix"
```

Class counts are asserted as a floor, not an exact value: androguard's DEX enumeration is the variable, and the point of the test is that real recovered apps yield real evidence.

- [x] **Step 2: Run them to verify they fail, then pass**

Run: `$env:DFX_BREAKER_ACCEPTANCE=1; .venv\Scripts\python.exe -m pytest tests/test_breaker_corpus.py -v -k "evidence"`
Expected first: FAIL on the missing import or a wrong signature; after Task 1 is in place: PASS. A `truncated != "none"` failure means the caps or the accounting are wrong — fix the collector, not the assertion.

- [x] **Step 3: Confirm the fast suite still skips them**

Run: `.venv\Scripts\python.exe -m pytest tests/ -m "not slow"`
Expected: green, with the new tests deselected.

- [x] **Step 4: Commit**

```powershell
git add tests/test_breaker_corpus.py
git commit -m "payload-evidence: opt-in coverage on real recovered apps"
```

---

### Task 5: Measured A/B acceptance

**Files:**
- Create (throwaway, outside the repo): `%TEMP%\opencode\evidence_ab.py`
- Modify: `docs/plans/2026-10-16-recovered-payload-evidence-plan.md` (Amendments section, appended at the end)
- Modify: `.superpowers/sdd/2026-10-16-breaker-pipeline-wiring/progress.md` (append a T8 section) if that ledger is still present

**Interfaces:**
- Consumes: everything above; `evaluation/run_validation_359.py` (`load_ground_truth`, `disable_ground_truth_lookup`, `install_accuracy_mode`, `start_ollama`, `resolve_apk_path`, `build_report`), `evaluation/validation_359/predictions.json` (the 6-Oct baseline, 265 rows, accuracy 0.3547).
- Produces: recorded readings and, if required, the spec §4.4 fallback.

- [x] **Step 1: Identify the affected set**

The merge can only fire where `master_key["recovered_evidence"]` exists, i.e. where the second chance recovered a ZIP payload. Reuse the sweep approach from the previous effort's ledger (triage each `ground_truth_all.csv` row, run `packers.breaker.engine.break_apk(apk, evidence_dir, attempts_cap=20_000, budget_s=120)` on the packed ones, keep hits whose `payload[:4] == b"PK\x03\x04"`). Expect the shape the ledger recorded: ~19 recoveries, ~17 ZIP. Report the list; if it differs from that, say so.

- [x] **Step 2: Run the affected samples off/on in one process**

For each affected sample run `pipeline_module.run_pipeline(resolve_apk_path(row), work_dir=..., event_emitter=None, pipeline_timeout=1200)` twice per process, mirroring `run_validation_359.main()`: `disable_ground_truth_lookup()`, `install_accuracy_mode()`, `start_ollama()` (private ollama on 11435). The only variable is the merge seam: `monkeypatch.setattr(pipeline_module, "merge_evidence", lambda extraction, evidence: extraction)` for the off run, the real function for the on run.

Record per sample: `family_identification.family`/`method`, `master_key.recovered_evidence` (payloads / class_count / len(permissions) / len(native_libs) / truncated), `extraction.decompiled_classes`, `len(extraction.native_libs_found)`, `len(manifest.uses_permissions)`.

- [x] **Step 3: Run the control samples**

Three samples that cannot carry evidence, each off/on as above: one dispatcher-recovered sample, one packed sample whose breaker run is exhausted, one `clean_static` sample. Assert the two result dicts are equal after dropping `timeline` (wall clock). This is the "samples with no breaker recovery are unchanged" acceptance criterion.

- [x] **Step 4: Assert the wiring actually fired**

For at least one affected sample, assert the on-run `extraction` differs from the off-run (e.g. `decompiled_classes` or `len(native_libs_found)` or `len(manifest.uses_permissions)`), or that the on-run `recovered_evidence` was non-empty while the off-run had none. A run where every affected sample is byte-identical means the merge never reached `extraction` — treat it as a failure of Task 3, not as a zero delta.

- [x] **Step 5: Compute the metric delta**

Take the 6-Oct `predictions.json`, replace the rows for affected in-eval samples with the on-run predictions, and call `evaluation.run_validation_359.build_report(rows)`; do the same with the off-run predictions. Report `accuracy`, `precision_macro`, `recall_macro` for baseline / off / on, with deltas. Scoring uses prediction, ground truth, status and source only.

- [x] **Step 6: Apply the fallback only if the measurement demands it**

Spec §4.4: if accuracy or macro-recall drops relative to the off run, drop the class-count merge (`decompiled_classes` keeps the stub value; the payload count stays in `recovered_payload_evidence`), keep the permission/native unions, re-run Steps 2-5 once, and record both readings. Never keep a losing merge silently, and never keep a fallback whose rationale was not measured.

- [x] **Step 7: Record the outcome and commit**

Append an `## Amendments (2026-10-16, measured A/B)` section to this plan's file with: the affected set size, the three-metric table (baseline / off / on), the per-sample movements, the control-sample result, the truncation observations, and the fallback decision with its reason. Update the ledger if present. Then:

```powershell
git add docs/plans/2026-10-16-recovered-payload-evidence-plan.md
git commit -m "plan: record the measured recovered-payload-evidence delta"
```

---

## Self-Review Notes

- Every completed task adds one independently testable deliverable: the collector (single-payload correctness), the merge (pure semantics), the wiring (step 0 contract + pipeline seam), the real-payload coverage (measured fixtures), the A/B (the metric).
- Delegated decisions left to the implementer, deliberately: the collector's Python body (the algorithm's rules are pinned above), the merge's copy mechanics, and the A/B harness's plumbing.
- Known gap, accepted by the spec: the pipeline's merge call site has no fast test, because `run_pipeline` needs a real APK and tools; Task 5 Step 4 is its behavioral guard.

---

## Amendments (2026-10-17, measured A/B)

Measured, not asserted. The authoritative run is the OS-level job started **2026-10-17 20:22:49** (`run_evidence_ab_all.ps1`): `ab` → `ctrl` → `wire` → `metrics`, each exit 0 (the `metrics` phase needed a post-hoc harness fix — see §8). Recordings live under `%TEMP%\opencode\evidence_ab\readings\`. Everything below is read from the artifacts: `readings\s1\affected.json`, `readings\pipeline\*.json`, `readings\wire\comparison.json`, `readings\ctrl\*_equality.json`, `readings\metrics\summary.json`, and `progress.log`.

### 1. The affected set — three counts that must not be conflated

`readings\s1\affected.json` (`packed_rows` 40) holds **17 samples** that are "affected": a standalone breaker sweep recovered a ZIP payload for each (`break_apk` + `_materialize_payload`; no pipeline, no LLM). That is the brief's expected shape (~17 ZIP). The 17 are `018f8548`, `44b5086d`, `5af77b5f`, `95236ef7`, `addbd877`, `bca248d3`, `c7944bda`, `de1d599d`, `e0f530ac`, `e4a321ef`, `fea09cb6`, `ff742233`, `0e81a0fd`, `49b59c87`, `f5ac462d`, `fcd233be`, `1869b4b8`.

Three different sizes, never to be conflated:

| set | size |
|---|---|
| "affected" — the standalone breaker sweep recovered a ZIP payload | 17 |
| of those, in the 265-row eval set | 11 |
| of those, the pipeline actually attached `recovered_evidence` to (the merge had anything to do) | 6 |
| **both** — in-eval *and* carrying evidence; the only samples the metric can reflect | **3** (`fea09cb6`, `ff742233`, `49b59c87`) |

The 11 affected samples that carry no evidence record `recovered_evidence: None`: the pipeline recovered them via the dispatcher, so the breaker's *second chance* never runs and the merge is never reached — they are not "recovered but empty". Only the 6 with an evidence record merge, and only 3 of those are scored.

### 2. The three-metric table

`readings\metrics\summary.json`, 265 rows evaluated, 0 errors:

| metric | baseline | off | on | delta (on − off) |
|---|---|---|---|---|
| accuracy | 0.3547 | 0.3547 | 0.3547 | **0.0** |
| precision_macro | 0.3049 | 0.3049 | 0.3049 | **0.0** |
| recall_macro | 0.3123 | 0.3123 | 0.3123 | **0.0** |

The metric is not structurally blind: `extraction` feeds `family_id`, so a merge that flipped a band or signal would surface as a changed `family` and a non-zero delta. None did — a genuine null **on verdicts**, blind only to the merge's extraction-only effect (which §3 records).

### 3. Per-sample movements (off → on)

6 of the 17 moved — exactly the 6 that carry an evidence record. Every on-value follows the merge rule (`max(stub_classes, payload_classes)` for the count; set-**union** for permissions and native libs):

| sample | ground truth | classes | native libs | manifest perms |
|---|---|---|---|---|
| `49b59c87` | FraudDropper | 3054 → **7012** | 0 → 4 | 0 → 22 |
| `c7944bda` | 40094400 | 1397 → **1622** | 0 → 4 | 0 → 9 |
| `de1d599d` | Android/Agent | 5204 → **6857** | 0 → 4 | 0 → 33 |
| `f5ac462d` | FraudDropper | 1501 → **6859** | 0 → 4 | 0 → 23 |
| `fea09cb6` | General | 2 → **1098** | 0 → 0 | 0 → 0 |
| `ff742233` | AndroidOS | 4 → **6857** | 0 → 4 | 0 → 33 |

`49b59c87 → 7012` reproduces Task 4's measured `class_count=7012` exactly. `ff742233` on-run provenance: `payloads=7`, `members_scanned=918`, `members_skipped=0`, `class_count=6857`, `truncated=none`, `errors=[]`, 33 permissions, 4 native entries (`['arm64-v8a','armeabi-v7a','lib/arm64-v8a/liblixhokfsmav.so','lib/armeabi-v7a/liblixhokfsmav.so']` — two ELF-magic-only, as the spec allows). `fea09cb6` is the only mover whose payload contributes classes but neither permissions nor native libs. The 11 samples without an evidence record are byte-identical off/on on all three fields.

### 4. Wiring proof

`readings\wire\comparison.json`: **6 moved / 11 identical** across the 17 affected samples; `progress.log` records `PHASE wire done: 6 moved, 11 identical`. The merge demonstrably reached `extraction` — the firing is real, not a Task 3 failure.

### 5. Control result — stated honestly

`phase_ctrl` ran three controls, and **all three came from the `dispatcher` bucket** (`progress.log` `csel dispatcher: [...]`, 13 candidates; `select_controls` fills all three from that one bucket), not the one-dispatcher + one-exhausted + one-clean the brief's Step 3 asked for. Shas: `018f8548`, `3a03b35a`, `44b5086d`. The saved verdict is `equal: false` for **all three** (`readings\ctrl\*_equality.json`), and the harness **never asserted**: `check_control_equality` logs `off == on (after dropping timeline)` unconditionally before the `if not equal` branch that logs `DIFFER [...]`. That is a harness defect, not a passing check.

So the criterion holds **in substance and is false as written**. For all three, `extraction` is byte-identical between arms and `recovered_evidence` is `None` in both. The only differing leaves are (a) artifact paths — the two arms run in different work directories by construction (`work\ctrl\<sha>\off` vs `\on`), (b) wall clocks, and (c) on `44b5086d` only, `llm_assessment` prose (`narrative`, `raw_llm_output`, `recommended_actions`, `threat_indicators`). That last difference is proven LLM nondeterminism, not leakage: both arms carry `recovered_evidence: None`, their `extraction` maps are identical on all seven keys including `total_strings_extracted = 3779`, and `family`/`method`/`confidence` are identical (`FakeInstaller`/`llm`/`0.5`). Whole-dict equality is unachievable for LLM-scored samples and by the two-work-dir design.

### 6. The baseline caveat

`baseline == off` at 4 dp is a coincidence. Exactly one row differs baseline → off — `fea09cb6`, `unknown` → `Bradesco` (ground truth `General`, wrong either way) — and it changes the same way in both arms. That single row is the only source of the per-family difference `unknown` precision `0.122 → 0.125`. The off arm is therefore **not** a reproduction of the 6-Oct baseline.

### 7. §4.4 fallback decision

**Not triggered.** §4.4 fires only on an `accuracy` or `recall_macro` *drop*; both deltas are `0.0` (§2). The class-count merge **stays** (with the permission and native-lib unions), and that decision is measured rather than assumed. **No code changed** — `analysis/payload_evidence.py`, `analysis/step0_master_key.py`, and the tests are untouched by this task; only this plan (and the uncommitted phase-1 ledger) is written.

### 8. Caveats

- **One run per arm, with an LLM in the loop.** Nondeterminism is demonstrated on the `44b5086d` control; a single run per arm cannot rule it out elsewhere. **No verdict claim depends on it**: none of the 6 firing samples changed family, and the 3 in-eval movers still predict `unknown` / `unknown` / `Bradesco` (`49b59c87` / `ff742233` / `fea09cb6`).
- **`substitute()` over-substitutes and silently skips failed runs.** It rewrites any baseline row that has a successful `<sha>_<seam>.json`, not only affected in-eval rows — 12 rows, including the control `3a03b35a` (harmless: its substituted value equals its baseline prediction). A failed affected run would be silently left at the baseline prediction, understating the merge rather than flagging it.
- **`readings\s1\affected.json` predates the authoritative run** (mtime 2026-10-16 19:57, from the first attempt). It is a deterministic pure-analysis carry-over (no pipeline, no LLM) and reports the brief's expected shape (17 affected / 40 packed).
- **Two affected recordings were overwritten by `ctrl`** — `018f8548` and `44b5086d` sit in both the affected set and the dispatcher bucket, so `phase_ctrl` re-ran them and overwrote their `readings\pipeline` files. Immaterial: both are evidence-free and show no movement.
- **Truncation observations.** Every scored recording carries `truncated: "none"` and `errors: []` in its `recovered_evidence`; the caps did not bite. (`truncated: "attempts"` on the separate `breaker` block is the breaker's own budget note, not the evidence record.)
- **The `metrics` phase first exited 1 on a harness bug.** `substitute` did `family["family"]` on a recording whose `family` is already the family-name string. The controller patched it **after `ab`, `ctrl` and `wire` had all completed**; `substitute` is pure analysis that reads recordings and rewrites an in-memory baseline copy, so it touches no recorded reading. `metrics` then ran exit 0 and wrote `summary.json` (the `ABORT` line in `evidence_ab_run.log` is the pre-patch attempt). The independent review reproduced the same metrics *without* the harness, so the numbers are not an artefact of the patch.

### 9. Criterion correction (plan Step 3 / Step 7 wording)

Plan Step 3 says to "Assert the two result dicts are equal after dropping `timeline`". That wording is **unachievable**: any recorded path differs because the two arms run in different work directories by construction, and wall-clock fields are not dropped; for an LLM-scored sample the `llm_assessment` prose also re-rolls. The corrected, testable reading is **outcome-bearing fields unchanged** — `extraction` byte-identical and `recovered_evidence` identical (here `None` in both arms) — with all other differences confined to artifact paths, wall clocks, and LLM prose. Read that way the criterion is met: the 3 controls plus the 11 affected-no-evidence samples are an independent, larger sample of "no recovery ⇒ no change".
