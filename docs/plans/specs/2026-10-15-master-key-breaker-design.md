# Master Key Breaker for Encrypted APKs — Design Spec

**Date:** 2026-10-15
**Approach:** Provider-based combinatorial search engine + standalone CLI (pipeline wiring deferred)
**Status:** Pending user review
**Related docs:** `docs/MASTER_KEY_STRATEGY.md`, `docs/FULL_KNOWLEDGE_TRANSFER.md`,
`docs/RTO_encrypted_apk_breakdown_CASE_STUDY.md`, `docs/PACKER_FRAMEWORK.md`,
`analysis/recovered/PENDRIVE_MASTER_KEY_INTEL.md` (local-only), `docs/plans/2026-08-26-static-unpacking-pipeline-plan.md`

---

## 1. Overview

The Master Key strategy recovers encrypted APK payloads by making the malware
produce its own keys and validating the result against file magic. Today that
capability is fragmented:

| Existing piece | What it does | Limitation |
|---|---|---|
| `scripts/unpack.py` → `myg0n_kdf_bruteforce_probe` | one scheme (SHA1→key/SHA256→IV, seed windows + `"2"`) | hardcoded family |
| `analysis/step20_payload_kdf_crack.py` | Zombinder-flavored seed/KDF matrix | standalone, not wired, narrow seed space |
| `packers/` framework | per-family oracles (only `myg0n`) | new family = new code |
| Pendrive sessions | manual "combo matrix" sweeps (up to 6,930 combos) | wins not persisted as a tool |

Meanwhile the pendrive corpus contains samples whose keys *are* statically
derivable but were cracked only by hand (lumolight stage-2), samples whose
"runtime keys" turned out to be name-derived with a delta (MediaPlayer2: asset
number `+ 0xFFFF`), and samples whose E-codes are honest dead ends
(runtime-keyed, VMP). This effort builds one **master key breaker**: a
budgeted, self-validating, scheme-agnostic search engine that finds
(seed, KDF, cipher) triples for encrypted assets across a much larger candidate
space than any current probe — with honest coverage accounting for every miss.

## 2. Goals

- **G1.** One engine that autonomously recovers encrypted APK payloads whose
  keys lie in a broad statically-derivable space (names, literals, mined
  strings, numeric deltas, known conventions) — zero hand-feeding of seeds.
- **G2.** Honest self-validation: a hit is a hit only if the decrypted output
  passes structural gates (ZIP/DEX/etc.); every miss is typed with coverage
  stats (`attempts`, `space size`, `truncation reason`). Never fabricate.
- **G3.** Deterministic, budgeted search (attempt caps + wall caps) suitable
  for batch runs over a case folder.
- **G4.** Verified acceptance on the local corpus: all previously recovered
  samples re-crack from scratch, plus a genuinely new autonomous crack
  (MediaPlayer2 LCG), with zero false positives on the known dead ends.
- **G5.** Reusable engine + thin CLI; no changes to pipeline behavior in this
  effort.

## 3. Non-Goals

- Pipeline wiring (`scripts/unpack.py`, `analysis/step0_master_key.py`) — a
  separate, explicitly approved follow-up after acceptance.
- Dashboard/backend surface.
- Runtime-keyed, commercial-VMP, or VM-interpreter payloads — they stay typed
  misses (`E-KDF-EXHAUSTED` / `SKIPPED_*`).
- AES-CTR / exotic ciphers with no field evidence; new ciphers only when a
  real case demands them.
- Any network activity at any point.

## 4. Design Decisions

### 4.1 Approach: provider-based combinatorial engine

Three approaches were considered:

1. **Provider-based combinatorial engine (selected).** Seed providers and
   transform providers compose into one budgeted, deduplicated,
   deterministically-ordered search. Priors (known-family recipes) run first;
   the rest of the space is swept until caps hit. Candidate space is
   data-driven, so new schemes are configuration, not code.
2. **Recipe registry only** (one curated rule per family). Clean coverage
   accounting but cannot discover unseen schemes — kept only as ordered
   *priors* inside approach 1.
3. **Oracle-first micro-brute** (emulate, read keys from traces, brute tiny
   unknown indices). Strongest evidence per hit but cannot reach the samples
   that are E-coded precisely because emulation hasn't decoded their keys.
   Kept as an optional seed-injection hook (`--seeds-extra`), not the engine.

### 4.2 Engine + CLI; pipeline untouched

New package `packers/breaker/` + CLI `scripts/breaker.py`. Reuses
`packers/framework.py` (`derive_key`, `validate_zip`, `validate_dex`,
`shannon_entropy`) and the magic-table/recursion ideas from
`analysis/step20_payload_kdf_crack.py`. No new dependencies
(pycryptodome already pinned; import as `Crypto.Cipher.AES`, matching
`scripts/unpack.py`).

### 4.3 Seed providers (ordered; priors first)

| ID | Provider | Material |
|---|---|---|
| P0 | Convention priors | myg0N: `seed = stem + "2"`; lumolight/installer: `seed = basename(stem)` with zero IV; Zombinder gen-2: `stem + {"", "1", "2", 0-9}`; RTO substring windows: `literal = stem + "bootstrap.dex"`, seeds = `literal[a:b][c:] + "2"` (capped) |
| P1 | Name variants | basename and stem forms, `stem`/`stem.lower()`/`stem.upper()`, `stem + digit` |
| P2 | Mined strings | printable runs (len 4–96) from all `.dex`, native libs, plaintext members, and any *decrypted* content from recursion; dedup; cap `--max-strings` (default 2000); includes package/class names |
| P3 | Extra seeds | `--seeds-extra FILE`: JSON array of strings, or `{"seeds": [...]}`, or `unpack.py`-style `key_log` (`[[kind, value], ...]`, values used for `getBytes`/`digest`) |
| P4 | Numeric deltas | for decimal stems: `n`, `n±1`, `n + 0xFFFF`, `n − 0xFFFF`, `n + 0x10000`, 32-bit truncations — **LCG provider only** (see §4.7) |

Per-blob asset-stem variants are always tried first against a small prior
matrix so known cases stay instant; the full matrix then sweeps the remaining
space.

### 4.4 Transform matrix

- **Hashes:** md5, sha1, sha256, sha512 × truncations {16, 20, 24, 32}
  (≤ digest size).
- **Key/IV rules:** `key = H1(seed)[:L]`; `IV ∈ {zeros, H2(seed)[:16]}` where
  H2 ranges over the same hash set → a bounded, enumerated scheme list
  (priors ordered first; total scheme count printed in coverage).
- **Ciphers:** AES-CBC (PKCS7), AES-ECB, repeating-XOR (key ∈ {digest[:16],
  full digest, seed string UTF-8, single bytes 0–255}), RC4 (key =
  digest[:16]), Java-Random LCG keystream (§4.7).
- **Dedupe:** candidates keyed by `(cipher, key, iv)` — one attempt each.

### 4.5 Blob collection (what gets attacked)

- Walk zip members: consider `assets/**` plus extensionless/root members;
  skip `res/`, `META-INF/`, `lib/`, `*.dex`, `dexopt/`, known media
  extensions, and members < 512 B.
- **Plaintext sniff:** members starting with a known magic (PK, dex, ELF,
  gzip, …) are not ciphertext candidates (ZIPs are still recursed for nested
  encrypted members).
- **Flag-lie handling (verified requirement, MediaPlayer2 case):**
  `zipfile` refuses flag-`0x1` members, so the collector parses the local
  file header itself: read raw data slice per `(method, compress_size)`;
  method 8 → raw inflate (wbits −15). If `crc32(inflated) == central CRC`,
  the "encryption" bit is a **lie** and the inflated bytes are the real
  content candidate. If inflate fails / CRC mismatches → genuine ZipCrypto →
  `SKIPPED_ZIPCRYPTO` (never brute-forced with KDF matrices).
- **Content = inflated bytes** for deflate members, stored bytes otherwise
  (this exact detail is what makes the MediaPlayer2 re-crack work).

### 4.6 Search order & early exit

Per blob: prior scheme × stem variants → full scheme matrix × P1 → P2 → P3 →
(P4 for LCG only). Early exit on first *strongly validated* hit per blob;
probe false-positives are counted and never reported as hits.

### 4.7 Java-Random LCG (verified end-to-end on MediaPlayer2)

- Keystream: `java.util.Random` (48-bit LCG: multiplier `0x5DEECE66D`, addend
  `0xB`, seed scramble `^0x5DEECE66D`, mask `(1<<48)−1`); **convention:
  `nextInt()` written as 4 bytes little-endian**, continuous stream over the
  member content. (Alternative conventions `next(8)-per-byte`, `nextInt()`
  low byte, big-endian, 16-bit pairings were tested and do **not** match.)
- Seed candidates from P4 (numeric stem ± deltas). For MediaPlayer2:
  `seed = asset_number + 0xFFFF`, verified: decrypted ZIP sha256
  `5b5697c9…9b5e`, inner `classes.dex` (5,684,096 B) sha256 `6babf08a…e9a3`.
- Implementation is pure Python (`JavaRandom` class); unit test asserts LCG
  determinism vectors.

### 4.8 Recursion & string harvesting

On a validated ZIP hit: record artifact, recurse into members (depth ≤ 3,
`--depth`), and harvest strings from decrypted `.dex`/plaintext members into
P2 for sibling blobs. On a validated DEX hit: harvest strings as well.

## 5. Honesty & Validation

Two-stage, per candidate:

1. **Probe:** decrypt first 48 bytes (16-aligned for block ciphers); require a
   known magic prefix. Purpose: cheap filter only.
2. **Strong validation:** full decrypt, then per-kind checks — ZIP:
   `ZipFile` + `testzip()` (evidence `zip-strict`) or, failing strict parse,
   EOCD presence (`zip-eocd`, recorded honestly); DEX: `dex\n0\d\d\0` +
   size gate, upgrade to `dex-header` when the header `file_size` field
   matches; gzip: full decompress; ELF/JSON: magic + minimal structural
   checks.

Outcome taxonomy per blob: `RECOVERED`, `E-KDF-EXHAUSTED` (space fully
searched), `E-KDF-BUDGET` (truncated by cap), `SKIPPED_PLAINTEXT`,
`SKIPPED_ZIPCRYPTO`, `SKIPPED_FILTER`, `SKIPPED_SIZE`. `E-KDF-BUDGET` and
`E-KDF-EXHAUSTED` are deliberately distinguishable: a truncated search must
never read as "not derivable".

Every run writes coverage stats: `attempts`, `space_size`, `truncation`
(`none|attempts|time`), `wall_s`, per-member outcome. Hit records carry
provenance (`provider chain`, seed, scheme, cipher, evidence string, artifact
hashes). **Key material (`key`/`iv` hex) is written only to local `hit.json`
files** — never to tracked docs, logs, or summary CSV (repo evidence policy).
Acceptance runs write to `analysis/master_key_breaker/`; this effort adds that
path to `.gitignore` so breaker outputs (and any key material) can never be
committed, even under `git add -A`.

## 6. Budgets & Determinism

- Defaults: `--attempts-cap 200000` per blob, `--budget-s 300` per APK,
  `--depth 3`, early exit per blob, batch `--jobs 1` (2 optional).
- Ordering is deterministic (sorted providers, stable nested loops, dedupe
  before counting), so attempt sequences are prefix-stable and coverage
  numbers are reproducible; wall-time truncation is recorded explicitly.
- Acceptance runs use attempt caps high enough that `truncation=time` does not
  occur (or record it).

## 7. Component Changes

| File | Change |
|---|---|
| `packers/breaker/__init__.py` | NEW — public API: `break_apk(...)`, result types, outcome constants |
| `packers/breaker/blobs.py` | NEW — member walking, raw local-header reader, flag-lie/inflate logic, filters, sniffing |
| `packers/breaker/seeds.py` | NEW — P0–P4 providers, string miner, extra-seeds parser, `JavaRandom` numeric candidates |
| `packers/breaker/schemes.py` | NEW — ordered scheme enumeration, cipher implementations (AES CBC/ECB, XOR, RC4, LCG), `derive_key` reuse |
| `packers/breaker/engine.py` | NEW — search loop, dedupe, budgets, recursion, coverage stats, result schema |
| `scripts/breaker.py` | NEW — CLI + batch walk + `summary.csv` |
| `tests/test_breaker.py` | NEW — unit fixtures, negative controls, budgets, LCG vectors |
| `tests/test_breaker_corpus.py` | NEW — opt-in corpus acceptance (`@slow`, env-gated) |
| `.gitignore` | ADD one line: `analysis/master_key_breaker/` (local-only breaker outputs) |
| `scripts/unpack.py`, `analysis/step0_master_key.py`, `analysis/step20_payload_kdf_crack.py` | **Untouched** in this effort |

## 8. Data Contracts

```jsonc
// <out>/<sha16>/hit.json  (local-only; may contain key material)
{
  "apk": "...", "sha256": "...",
  "hits": [{
    "member": "assets/3664888858717845462", "size": 2062452,
    "content": "inflated|stored",
    "seed": "...", "provenance": ["numeric:+0xffff"],
    "scheme": {"key_hash": "sha1", "key_len": 16, "iv": "zeros", "cipher": "java-lcg"},
    "key_sha256": "...", "key_hex": "...", "iv_hex": "...",
    "validation": "zip-strict", "artifacts": [{"file": "...", "sha256": "..."}],
    "children": [ /* recursion level ≤ depth */ ]
  }]
}
// <out>/<sha16>/coverage.json  (no key material — shareable)
{
  "apk": "...", "sha256": "...", "wall_s": 1.31, "scheme_count": 0,
  "members": [{"name": "...", "size": 0, "outcome": "...",
               "attempts": 0, "space_size": 0, "truncation": "none",
               "probe_false_positives": 0}]
}
// <out>/summary.csv  (batch; columns)
// apk_path,sha256,ciphertext_members,recovered,attempts_total,truncated,wall_s,outcome
```

## 9. CLI

```
python scripts/breaker.py --input <apk|dir> --out <dir> \
    [--attempts-cap N] [--budget-s N] [--depth N] \
    [--seeds-extra FILE] [--max-strings N] [--jobs N]
```

Dir mode: walk `*.apk` (skip `._*` AppleDouble junk), dedupe by sha256,
deterministic sorted order. Always exits 0 with a verdict in the outputs (repo
tool convention). Prints a short JSON summary to stdout.

## 10. Testing Plan

- **Synthetic fixtures (in-test, deterministic):** for each cipher family and
  representative scheme (myg0N pair, lumolight zero-IV, Zombinder gen-2,
  LCG), encrypt a small ZIP/DEX in memory with a pinned seed; assert the
  engine finds exactly that (seed, scheme).
- **Negative controls:** wrong sibling scheme must not validate (hole-5
  precedent: installer scheme without `+1` fails); runtime-keyed random blob →
  `E-KDF-EXHAUSTED`.
- **Flag-lie fixture:** construct a deflate member with lying flag `0x1` and
  CRC-over-inflated; assert collector treats it as content, not ZipCrypto.
- **Budget/determinism:** tiny `attempts-cap` → `E-KDF-BUDGET`, identical
  `attempts` count across repeated runs.
- **LCG vectors:** `JavaRandom` determinism + MediaPlayer2 fixture.
- **RTO ground truth:** reuse pinned values from `tests/test_framework.py`
  (`myg0N2` → key/iv hex) to cross-check `derive_key` wiring.
- **Corpus acceptance (opt-in):** `@pytest.mark.slow` +
  `DFX_BREAKER_ACCEPTANCE=1`; resolves `RTO.apk`, `PENDRIVE DATA/**` from repo
  root; skips cleanly when samples are absent.

## 11. Acceptance Criteria (verified ground truth, 2026-10-15)

1. **Re-crack from scratch (no hand-feeding):**
   - `RTO.apk` (repo root, kit zip sha256 `d414cb8f…`) and
     `RTO E CHALLAN (1).apk` → 10-entry kit, `bootstrap.dex` sha256
     `35b4852821b26aa1…`; same assertion for `PNB One.apk`,
     `Repair service.apk` (myg0N scheme).
   - `PNB ONE ACTIVATION.apk` → `assets/wyvhtvmqlcbfmi9w/bhtn0kbg` →
     `classes.dex` (622,896 B) sha256 `1049fdaa…`; `M PARIWAHAN CHALAN
     (12).apk` → `kesaj3fo` → `classes.dex` sha256 `65efa657…` (lumolight
     `SHA1(basename)[:16]`, zero IV).
2. **New autonomous crack:** `MediaPlayer2.apk` → LCG `seed =
   asset_number + 0xFFFF`, nextInt-LE keystream → ZIP sha256 `5b5697c9…9b5e`,
   `classes.dex` sha256 `6babf08a…e9a3`. (Previously never recovered by any
   tool — manual session work only; today's verification is the discovery,
   the acceptance requires the *engine* to reproduce it end-to-end.)
3. **Zero false positives:** the known dead ends (`Calculator` ×3 Ijiami,
   `Tubi-inin`/`Google Video` loaders, genuine ZipCrypto containers,
   runtime-keyed assets) return typed misses, no fabricated hits; unit
   negative controls pass.
4. **Honest coverage:** every non-hit has `attempts`/`space_size`/
   `truncation` recorded; acceptance run summary written to
   `analysis/master_key_breaker/` (local-only evidence, untracked).

## 12. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Combinatorial blowup (seeds × schemes × blobs) | priors first, dedupe by key, attempt caps, early exit, string caps |
| False positive from weak magics | two-stage validation, evidence levels, negative-control tests |
| Genuine ZipCrypto mistaken for flag-lie | CRC-over-inflated + inflate-success check (verified logic) |
| Deflate members decrypted without inflating (silent miss) | collector contract §4.5; MediaPlayer2 regression pinned in tests |
| LCG convention space | verified convention first; alternatives enumerated and tested |
| Large batch runtime on 67-file corpus | per-APK caps, `--jobs`, acceptance uses attempt-cap determinism |

## 13. Follow-ups (not in this effort)

- Wire engine into `scripts/unpack.py` KDF fallback + `step0_master_key.py`
  catch-all adjustment, then corpus re-evaluation (explicitly approved pass).
- Dashboard/backend surface for ad-hoc runs.
- Oracle seed adapter (feed `emulate.py` traces directly as P3).
- Revisit cipher list (AES-CTR, etc.) only on new field evidence.
