# SOP — Packer Workstream (Tiers 1–2)

Standard operating procedure for the DroidForensix packer workstream.
Reference material lives in `docs/PACKERS.md`; blocker evidence in
`analysis/emulate/calc_ijiami/PHASE1_GATE.md`.

**Scope boundary:** this SOP governs only `docs/PACKERS.md`, `docs/PACKER_SOP.md`,
`scripts/unpack.py`, `scripts/emulate.py`, `scripts/find_soft_packers.py`,
`tests/test_emulate_ijiami.py`, `tests/test_step10_packer.py`,
`tests/test_unpacking_tool.py`, `data/packer_markers.json`, `analysis/emulate/`.
Never mix packer and classifier changes in one commit.

**Excluded:** Frida / device-level hooks and hardened-VM bytecode RE
(`E-HARDENED-VM`) are out of scope until explicitly authorized — PHASE1_GATE
returned NO-GO for the static route.

## Standing rules (every step)

- Minimal changes; every changed line traces to a packer task.
- Every run ends in exactly one of: `RECOVERED` (self-validated payload) or a
  **typed E-code** — no untyped outcomes, no swallowed exceptions.
- Reuse the existing dispatcher/oracle; extend E-codes rather than bypassing routes.
- Numbers reported honestly, including "scan found few soft packers".
- No system mutation: no installs, no config changes, no services; corpus and
  repo data are read-only except the declared output files.

## Phase A — Land & Measure (tier 1)

| # | Step | Command / action | Gate to pass |
|---|------|------------------|--------------|
| A1 | Baseline tests | `python -m pytest tests/test_emulate_ijiami.py tests/test_step10_packer.py tests/test_unpacking_tool.py -q` | All green |
| A2 | Land in-flight work | `git add` exactly the packer files → one commit (message: E-HARDENED-VM + Legu boundary + PHASE1_GATE reference) | `git status` shows packer files clean; workstreams not interleaved |
| A3 | Corpus scan | `python scripts/find_soft_packers.py samples/malware --out evaluation/soft_packers_found.json` (plus `samples/goodware`, `samples/legitimate` as FP controls) | JSON written; every matched APK classified `SOFT` / `HARD` / `MIXED` / `NONE` |
| A4 | Decision gate | Report totals per family × verdict; proposed family order (most-SOFT first) | User approves tier 2 scope/order — or stop here |

## Phase B — Per-family recovery loop (tier 2, repeat per family)

| # | Step | Detail |
|---|------|--------|
| B1 | Select family | Order from A4 scan results (default: highest SOFT count first) |
| B2 | Sample set | Start with 3–5 APKs carrying that family's markers |
| B3 | Route check | `python scripts/unpack.py <apk> --out report.json` → confirm `sniff_family` routes correctly; fix via `data/packer_markers.json` if misrouted (data-first, no code) |
| B4 | Hardened gate | Native route: `is_hardened_vm` — hardened ⇒ `E-HARDENED-VM`, no emulator minutes burned, no retry |
| B5 | Oracle run | Soft ⇒ `run_jni_oneshot`. If faulting: debug stubs — **max 3 attempts per sample, then escalate to user** |
| B6 | Outcome | Success = payload DEX self-validated (padding-oracle + KDF/domain-chain checks) + `unpack_report.json`. Else typed E-code with `fault info` / `key_log` attached |
| B7 | Regression test | Add family case to the test file (fixture pattern from `test_emulate_ijiami.py`) — test must pass |
| B8 | Docs | Update PACKERS.md matrix row with evidence; add sniff fixes to markers JSON |
| B9 | Commit | One surgical commit per family: recovered/refused counts + E-code breakdown |
| B10 | Report | Updated table to user: family → n, recovered, E-code distribution |

## Stop rules

- Per-sample budget: 3 oracle-debug attempts, then escalate.
- Per-family budget: 2–5 days → untouched samples get honest typed E-codes.
- New blocker evidence ⇒ write a gate doc (PHASE1_GATE style) and recommend
  NO-GO instead of grinding.

## Definition of done (tier 2)

Every soft-family APK ends in `RECOVERED` or a typed E-code; tests green;
PACKERS.md reflects reality; scan JSON + per-family commits reproducible from
committed commands.
