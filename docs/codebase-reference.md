# DroidForensix Codebase Reference

> Comprehensive documentation of every source file, its purpose, and the algorithms it implements.

---

## Project Overview

**DroidForensix** is an automated Android malware static-analysis pipeline that extracts C2 infrastructure from bytecode without execution. 1,711 C2 indicators extracted from 277 malware samples across 12 countries. 63x speedup over manual analysis.

### Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI, Ollama (Mistral 7B) |
| Decompilation | AndroGuard, APKTool |
| Threat Intel | VirusTotal, AlienVault OTX, Shodan, Censys, AbuseIPDB |
| Geolocation | MaxMind GeoLite2 |
| Frontend | React 18, Leaflet, WebSocket, highlight.js, Recharts |

---

## 1. Analysis Pipeline (`analysis/`)

The 9-step pipeline orchestrates APK decomposition through report generation.

### `pipeline.py` — Pipeline Orchestrator (409 LOC)

**Purpose:** Coordinates all 9 pipeline steps sequentially with real-time progress events.

**Key Functions:**
- `run_pipeline(apk_path, event_emitter=None)` — Main entry point, runs all 9 steps
- `_run_step(step_fn, step_name, ...)` — Wraps a step with timing, event emission, error handling
- `_estimate_remaining_eta(apk_path, step_index)` — Bucket-based ETA by APK size

**Algorithms:**
- **ETA Estimation:** Buckets APK into <1MB (18s total), 1–10MB (31.5s), >10MB (45s); distributes across remaining steps
- **Event-driven progress:** Emits `step_started`, `step_completed`, `metric_updated`, `error`, `analysis_started`, `analysis_complete`
- **Fallback wrappers:** Steps 7 (obfuscation), 8 (LLM), and family ID wrapped in try/except for resilience
- **Result assembly:** Merges all step outputs into a single dict, strips lone surrogates via `_strip_surrogates()`

### `step1_apk_extraction.py` — APK Decomposition (353 LOC)

**Purpose:** Unpacks APK with apktool, extracts DEX class/string data with Androguard, parses AndroidManifest.xml, and extracts native library strings.

**Key Functions:**
- `extract_apk(apk_path, work_dir, sha256)` — Main entry point
- `compute_sha256(path)` / `compute_md5(path)` — File hashing
- `run_apktool(apk_path, output_dir)` — APK unpacking
- `run_androguard(apk_path)` — Fast DEX-level extraction
- `extract_native_strings(extract_dir)` — Multi-tool native .so string extraction
- `extract_package_name(manifest_path)` — Regex-based package name extraction

**Algorithms:**
- **Multi-tool native string extraction:** Tries radare2 → rabin2 → strings utility → pure-Python printable-ASCII fallback
- **Androguard path:** Pure-Python DEX parsing (~5s/APK), no external decompiler required
- **Manifest parsing:** Regex-based extraction of package, versions, SDK, permissions from AndroidManifest.xml

### `step2_string_enumeration.py` — String Extraction & Filtering (313 LOC)

**Purpose:** Extracts string literals, byte arrays, resource strings, and native strings from decompiled APK. Calculates Shannon entropy and filters framework/SDK noise.

**Key Functions:**
- `enumerate_strings(result, ...)` — Main entry point
- `shannon_entropy(data)` — Byte-level entropy
- `is_noisy_string(s)` — Framework/SDK noise filter
- `extract_java_strings(source_dir)` — Java string literal extraction
- `extract_smali_strings(decompile_dir)` — Smali fallback extraction
- `extract_androguard_strings(apk_path)` — Fast DEX string extraction
- `extract_resource_strings(extract_dir)` — Android resource strings

**Algorithms:**
- **Shannon Entropy:** `H = -Σ p(x)·log₂(p(x))` over UTF-8 byte representation
- **Multi-layer noise filtering:** DEX type descriptors, Java/Kotlin framework prefixes, pure-symbol/digit patterns, hex constants, dotted package names
- **Byte array extraction:** Regex `{0xNN, 0xNN, ...}` patterns from Java source
- **Multi-source strategy:** Androguard DEX (primary) → smali (fallback) → resources + native (always)

### `step3_encoding_detection.py` — Encoding Detection (442 LOC)

**Purpose:** Detects Base64, URL-safe Base64, hex, XOR, and custom encodings in enumerated strings with false-positive filtering.

**Key Functions:**
- `detect_encoding(strings, ...)` — Main entry point
- `try_base64_decode(s)` / `try_hex_decode(s)` / `try_urlsafe_base64_decode(s)` — Individual decoders
- `xor_brute_force(data, min_key=1, max_key=255)` — Brute-force XOR key search
- `calculate_confidence(alphabet, decode_ok, meaningful, entropy)` — Weighted confidence
- `is_likely_obfuscated_payload(value, source, entropy)` — 5-rule FP filter
- `has_meaningful_content(text)` — URL/IP/domain/email detection

**Algorithms:**
- **Multi-encoding detection:** Tries Base64 → hex → URL-safe Base64 → XOR → custom flag, early continuation
- **XOR brute-force:** Iterates keys 1–255, filters by printable ratio ≥ 0.70, boosts for meaningful content, returns top 3
- **False-positive filter (5 rules):** (1) meaningful content → keep; (2) suspicious source + high entropy → keep; (3) benign source/value → reject; (4) short strings in utility classes → reject; (5) high entropy alone → uncertain
- **Confidence formula:** `alphabet_match × 0.3 + decode_ok × 0.3 + meaningful × 0.2 + entropy_alignment × 0.2`, clamped [0,1]

### `step4_decoding.py` — Payload Decoding (321 LOC)

**Purpose:** Decodes detected encodings into raw bytes, extracts artifacts (URLs, IPs, domains, emails, phones), and detects binary payload types via magic bytes.

**Key Functions:**
- `decode_payloads(encodings, ...)` — Main entry point
- `decode_base64(s)` / `decode_hex(s)` / `decode_xor(s, key)` — Individual decoders
- `extract_urls(text)` / `extract_ips(text)` / `extract_domains(text)` — Artifact extractors
- `detect_binary(data)` — Magic byte detection (MZ, ELF, ZIP, PDF, PNG, JPEG)
- `extract_artifacts(decoded_bytes, context)` — Full artifact extraction with IP scoring

**Algorithms:**
- **Magic byte detection:** Checks first bytes against known signatures
- **IP legitimacy scoring:** Uses `calculate_ip_legitimacy_score()` from `ip_validation.py` — classifies as `likely_malicious` (0.95), `uncertain` (0.75), `likely_benign` (0.50)
- **Phone validation:** Uses `phonenumbers` library with E164 formatting
- **Multi-layer decoding enrichment:** Calls `multi_layer_decode()` to detect chained encodings
- **Artifact deduplication:** By (type, value) tuple

### `step5_c2_extraction.py` — C2 Infrastructure Extraction (1,213 LOC)

**Purpose:** Parses URLs, IPs, and domains from decoded payloads and raw source into structured C2 records with confidence scoring and extensive benign-domain allowlisting.

**Key Functions:**
- `extract_c2_infrastructure(decoded_payloads, ...)` — Main entry point
- `parse_url(url)` — URL component breakdown
- `classify_ip(ip)` — Private/loopback/VPN/public classification
- `calculate_c2_confidence(c2_record)` — Weighted confidence scoring
- `enrich_with_circl(c2_list, ...)` — Optional CIRCL pSSL/pDNS enrichment
- `is_benign_url(url)` / `is_ad_network(domain)` — Allowlist checks

**Algorithms:**
- **Benign domain allowlist:** ~500+ known-benign domains (Android SDK, Java, W3C, CDNs, PKI, payment gateways, social media APIs)
- **Code reference filtering:** Detects Java package/class refs masquerading as domains (uppercase letters, pseudo-TLDs, known prefixes)
- **Junk domain filtering:** File extensions as TLDs, single-word www subdomains, English words as SLDs
- **C2 confidence scoring:** Base 0.5, +0.2 for HTTP/HTTPS, +0.25 for public/VPN IP, +0.2 for recognized TLD, +0.15 for non-root path, ×0.5 for ad networks, capped [0,1]
- **CIRCL enrichment:** Passive SSL/DNS data via authenticated API

### `step6_correlation.py` — Threat Chain Correlation (229 LOC)

**Purpose:** Builds directed threat chains linking encoded strings → decoded payloads → C2 infrastructure with composite confidence scoring.

**Key Functions:**
- `build_threat_chains(encodings, decoded_payloads, c2_records)` — Main entry point

**Algorithms:**
- **Chain construction:** encoding → decoding_function → decoded_artifact → usage → c2 (up to 5 steps)
- **Composite confidence:** Weighted average with `[0.15, 0.20, 0.25, 0.20, 0.20]` weights; partial chains normalize by sum
- **C2 threshold:** Only C2 records ≥ 0.6 confidence included
- **Severity:** Critical (≥0.8 + public IP), High (≥0.7), Medium (default), Low (<0.5)

### `step7_llm_assessment.py` — LLM Severity Assessment (1,201 LOC)

**Purpose:** Sends threat chains to LLM (NVIDIA NIM / OpenRouter / Ollama) for severity assessment with JSON validation, sanity checks, and rule-based fallback.

**Key Functions:**
- `assess_with_llm(threat_chains, c2_results, obfuscation, secrets, ...)` — Main entry point
- `_call_nvidia_nim(messages, ...)` / `_call_ollama(messages, ...)` — Provider wrappers
- `parse_llm_json(text)` — JSON extraction from markdown
- `validate_assessment(assessment)` — Schema validation
- `sanity_check(assessment, ...)` — Cross-reference LLM output against indicators
- `heuristic_fallback(...)` — Rule-based fallback (6 tiers)
- `should_skip_llm(...)` — Benign app optimization

**Algorithms:**
- **LLM provider selection:** NVIDIA NIM (if key set) → OpenRouter → local Ollama; configurable via `LLM_PROVIDER`
- **Benign skip:** Skips LLM if no C2 ≥ 0.8 and no critical/high secrets → uses `benign_verdict_heuristic()`
- **Sanity check:** Elevates for critical secrets/significant obfuscation/active C2; caps at medium if no C2 present
- **Safety cap:** If no C2 ≥ 0.85 after LLM, caps risk at 30
- **Heuristic tiers:** C2 present (high/80), extreme obfuscation (high/75), chains present (medium/45), clean (low/25)

### `step8_obfuscation_analysis.py` — Obfuscation Analysis (667 LOC)

**Purpose:** Detects reflection, dynamic loading, packing, encrypted assets, and suspicious native libraries via Androguard cross-references and DEX entropy analysis.

**Key Functions:**
- `analyze_obfuscation(apk_path, result, ...)` — Main entry point
- `analyze_with_androguard(apk_path)` — Androguard bytecode analysis
- `calculate_obfuscation_score(indicators)` — Weighted 0–100 score
- `analyze_native_libraries(apk_path)` — ELF analysis with ELFBreaker
- `dex_entropy_from_apk(apk_path)` — Per-DEX Shannon entropy
- `analyze_assets(apk_path)` — Encrypted asset detection

**Algorithms:**
- **Cross-reference analysis:** Examines Androguard cross-refs to detect calls to reflection, classloaders, native loading, crypto, suspicious APIs (avoids framework false positives)
- **DEX packing detection:** Entropy > 7.5 = `likely_packed`
- **Asset analysis:** Tiny stub DEX (<10KB) + large assets (>50KB) + native libs = encrypted payload
- **Native library analysis:** Flags undersized (<16KB = loader stub), high-entropy (>7.8 = packed), stripped symbols
- **Obfuscation scoring:** Reflection (2pts, max 20), dynamic loading (5pts, max 20), native loading (3pts, max 10), crypto (1.5pts, max 15), suspicious APIs (1.5pts, max 15), dangerous perms (2pts, max 10), suspicious native (5pts, max 10), packed DEX (+15), encrypted assets (+15–25), behavior groups (+15–35)

### `step9_post_process.py` — Post-Processing Corrections (399 LOC)

**Purpose:** Applies sanity corrections for missed Metasploit stagers, benign false positives, suspicious package names, tiny DEX files, and decoding-without-C2 scenarios.

**Key Functions:**
- `post_process_result(result)` — Main entry point (applies all corrections in order)
- `correct_metasploit_stager(result)` — Boosts missed stagers
- `correct_benign_false_positive(result)` — Downgrades known benign apps
- `correct_tiny_dex(result)` — Boosts tiny DEX + dangerous perms
- `correct_suspicious_package(result)` — Boosts obfuscated/random package names
- `correct_decoding_no_c2(result)` — Boosts decoding chains without C2

**Algorithms:**
- **Metasploit detection:** Package match OR small APK (<100KB) + ≥3 reflection + ≥1 dynamic loading → high/85+
- **Benign FP correction:** Known benign packages with no public IP C2 → low/25
- **Tiny DEX:** <25 methods + dangerous perms + no code signals → medium/55
- **Suspicious package:** Random-looking names (all-consonant, mixed case, no vowels) → medium/55 or high/65
- **Order:** Malware corrections first → benign FP correction last

### Supporting Files

#### `decoding_engine.py` (760 LOC)
Multi-layer decoding engine that detects chained encodings (e.g., Base64 → XOR → Base64). Implements detectors for Base64, hex, Base32, Base58, URL encoding, and XOR. Uses entropy classification to distinguish encoded/packed/encrypted/plain data.

#### `hardcoded_secrets.py` (723 LOC)
Hardcoded secret detection using regex patterns for API keys, AWS secrets, JWT tokens, private keys, Firebase URLs, Telegram bot tokens, and other credentials. Assigns severity (critical/high/medium/low) per secret type.

#### `ip_validation.py` (262 LOC)
IP validation and legitimacy scoring. Validates IPv4/IPv6 format, classifies as public/private/loopback/reserved, and calculates a legitimacy score based on RFC compliance and known threat feeds.

#### `retry_utils.py` (108 LOC)
Retry utility with exponential backoff for flaky operations. Supports max retries, custom delay functions, and per-attempt callbacks.

#### `yara_rules.yar` (20,329 LOC)
Comprehensive YARA rule set for malware family detection. Covers Android malware, banking trojans, spyware, and adware families.

---

## 2. Backend (`backend/`)

### `main.py` — FastAPI Application (1,336 LOC)

**Purpose:** REST API server with 30+ endpoints for sample listing, analysis, dissection, threat intelligence, and WebSocket-based real-time analysis streaming.

**Key Components:**
- `ConnectionManager` — WebSocket connection management with broadcast
- `lifespan(app)` — Startup/shutdown handler (Ollama lifecycle)
- 30+ endpoint handlers

**Key Endpoints:**
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` | Health check |
| GET | `/api/samples` | List analyzed samples |
| GET | `/api/sample/{id}` | Full analysis report |
| GET | `/api/sample/{id}/attribution` | MAFIA attribution evidence |
| GET | `/api/sample/{id}/threat-summary` | Threat summary |
| GET | `/api/sample/{id}/dissection` | Full dissection data |
| GET | `/api/sample/{id}/dissection/{section}` | Per-tab dissection |
| GET | `/api/graph/{id}` | 3D graph data |
| GET | `/api/clusters` | Clustering data |
| POST | `/api/upload` | Upload APK |
| POST | `/analyze` | Trigger analysis |
| WS | `/ws` | Real-time events |

**Algorithms:**
- **SHA-256 deduplication:** Prevents duplicate uploads
- **WebSocket broadcast:** `asyncio.run_coroutine_threadsafe` for thread-safe event emission
- **On-demand dissection caching:** In-memory cache with 5min TTL
- **Jaccard similarity:** `_find_related_samples()` uses permission + domain Jaccard overlap
- **Static code annotation:** `_annotate_lines()` matches keywords against Java source lines

### `config.py` — Configuration (76 LOC)

**Purpose:** Pydantic-based settings loaded from `.env` and environment variables. Defines paths, LLM provider settings, timeouts, and CORS origins.

**Algorithms:**
- **LLM provider auto-detection:** `LLM_PROVIDER` field chooses between nvidia/openrouter/ollama
- **Directory auto-creation:** Creates required directories at module load

### `family_id.py` — Malware Family Identification (625 LOC)

**Purpose:** Multi-dimensional family identification combining ground-truth SHA-256 lookup, signature heuristics, obfuscation profiling, string patterns, YARA rules, and LLM classification into a weighted voting system.

**Key Functions:**
- `identify_family(sample_id, result, ...)` — Main orchestrator
- `_ground_truth_map()` — SHA-256 → family mapping from ground truth JSONs
- `_signature_candidates(result)` — Heuristic matching against 50+ family signatures
- `_obfuscation_candidates(result)` — Obfuscation profile matching
- `_string_pattern_candidates(result)` — Distinctive string matching
- `_yara_candidates(result)` — YARA rule matching
- `_llm_family(result)` — LLM-based classification

**Algorithms:**
- **Priority-based winner selection:** ground_truth (5) > yara/string (4) > signature (3) > obfuscation/llm (1)
- **Ground truth:** Exact SHA-256 match → confidence 1.0
- **Signature matching:** Substring token matching, base 0.55 (+0.40 if domain match), +0.10 per reason, capped 0.95
- **LLM fallback:** Only consulted when best deterministic confidence < 0.75

### `dissection.py` — APK Dissection Engine (713 LOC)

**Purpose:** Structural APK dissection using Androguard — extracts manifest, permissions, components, native libs, DEX stats, and file structure with thread-safe caching.

**Key Classes/Functions:**
- `APKDissector` — Main dissection class
- `SampleAPKCache` — Thread-safe per-sample APK cache
- `load_dissection(work_dir, sample_id)` — Cached dissection loading (5min TTL)

**Algorithms:**
- **Permission classification:** Compound level parsing + hardcoded dangerous/signature sets
- **Component exported-status:** Android default rules (exported if intent filters for activities/receivers/services)
- **Class caching:** Per-sample locks with atomic `os.replace(tmp, dest)`
- **Method body extraction:** DEX instruction disassembly via Androguard

### `threat_intel.py` — Threat Intelligence Aggregation (524 LOC)

**Purpose:** Builds the Phase-2 threat intelligence view with C2 classification, DNS resolution, GeoIP, ISP enrichment, and CSV/STIX/YARA export.

**Key Functions:**
- `build_threat_intel(result, sample_id)` — Main aggregation
- `classify_c2(c2)` — Benign/suspicious/malicious classification
- `to_csv(result)` / `to_stix(result, sample_id)` / `to_yara(result, sample_id)` — Export formats

**Algorithms:**
- **C2 classification:** TLD blacklist, port blacklist, protocol check, DNS resolution, pDNS history, path keywords
- **ISP enrichment:** ip-api.com with ≥1.4s rate limiting + file cache
- **DNS resolution:** `socket.getaddrinfo` with 2s timeout
- **STIX 2.0:** Generates domain/ipv4-addr patterns with bundle wrapper
- **YARA generation:** Auto-creates rules from malicious C2 indicators

### `threat_intelligence.py` — Multi-Source TI (420 LOC)

**Purpose:** Parallel threat intel queries to VirusTotal, OTX, Shodan, and Censys with consolidated risk scoring.

**Key Classes:**
- `ThreatIntelligenceEnricher` — Enricher with per-source query methods

**Algorithms:**
- **Parallel queries:** `ThreadPoolExecutor(max_workers=4)`
- **Evidence consolidation:** VT detections (+2), OTX pulses (+2), Shodan high-risk (+1.5) → HIGH ≥ 4, MEDIUM ≥ 2, LOW < 2
- **Rate-limit handling:** Detects HTTP 429 with retry

### `transformers.py` — Data Transformation (329 LOC)

**Purpose:** Converts pipeline results into frontend-friendly formats: 3D graphs, cluster scatter data, attack-chain timelines, and sample listings.

**Key Functions:**
- `transform_graph(result)` — 3D nodes/edges with deterministic MD5 IDs
- `transform_clusters(results)` — 3D scatter: x=encoding complexity, y=C2 sophistication, z=exfiltration volume
- `transform_timeline(result)` — Step-by-step threat chain timeline

**Algorithms:**
- **Graph node IDs:** `hashlib.md5(artifact + source)` for deterministic, deduplicatable IDs
- **Cluster axes:** Composite formulas (e.g., `avg_entropy + log1p(encoding_count)`)
- **Family index cache:** TTL-based invalidation (5s)

### `code_analysis.py` — Java Source Analysis (359 LOC)

**Purpose:** Parses decompiled Java source to extract methods, detect suspicious patterns (8 categories), extract string references, and reconstruct attack flow.

**Key Classes:**
- `CodeAnalyzer` — Main analysis class

**Algorithms:**
- **Suspicious pattern detection:** 27 regex patterns across 8 technique categories (reflection, payload drop, anti-analysis, crypto, network, dynamic loading, command exec)
- **Attack flow reconstruction:** Orders methods by entry point priority (onCreate > onStart > ... > onActivityResult)
- **Risk assessment:** Any CRITICAL technique → CRITICAL; any HIGH → HIGH; any technique → MEDIUM; else LOW

### `elf_analyzer.py` — ELF Binary Analysis (911 LOC)

**Purpose:** Comprehensive ELF analysis for Android native libraries — header extraction, section parsing, symbol table analysis, packing detection, anti-analysis scanning, and multi-technique string deobfuscation.

**Key Classes:**
- `ELFBreaker` — Main analyzer

**Algorithms:**
- **Packing detection:** Signature scanning (UPX, OLLVM) + high-entropy section (>7.5)
- **Anti-analysis detection:** 60+ patterns (ptrace, TracerPid, frida, xposed, debugger checks)
- **Readability scoring:** English digraph frequency, vowel ratio, chi-squared letter frequency, 200-word dictionary
- **String deobfuscation:** Single-byte XOR (keys 1–255), multi-byte XOR, ADD/SUB cipher (keys 1–32), ROT47
- **Risk scoring:** Weighted across JNI exports, packing, anti-analysis, suspicious APIs, C2 strings, deobfuscations, embedded blobs

### `circl_client.py` — CIRCL API Client (374 LOC)

**Purpose:** Authenticated client for CIRCL pSSL (passive SSL) and pDNS (passive DNS) APIs with rate limiting, pagination, and timeout handling.

**Algorithms:**
- **Rate limiting:** Configurable delay (default 2s) between requests
- **pDNS pagination:** NDJSON streaming with cursor-based pagination, auto-paginate up to 10 pages
- **Error handling:** HTTP 401 → CIRCLAuthError; retry on 5xx

### `censys_enrichment.py` — Censys IP Enrichment (208 LOC)

**Purpose:** Censys Platform API v3 enrichment for IP addresses with synchronous (pipeline) and async (batch) paths.

**Algorithms:**
- **Sync path:** `requests` with exponential backoff (2^n seconds) on 429/5xx, up to 4 retries
- **Async path:** `aiohttp` with `asyncio.Semaphore(3)` for global rate throttle (0.6s delay)
- **File cache:** JSON at `analysis/work/censys_cache.json`

### `events.py` — WebSocket Event Model (42 LOC)

**Purpose:** Defines `WebSocketEvent` dataclass with validated event types and automatic ISO timestamp generation.

### `validators.py` — Request Validation (45 LOC)

**Purpose:** Pydantic models for API request/response validation and WebSocket event validation.

### `obfuscation_view.py` — Obfuscation View Builder (263 LOC)

**Purpose:** Transforms Step-8 raw obfuscation data into dashboard-friendly structure with smali-to-Java method parsing and simple deobfuscation utilities.

### `pdf_report.py` — PDF Report Generation (390 LOC)

**Purpose:** Core PDF report using ReportLab — cover page, metadata, LLM assessment, obfuscation, C2 table, suspicious methods. Quick/full modes with section toggling.

### `pdf_report_enhanced.py` — Enhanced PDF + TI (892 LOC)

**Purpose:** Extended PDF generator with live TI enrichment (VT/OTX/Shodan/Censys), confidence-band method classification, STIX 2.0 export, and three-layer risk methodology explanation.

### `core/androguard_analyzer.py` — Androguard Static Analysis (528 LOC)

**Purpose:** Androguard-based static analysis for pipeline integration — metadata, permissions, FCM, native libs, obfuscation, suspicious strings, certificates, risk scoring.

### `core/apk_processor.py` — 7-Step Pipeline Orchestrator (671 LOC)

**Purpose:** Alternative 7-step static analysis pipeline using Androguard with per-step disk caching. Steps: Androguard analysis → string extraction → entropy analysis → encoding detection → payload decoding → C2 extraction → threat chain.

---

## 3. Frontend — React Application (`frontend/src/`)

### Entry Point & Routing

#### `main.jsx` (12 LOC)
Application entry point. Renders `<App />` in `StrictMode` with `BrowserRouter`.

#### `App.jsx` — Root Application Shell (732 LOC)

**Purpose:** Manages WebSocket connections, backend health polling, file upload with retry, and routing between Upload/Analysis/Dissection/Raw Code/Threat Intel views.

**Key Components:**
- `App()` — Routes `/sample/:id` to `SampleRoutePage`
- `AppInner()` — Main shell with sidebar, topbar, tab navigation
- `SampleRoutePage()` — Lazy-loads `SampleDetail` for direct URL access

**Algorithms:**
- **Exponential backoff:** `delay = min(2000 × 2^(attempt-1), 32000) + random(0..1000)` for upload retries
- **ETA estimation:** APK size tiers (<1MB = 18s, <10MB = 31.5s, else 45s)
- **WebSocket keepalive:** 20-second ping interval
- **Health polling:** 2-second interval when backend offline
- **Non-retryable statuses:** 400/413/422/429; retryable: 500/502/503/504

### Components

#### `AnalysisView.jsx` — Analysis Results View (1,340 LOC)

**Purpose:** Main analysis results view with three states (idle/running/complete) and tabbed interface (Overview, Secrets, LLM Summary, Dissection Summary, Obfuscation, Threat Chains, Manifest).

**Key Components:**
- `LoadingState` — Animated hex radar, progress bar, ETA, KPI cards
- `ResultView` — Fetches JSON, renders tabbed result interface
- `OverviewTab` — Assessment summary, family signals, metrics grid
- `ChainsTab` — Threat chains with sort/filter
- `ChainCard` — Collapsible chain with interactive decoder (Base64/Hex/URL/XOR/Custom JS)
- `ErrorState` — Error display with retry countdown

**Algorithms:**
- **Client-side decoding:** `atob()` for base64, regex hex parse, `decodeURIComponent()`, XOR with cyclic key, `new Function()` for custom JS
- **Chain sorting:** Severity order (critical=0 → low=3), confidence desc, or step count desc
- **Retry countdown:** `setInterval` + `setTimeout` with exponential backoff (max 3 retries)

#### `UploadPanel.jsx` — APK Upload Panel (359 LOC)

**Purpose:** Drag-and-drop upload with client-side validation (extension, MIME, size, magic bytes), simulated progress, and recently-uploaded sample list.

**Algorithms:**
- **File validation pipeline:** Sync checks (extension/MIME/size) → async magic byte check (ZIP `PK\x03\x04`)
- **Simulated progress:** 0–15% random increment every 250ms, capped at 90%
- **Retry progress:** `(attempt / maxRetries) × 100`

#### `FamilySignalsCard.jsx` — Family Attribution Card (161 LOC)

**Purpose:** Collapsible card showing family attribution signals — primary match, confidence, method badge, breakdown bars, candidates, related samples.

**Algorithms:**
- **Parallel fetch:** `Promise.all([attribution endpoint, threat-intel endpoint])` via `fetchWithCache`
- **Candidate filtering:** Excludes primary family name from candidates list
- **Empty state:** Returns `null` (renders nothing) when `family: "unknown"` or no data

#### `SmartDissection.jsx` — Interactive Code Dissection (563 LOC)

**Purpose:** Class browser with filtering, search, lazy-loaded methods, LLM analysis, syntax highlighting, and line annotations.

**Algorithms:**
- **Suspicion scoring:** Keyword matches in method names weighted 2× vs body text (1×)
- **Lazy loading:** Method bodies fetched on first expansion via `/class-methods/` endpoint
- **Filtering:** By malicious (suspicion heuristic) or obfuscated (cross-ref with obfuscation data)

#### `ThreatIntelView.jsx` — Threat Intelligence Dashboard (549 LOC)

**Purpose:** Full TI dashboard with C2 table, DNS verification, classification bars, family card, Leaflet map, PDF export.

**Algorithms:**
- **Active C2 rate:** `((dns.active + dns.likely_active) / max(c2s.length, 1)) × 100`
- **Map auto-bounds:** `L.latLngBounds` with `map.fitBounds()` on first load
- **Loading phases:** Rotates 5 phases (Resolving → DNS → Classification → Family → Geo) every 1.2s
- **PDF export:** POST to `/api/sample/{id}/report/pdf` with mode/sections, blob download

#### `ChainCard` (inline in `AnalysisView.jsx`)
Interactive threat chain step flow with expandable decoder. Step selection auto-populates decoder input from previous artifact.

#### `Toast.jsx` — Toast Notification System (69 LOC)
React Context-based toast system with 4 types (success/info/warning/error), auto-dismiss durations (3s/5s/8s/manual), and `useToast` hook.

#### `ErrorBoundary.jsx` — Error Boundary (56 LOC)
Class-based error boundary that catches render errors, logs to backend, and shows "Try Again" fallback.

### Tab Components (`components/tabs/`)

| File | LOC | Purpose |
|------|-----|---------|
| `CodeTab.jsx` | 562 | Code analysis with attack flow, method analysis, string references, sharing/export |
| `StringsTab.jsx` | 218 | Strings viewer with format detection, client-side decode, risk analysis, search |
| `NativeLibsTab.jsx` | 144 | Native library browser with ELF analysis details |
| `ManifestTab.jsx` | 84 | Raw manifest data display |
| `DEXTab.jsx` | 83 | DEX stats with Recharts donut entropy visualization |
| `PermissionsTab.jsx` | 53 | Permissions list with protection-level filter |
| `ComponentsTab.jsx` | 53 | Component browser with type filter |

### Shared/Utility Components

| File | LOC | Purpose |
|------|-----|---------|
| `ManifestView.jsx` | 242 | Manifest viewer with dangerous permission detection |
| `ThreatConsolidationSummary.jsx` | 277 | Consolidated threat assessment report |
| `AttributionEvidence.jsx` | 132 | Detailed attribution with confidence breakdown |
| `ObfuscationView.jsx` | 317 | Obfuscation analysis with deobfuscation tool |
| `ThreatSummary.jsx` | 102 | Compact threat summary card |
| `DissectionPage.jsx` | 60 | Page wrapper composing SmartDissection + ClassSourceViewer |
| `DissectionTabs.jsx` | 54 | Tabbed dissection browser |
| `RawCodeView.jsx` | 116 | Sidebar-based raw code browser |
| `ClassSourceViewer.jsx` | 83 | Decompiled Java source viewer with highlight.js |
| `RelatedSamples.jsx` | 66 | Related samples listing |
| `SampleSearch.jsx` | 66 | Sample search component |
| `MITREDisplay.jsx` | 113 | MITRE ATT&CK tactic display |
| `LLMVerificationBadge.jsx` | 91 | LLM verdict display |
| `ConfidenceBar.jsx` | 49 | Reusable confidence bar |
| `ThreatBadge.jsx` | 26 | Severity badge |
| `ComponentCard.jsx` | 24 | Android component card |
| `PermissionCard.jsx` | 26 | Android permission card |
| `LoadingSpinner.jsx` | 22 | Animated shimmer loading bar |

### Hooks & Utilities

| File | LOC | Purpose |
|------|-----|---------|
| `hooks/useSampleData.js` | 22 | Data fetching hook with caching |
| `api/client.js` | 38 | API client with in-memory request cache |
| `utils/fetchWithCache.js` | 15 | Lightweight memoized fetch wrapper |
| `utils/formatters.js` | 50 | Formatting utilities (duration, hash, severity, entropy) |

### Styles (`src/styles/` & `src/App.css`)

| File | LOC | Purpose |
|------|-----|---------|
| `App.css` | 1,525 | Global application styles |
| `index.css` | 129 | Reset and base styles |
| `styles/ThreatIntelView.css` | 802 | Threat intel dashboard styles |
| `styles/SmartDissection.css` | 607 | Code dissection styles |
| `styles/UploadPanel.css` | 568 | Upload panel + feature cards |
| `styles/AnalysisView.css` | 1,266 | Analysis view (includes FamilySignalsCard styles) |
| `styles/ManifestView.css` | 122 | Manifest viewer styles |
| `styles/ObfuscationView.css` | 117 | Obfuscation view styles |
| `styles/ClassSourceViewer.css` | 56 | Source code viewer styles |
| `styles/Toast.css` | 70 | Toast notification styles |

---

## 4. Tests

### Python Backend Tests (`tests/` — 17 files, 3,019 LOC)

| File | LOC | Tests |
|------|-----|-------|
| `test_attribution.py` | 272 | Attribution endpoint and family identification |
| `test_backend.py` | 139 | Backend endpoint health checks |
| `test_c2_and_correlation.py` | 364 | C2 extraction and threat chain correlation |
| `test_circl_client.py` | 254 | CIRCL client with mocked responses |
| `test_code_analysis.py` | 273 | Java source code analysis patterns |
| `test_dissection.py` | 412 | APK dissection engine |
| `test_encoding_detection.py` | 202 | Encoding detection algorithms |
| `test_hardcoded_secrets.py` | 250 | Secret detection patterns |
| `test_llm_obfuscation_anchor.py` | 65 | LLM obfuscation anchor tests |
| `test_module_imports.py` | 82 | Module import validation |
| `test_obfuscation_analysis.py` | 74 | Obfuscation analysis edge cases |
| `test_retry_utils.py` | 118 | Retry utility behavior |
| `test_smali_fallback.py` | 39 | Smali fallback path |
| `test_step9_post_process.py` | 473 | Post-processing corrections |

### Frontend React Tests (`frontend/__tests__/` — 38 test files, 248 total tests)

Every component and utility has a corresponding test file using Vitest + React Testing Library:

| Test File | Scenario Coverage |
|-----------|-------------------|
| `App.test.jsx` | Health check polling, upload interaction, WS events, navigation |
| `AnalysisView.test.jsx` | Loading, results, error states, chains, decoder, tabs |
| `UploadPanel.test.jsx` | Drag/drop, validation, progress, retry, sample list |
| `FamilySignalsCard.test.jsx` | Loading, empty, partial data, expand, unknown family, dedup, errors |
| `AttributionEvidence.test.jsx` | Loading, data display, error, empty |
| `SmartDissection.test.jsx` | Class listing, filtering, lazy loading |
| `ThreatIntelView.test.jsx` | Loading phases, C2 table, map, PDF export |
| `StringsTab.test.jsx` | Format detection, decode, risk classification, search |
| `CodeTab.test.jsx` | Attack flow, methods, sharing, export |
| `ChainCard.test.jsx` | Step flow, decoder, expansion, explanation |
| Plus 27 more component/utility tests | |

---

## 5. Scripts (`scripts/`)

| File | LOC | Purpose |
|------|-----|---------|
| `forensic_pipeline.py` | 1,078 | Full APK forensic pipeline for batch processing |
| `download_samples.py` | 644 | Sample downloader from AndroZoo and MalwareBazaar |
| `fetch_abusech_c2_samples.py` | 424 | Abuse.ch C2 feed integration |
| `fetch_github_malware.py` | 310 | GitHub malware repository downloader |
| `New-AndroidAnalysisVM.ps1` | 248 | Windows VM setup script |
| `check_live_c2.py` | 194 | C2 liveness checker |
| `download_drebin_androzoo.py` | 135 | Drebin dataset AndroZoo downloader |
| `run_batch_analysis.py` | 120 | Batch pipeline runner |
| `install_windows_tools.py` | 101 | Windows tool installer |
| `censys_backfill.py` | 88 | Censys batch enrichment backfill |

---

## 6. Evaluation (`evaluation/`)

| File | LOC | Purpose |
|------|-----|---------|
| `run_evaluation.py` | 190 | Full evaluation harness |
| `compute_metrics.py` | 64 | Precision/recall/F1 computation |
| `compute_balanced_metrics.py` | 146 | Balanced accuracy metrics |
| `eval_modern.py` | 178 | Modern sample evaluation set |
| `extract_ground_truth.py` | 43 | Ground truth extraction from metadata |

---

## 7. Configuration & Documentation (root)

| File | LOC | Purpose |
|------|-----|---------|
| `README.md` | 257 | Project overview, setup, API docs |
| `AGENTS.md` | 302 | AI coding agent guidelines |
| `API_SPEC.md` | 331 | Detailed API specification |
| `architecture.md` | 79 | System architecture document |
| `EVALUATION.md` | 171 | Evaluation methodology |
| `pytest.ini` | 4 | Pytest configuration with asyncio mode |
| `vitest.config.js` | 9 | Vitest configuration |
| `requirements.txt` | 35 | Flexible Python dependencies |
| `requirements-lock.txt` | 98 | Pinned Python dependencies |
