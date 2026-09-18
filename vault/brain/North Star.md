# North Star

## Current Focus (Thesis Timeline)
- Complete DroidForensix research and validation (deadline: May 2027)
- Publish findings on Android malware C2 infrastructure
- Target venues: Virus Bulletin, DFRWS, ACSAC

## Active Projects

### DroidForensix (Primary)
- **Status:** 9-step pipeline validated, 277 samples analyzed
- **Metrics:** 1,711 C2 indicators, 63x speedup vs manual
- **Current Blocker:** Confirm "100% missed by all aggregators" claim
- **Next Steps:** Finalize LinkedIn article, then paper draft
- **Architecture:** AndroGuard, threat intel, geospatial, synthesis

## Technical Environment
- **Machine:** Lenovo LOQ 15 (Ryzen 7435HS, RTX 4050 6GB, 24GB RAM)
- **OS:** Windows
- **Local LLM:** Mistral 7B via Ollama (method annotation)
- **Dev:** OpenCode (primary coding environment), Claude Code (architecture/audit)
- **GitHub:** DarshakPatel2004

## Research Principles
- Reproducibility > novelty
- Ablation studies on each pipeline step
- All claims validated against final_summary.json
- Documentation for open-source release
- Know your threat model explicitly

## Key Metrics to Track
- Samples processed: 277
- C2 indicators extracted: 1,711
- Unique IPs geolocated: 203 (75% Chinese cloud providers)
- Location clusters: 26 (2D Leaflet map)
- Performance improvement: 63x over manual analysis
- Pipeline steps: 9 validated
- Method similarity: SHA-256 fingerprinting

## Constraints
- Thesis deadline: May 2027
- Windows-native development
- Local inference preferred (privacy-sensitive)
- No cloud storage of code/samples

## Recent Wins
- 9-step pipeline fully validated
- Frontend: useReducer + WebSocket architecture
- PDF export with Quick/Full modes and per-phase timing
- Geospatial layer with 26 location clusters
- Threat Synthesis Engine designed (steps 10-18)
