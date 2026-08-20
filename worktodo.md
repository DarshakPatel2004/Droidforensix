# DroidForensix — Kali Linux Setup & Execution Guide

## 1. Environment Setup

```bash
cd DroidForensix
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-lock.txt
sudo apt install openjdk-17-jdk -y
chmod +x tools/jadx/bin/jadx
cp .env.example .env
# Edit .env with your API keys:
#   ANDROZOO_API_KEY, KOODOUS_API_KEY, VT_KEY,
#   MALWAREBAZAAR_API_KEY, OLLAMA_HOST, OLLAMA_MODEL
```

## 2. Download Samples (if starting fresh)

```bash
python scripts/download_samples.py --androzoo     # ~50 from AndroZoo
python scripts/download_samples.py --malware-only  # ~50 from MalwareBazaar
python scripts/download_samples.py --legit-only    # ~10 from F-Droid
```

Or copy the `samples/` folder from Windows if already collected.

## 3. Build Ground Truth

```bash
python scripts/build_ground_truth.py
# Outputs: ground_truth_all.csv
```

Queries MalwareBazaar + VirusTotal for family labels. Needs API keys in .env.

## 4. Batch Pipeline Analysis

```bash
python scripts/run_batch_analysis.py --max-samples 50
# Or all: python scripts/run_batch_analysis.py
```

Each sample: ~30-180s depending on size.

## 5. Validation / FP Check

```bash
python scripts/validate_fp.py
python scripts/check_legitimacy.py
```

## 6. Evaluation Metrics

```bash
python scripts/_analyze_val.py
```

## Notes

- Only `samples/` and scripts need to come from Windows
- `evaluation_results/` and `analysis/work/` were incomplete — start fresh
- Steps 3-6 depend on API keys and Ollama running
