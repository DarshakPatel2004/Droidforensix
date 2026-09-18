import csv
import os
import sys
import time
from pathlib import Path

os.environ['JAVA_HOME'] = r'C:\Program Files\Microsoft\jdk-21.0.11.10-hotspot'
os.environ.pop('NVIDIA_NIM_API_KEY', None)
os.environ['LLM_PROVIDER'] = 'ollama'
os.environ['OLLAMA_HOST'] = 'http://localhost:11434'
os.environ['OLLAMA_MODEL'] = 'mistral:7b-instruct-q4_K_M'

sys.path.insert(0, 'D:/DroidForensix')
from analysis.pipeline import run_pipeline
from backend.config import settings

WORK_DIR = settings.WORK_DIR
SAMPLES_DIR = settings.SAMPLES_DIR
META_PATH = Path('D:/DroidForensix/sample_metadata.csv')
FIELDNAMES = ['sample_name', 'sha256', 'md5', 'family', 'source', 'type', 'tags',
              'file_size_bytes', 'status', 'vt_detections', 'collection_date']

def load_metadata():
    with open(META_PATH, 'r', newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))

def save_metadata(records):
    with open(META_PATH, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=FIELDNAMES)
        w.writeheader()
        for r in records:
            w.writerow({k: r.get(k, '') for k in FIELDNAMES})

records = load_metadata()
pending = [r for r in records if r.get('status') == 'pending']
print(f"[*] Analyzing {len(pending)} pending samples...")

for i, record in enumerate(pending, 1):
    sample_name = record['sample_name']
    candidates = list(Path(SAMPLES_DIR).rglob(sample_name))
    if not candidates:
        print(f"\n[!] Not found: {sample_name}")
        record['status'] = 'error: file not found'
        save_metadata(records)
        continue
    path = candidates[0]
    size_mb = path.stat().st_size / (1024 * 1024)
    print(f"\n[*] [{i}/{len(pending)}] {sample_name} ({size_mb:.1f} MB)")

    start = time.time()
    try:
        result = run_pipeline(str(path), str(WORK_DIR))
        elapsed = time.time() - start
        record['status'] = 'analyzed'
        c2s = len(result.get('c2_infrastructure', []))
        encs = len(result.get('encodings', []))
        payloads = len(result.get('payloads', []))
        chains = len(result.get('threat_chains', []))
        print(f"  [+] {elapsed:.1f}s | encodings={encs} payloads={payloads} c2s={c2s} chains={chains}")
    except Exception as e:
        elapsed = time.time() - start
        record['status'] = f'error: {e}'
        print(f"  [!] Error after {elapsed:.1f}s: {e}")

    save_metadata(records)

print(f"\n[+] Complete. {len(records)} samples processed.")
