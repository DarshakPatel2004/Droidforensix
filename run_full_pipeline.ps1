# DroidForensix Full Pipeline Runner

Set-Location -Path "D:\\DroidForensix"

# 1. Start Ollama if not running
$ollamaRunning = $false
try {
    $null = Invoke-RestMethod -Uri "http://localhost:11434/api/tags" -Method Get -ErrorAction Stop
    $ollamaRunning = $true
    Write-Host "[+] Ollama already running"
} catch {
    Write-Host "[*] Starting Ollama..."
    Start-Process -FilePath "C:\Users\darsh\AppData\Local\Programs\Ollama\ollama.exe" -ArgumentList "serve" -WindowStyle Hidden
    Start-Sleep -Seconds 3
}

# 2. Set environment
$env:JAVA_HOME = "C:\Program Files\Microsoft\jdk-21.0.11.10-hotspot"

# 3. Reset sample statuses to pending
python -c "
import csv
records = []
with open('sample_metadata.csv', 'r', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        row['status'] = 'pending'
        records.append(row)
fn = ['sample_name','sha256','md5','family','source','type','tags','file_size_bytes','status','vt_detections','collection_date']
with open('sample_metadata.csv', 'w', newline='', encoding='utf-8') as f:
    w = csv.DictWriter(f, fieldnames=fn)
    w.writeheader()
    for r in records:
        w.writerow({k: r.get(k, '') for k in fn})
print(f'Reset {len(records)} to pending')
"

# 4. Run pipeline
Write-Host "[*] Running pipeline on all samples..."
python run_pipeline_direct.py

Write-Host "[+] Pipeline complete"
