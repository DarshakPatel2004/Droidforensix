#!/usr/bin/env python3
"""Verify 97% accuracy is real by checking family overlap between training and test sets."""

import os
import json
import time
import pandas as pd
from dotenv import load_dotenv

load_dotenv()

VT_KEY = os.getenv('VT_KEY')
if not VT_KEY:
    raise RuntimeError("VT_KEY not set in .env")

try:
    import vt
except ImportError:
    raise RuntimeError("pip install vt-py")

# Load training families
gt = pd.read_csv('ground_truth_all_corrected.csv')
malware = gt[gt['is_malware'] == 'yes']
train_families = set(malware['family'].dropna().unique())
print(f"Training families: {len(train_families)}")
print(f"Training family examples: {sorted(train_families)[:20]}")

# Load test samples
test_df = pd.read_csv('evaluation/untested_malware_all.csv')
test_shas = test_df['sha256'].tolist()
print(f"\nTest samples: {len(test_shas)}")

# Query VirusTotal
client = vt.Client(VT_KEY)

test_families = []
results = []

for i, sha in enumerate(test_shas):
    print(f"[{i+1}/{len(test_shas)}] Querying {sha}...")
    try:
        file_obj = client.get_object(f"files/{sha}")
        # Get popular threat classification
        family = "Unknown"
        if hasattr(file_obj, 'popular_threat_classification') and file_obj.popular_threat_classification:
            pop = file_obj.popular_threat_classification
            if pop.suggested_threat_label:
                family = pop.suggested_threat_label
            elif pop.popular_threat_category:
                family = pop.popular_threat_category[0]
        elif hasattr(file_obj, 'meaningful_name') and file_obj.meaningful_name:
            family = file_obj.meaningful_name
        
        test_families.append(family)
        results.append({'sha256': sha, 'vt_family': family})
        print(f"  -> {family}")
    except vt.error.APIError as e:
        if "NotFound" in str(e):
            print(f"  -> Not found in VT")
            test_families.append("VT_NotFound")
            results.append({'sha256': sha, 'vt_family': "VT_NotFound"})
        else:
            print(f"  -> API Error: {e}")
            test_families.append("VT_Error")
            results.append({'sha256': sha, 'vt_family': "VT_Error"})
    except Exception as e:
        print(f"  -> Error: {e}")
        test_families.append("Error")
        results.append({'sha256': sha, 'vt_family': "Error"})
    
    # Rate limit: 4 requests/min = 15 sec between requests
    if i < len(test_shas) - 1:
        time.sleep(15)

# Save results
results_df = pd.DataFrame(results)
results_df.to_csv('reports/vt_test_families.csv', index=False)
print(f"\nSaved to reports/vt_test_families.csv")

# Calculate overlap
test_family_set = set([f for f in test_families if f not in ("VT_NotFound", "VT_Error", "Error", "Unknown")])
overlap = train_families & test_family_set
new_families = test_family_set - train_families
overlap_pct = len(overlap) / len(test_family_set) * 100 if test_family_set else 0

print(f"\n{'='*60}")
print(f"RESULTS")
print(f"{'='*60}")
print(f"Test families found: {len(test_family_set)}")
print(f"Training families: {len(train_families)}")
print(f"Overlap: {len(overlap)} / {len(test_family_set)} = {overlap_pct:.1f}%")
print(f"\nOverlap families: {sorted(overlap)}")
print(f"\nNew families in test (not in training): {sorted(new_families)}")

print(f"\n{'='*60}")
print(f"INTERPRETATION")
print(f"{'='*60}")
if overlap_pct > 70:
    print(f"⚠️  HIGH OVERLAP ({overlap_pct:.1f}%) - 97% accuracy may be overfitting to family patterns")
    print(f"    Recommendation: Retrain on family-blind features or acknowledge limitation")
elif overlap_pct >= 30:
    print(f"⚡ MODERATE OVERLAP ({overlap_pct:.1f}%) - Mixed signal")
    print(f"    Recommendation: Note in thesis, acceptable but not definitive")
else:
    print(f"✅ LOW OVERLAP ({overlap_pct:.1f}%) - 97% accuracy is REAL (different malware, same accuracy)")
    print(f"    Recommendation: Strong evidence for real-world generalization")

client.close()