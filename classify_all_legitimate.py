import sys
sys.path.insert(0, 'D:/DroidForensix')
from analysis.classify_fast import classify_malware_fast
import os
import pandas as pd
import time

legitimate = 'D:/DroidForensix/samples/legitimate'
apks = [f for f in os.listdir(legitimate) if f.endswith('.apk')]
print('Total APKs to classify: ' + str(len(apks)))

# Load existing results if any
output_file = 'D:/DroidForensix/evaluation/legitimate_predictions_all.csv'
if os.path.exists(output_file):
    existing = pd.read_csv(output_file)
    processed_files = set(existing['file'].tolist())
    results = existing.to_dict('records')
    print('Loaded ' + str(len(results)) + ' existing results')
else:
    processed_files = set()
    results = []

# Process each APK
for i, f in enumerate(apks):
    if f in processed_files:
        print(str(i+1) + '/' + str(len(apks)) + ': ' + f + ' -> SKIPPED (already processed)')
        continue
    
    path = os.path.join(legitimate, f)
    try:
        start = time.time()
        is_mal, conf = classify_malware_fast(path, pipeline_timeout=600)
        elapsed = time.time() - start
        results.append({'file': f, 'is_malicious': int(is_mal), 'confidence': conf, 'time_sec': round(elapsed, 1)})
        print(str(len(results)) + '/' + str(len(apks)) + ': ' + f + ' -> malicious=' + str(is_mal) + ', conf=' + str(conf) + ', time=' + str(round(elapsed,1)) + 's')
    except Exception as e:
        print(str(len(results)+1) + '/' + str(len(apks)) + ': ' + f + ' -> ERROR: ' + str(e))
        results.append({'file': f, 'is_malicious': -1, 'confidence': -1, 'time_sec': -1})
    
    # Save progress every 5 samples
    if len(results) % 5 == 0:
        df = pd.DataFrame(results)
        df.to_csv('D:/DroidForensix/evaluation/legitimate_predictions_all.csv', index=False)
        print('  ... saved progress (' + str(len(results)) + '/' + str(len(apks)) + ')')

# Final save
df = pd.DataFrame(results)
df.to_csv('D:/DroidForensix/evaluation/legitimate_predictions_all.csv', index=False)

# Summary
mal_count = sum(1 for r in results if r['is_malicious'] == 1)
benign_count = sum(1 for r in results if r['is_malicious'] == 0)
error_count = sum(1 for r in results if r['is_malicious'] == -1)
print()
print('FINAL SUMMARY:')
print('Total: ' + str(len(results)))
print('Predicted malicious: ' + str(mal_count))
print('Predicted benign: ' + str(benign_count))
print('Errors: ' + str(error_count))

# Compute metrics
from sklearn.metrics import accuracy_score, confusion_matrix
y_true = [0] * len(results)
y_pred = [r['is_malicious'] for r in results]
valid = [(yt, yp) for yt, yp in zip(y_true, y_pred) if yp != -1]
if valid:
    y_true_valid, y_pred_valid = zip(*valid)
    accuracy = accuracy_score(y_true_valid, y_pred_valid)
    # labels=[0, 1] forces a 2x2 matrix: y_true is all-zero, so without it
    # sklearn returns a 1x1 matrix and cm[0, 1] raises IndexError.
    cm = confusion_matrix(y_true_valid, y_pred_valid, labels=[0, 1])
    print()
    print('REAL-WORLD ACCURACY (excluding errors):')
    print('Accuracy: ' + str(round(accuracy*100, 1)) + '%')
    print('FP Rate: ' + str(cm[0,1]) + '/' + str(len(y_true_valid)) + ' = ' + str(round(cm[0,1]/len(y_true_valid)*100, 1)) + '%')