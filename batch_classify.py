import sys
sys.path.insert(0, 'D:/DroidForensix')
from analysis.classify_fast import classify_malware_fast
import os
import pandas as pd

legitimate = 'D:/DroidForensix/samples/legitimate'
apks = [f for f in os.listdir(legitimate) if f.endswith('.apk')]

results = []
for i, f in enumerate(apks[20:40]):
    idx = 20 + i
    path = os.path.join(legitimate, f)
    try:
        is_mal, conf = classify_malware_fast(path, pipeline_timeout=600)
        results.append({'file': f, 'is_malicious': int(is_mal), 'confidence': conf})
        print(str(idx+1) + '/100: ' + f + ' -> malicious=' + str(is_mal) + ', conf=' + str(conf))
    except Exception as e:
        print(str(idx+1) + '/100: ' + f + ' -> ERROR: ' + str(e))
        results.append({'file': f, 'is_malicious': -1, 'confidence': -1})

df = pd.DataFrame(results)
df.to_csv('D:/DroidForensix/evaluation/legitimate_predictions_20_40.csv', index=False)
mal_count = sum(1 for r in results if r['is_malicious'] == 1)
benign_count = sum(1 for r in results if r['is_malicious'] == 0)
error_count = sum(1 for r in results if r['is_malicious'] == -1)
print('Batch 2: Predicted malicious: ' + str(mal_count) + ', benign: ' + str(benign_count) + ', errors: ' + str(error_count))