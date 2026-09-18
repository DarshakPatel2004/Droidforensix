import json, os, csv

# 1. Campaign Purity (Original vs Final)
with open('D:/DroidForensix/evaluation_results/campaign_purity.json', 'r') as f:
    orig = json.load(f)['summary']
with open('D:/DroidForensix/evaluation_results/campaign_purity_final.json', 'r') as f:
    final = json.load(f)['summary']

print('=== CAMPAIGN PURITY CLUSTERING ===')
print('Original:  purity_all={:.4f}, non_single={:.4f}, coverage={:.4f}, edges={}'.format(
    orig["purity_all"]["purity"], orig["purity_all"]["non_singleton_purity"], orig["purity_all"]["coverage"], orig["edges"]))
print('Final:     purity_all={:.4f}, non_single={:.4f}, coverage={:.4f}, edges={}'.format(
    final["purity_all"]["purity"], final["purity_all"]["non_singleton_purity"], final["purity_all"]["coverage"], final["edges"]))
print('Improvement: +{:.2f}% purity_all'.format((final["purity_all"]["purity"]-orig["purity_all"]["purity"])*100))

print()
print('=== HIGH-CONFIDENCE SUBSET ===')
print('Original:  purity={:.4f}, non_single={:.4f}, coverage={:.4f}'.format(
    orig["purity_high_conf"]["purity"], orig["purity_high_conf"]["non_singleton_purity"], orig["purity_high_conf"]["coverage"]))
print('Final:     purity={:.4f}, non_single={:.4f}, coverage={:.4f}'.format(
    final["purity_high_conf"]["purity"], final["purity_high_conf"]["non_singleton_purity"], final["purity_high_conf"]["coverage"]))
print()

# 2. FP Validation
with open('D:/DroidForensix/evaluation_results/fp_validation_auto.json', 'r') as f:
    fp = json.load(f)
print('=== FP VALIDATION (Auto) ===')
s = fp['summary']
print('Total samples: {}'.format(s["total_samples"]))
print('Total indicators: {}'.format(s["total_indicators"]))
print('Benign: {} ({:.1f}%)'.format(s["benign"], s["benign"]/s["total_indicators"]*100))
print('Suspicious: {} ({:.1f}%)'.format(s["suspicious"], s["suspicious"]/s["total_indicators"]*100))
print('Malicious: {} ({:.1f}%)'.format(s["malicious"], s["malicious"]/s["total_indicators"]*100))
print('Overall FP Rate: {:.2f}%'.format(s["fp_rate"]))
print()

# 3. Legitimacy Check
with open('D:/DroidForensix/evaluation_results/legitimacy_check.json', 'r') as f:
    leg = json.load(f)
print('=== LEGITIMACY CHECK ===')
print('IPs: {} total, {} unknown, {} reserved'.format(leg["total_ips"], leg["ip_summary"].get("unknown",0), leg["ip_summary"].get("reserved",0)))
print('Domains: {} total, {} benign, {} junk'.format(leg["total_domains"], leg["domain_summary"].get("BENIGN",0), leg["domain_summary"].get("JUNK",0)))
print()

# 4. Domain Classification
with open('D:/DroidForensix/analysis/c2_domain_classification.json', 'r') as f:
    c2 = json.load(f)
print('=== DOMAIN CLASSIFICATION ===')
print('Total domains: {}'.format(c2["total_domains"]))
for k, v in c2['summary'].items():
    print('  {}: {}'.format(k, v))
print()

# 5. Family ID coverage
print('=== FAMILY ID COVERAGE ===')
with open('D:/DroidForensix/ground_truth_all.csv', 'r') as f:
    reader = csv.DictReader(f)
    families = {}
    for row in reader:
        if row.get('is_malware') == 'yes':
            fam = row.get('family', 'unknown')
            families[fam] = families.get(fam, 0) + 1
total = sum(families.values())
print('Total malware samples: {}'.format(total))
print('Unique families: {}'.format(len(families)))
unknown = families.get('unknown', 0)
print('Unknown family samples: {} ({:.1f}%)'.format(unknown, unknown/total*100))
print('Known family samples: {} ({:.1f}%)'.format(total-unknown, (total-unknown)/total*100))