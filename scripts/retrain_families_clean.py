#!/usr/bin/env python3
"""Retrain family classifier on clean labels only."""

import sys
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import cross_val_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analysis.labels import is_catch_all  # same label policy as the scorer

gt = pd.read_csv(ROOT / 'ground_truth_all_corrected.csv')

# Clean sources (exclude abusech which is 82.6% catch-all)
clean_sources = ['AndroZoo', 'androzoo_drebin', 'modern_eval']

malware = gt[
    (gt['is_malware'] == 'yes') & 
    (gt['source'].isin(clean_sources)) & 
    (~gt['family'].fillna('').map(is_catch_all))
].copy()

print(f"Original malware: {len(gt[gt['is_malware']=='yes'])}")
print(f"Clean subset: {len(malware)}")
print(f"Families in clean: {malware['family'].nunique()}")
print("Families:", sorted(malware['family'].unique()))

# Load features
feats = pd.read_csv(ROOT / 'evaluation' / 'classifier_data' / 'features.csv')

# Merge
train_set = malware.merge(feats, on='sha256', how='inner', suffixes=('', '_feat'))
print(f"Samples with features: {len(train_set)}")

# Save clean training set
out_csv = ROOT / 'evaluation' / 'clean_family_train.csv'
train_set.to_csv(out_csv, index=False)
print(f"Saved to {out_csv}")

# Prepare features - unique columns don't get _feat suffix
feature_cols = [c for c in feats.columns if c not in ['sha256', 'is_malware', 'source', 'family']]
X = train_set[feature_cols]
y = train_set['family']

# 5-fold CV
clf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1, max_depth=20)
scores = cross_val_score(clf, X, y, cv=5, scoring='accuracy')
print(f"\n5-Fold CV Accuracy (clean labels): {scores.mean():.1%} (+/- {scores.std():.1%})")

# Fit on full clean set
clf.fit(X, y)
y_pred = clf.predict(X)
train_acc = accuracy_score(y, y_pred)
print(f"Training Accuracy (clean): {train_acc:.1%}")

# Per-source breakdown
for source in clean_sources:
    source_mask = train_set['source'] == source
    if source_mask.sum() > 0:
        X_source = X[source_mask]
        y_source = y[source_mask]
        y_pred_source = clf.predict(X_source)
        acc = accuracy_score(y_source, y_pred_source)
        print(f"  {source}: {acc:.1%} (n={int(source_mask.sum())})")

# Feature importance
importances = pd.DataFrame({
    'feature': feature_cols,
    'importance': clf.feature_importances_
}).sort_values('importance', ascending=False)
print("\nTop 15 features:")
print(importances.head(15).to_string(index=False))

# Save model
import joblib

joblib.dump(clf, 'evaluation/family_classifier_clean.pkl')
print("\nSaved model to evaluation/family_classifier_clean.pkl")