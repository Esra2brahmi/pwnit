"""
Train a RandomForest model using advanced features from processed_iocs_advanced.csv.
Usage:
  python3 train_advanced_model.py
"""
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# Load data
csv_path = "processed_iocs_advanced.csv"
df = pd.read_csv(csv_path)

# Simple label: high risk if confidence >= 90 or has_malware == 1
# (You can adjust this logic for your needs)
df["high_risk"] = ((df["features.confidence"] >= 90) | (df["features.has_malware"] == 1)).astype(int)

# Features and label
feature_cols = [
    "features.confidence", "features.has_malware", "features.ioc_type", "features.threat_type",
    "features.days_since_first_seen", "features.days_since_last_seen", "features.seen_duration_days",
    "domain_length", "domain_digits", "domain_hyphens", "ip_octets"
]
X = df[feature_cols].fillna(0)
y = df["high_risk"]

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Evaluate
y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred))

# Optional: show feature importances
importances = clf.feature_importances_
for col, imp in zip(feature_cols, importances):
    print(f"{col}: {imp:.4f}")
