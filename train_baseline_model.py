"""
Train a RandomForest model on processed IOCs with richer features.
Usage:
  python3 train_baseline_model.py
"""
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import OneHotEncoder
from pymongo import MongoClient
from datetime import datetime, timezone

# ---------------------------
# Connect to MongoDB
# ---------------------------
client = MongoClient("mongodb://localhost:27017/")
db = client["misp"]
coll = db["processed_iocs"]

# ---------------------------
# Load data from MongoDB
# ---------------------------
records = list(coll.find({}))
df = pd.DataFrame(records)
print(f"Loaded {len(df)} IOCs from MongoDB")

# ---------------------------
# Current time (UTC)
# ---------------------------
now = datetime.now(timezone.utc)

# ---------------------------
# Create high_risk label
# ---------------------------
def compute_high_risk(row):
    first_seen = row.get("first_seen")
    malware = row.get("malware")
    if not first_seen:
        return 0

    # Convert to datetime
    if isinstance(first_seen, str):
        try:
            first_seen_dt = datetime.strptime(first_seen, "%Y-%m-%d %H:%M:%S")
        except Exception:
            return 0
    else:
        first_seen_dt = first_seen

    # Make tz-aware
    if first_seen_dt.tzinfo is None:
        first_seen_dt = first_seen_dt.replace(tzinfo=timezone.utc)

    delta_hours = (now - first_seen_dt).total_seconds() / 3600
    return 1 if (delta_hours <= 48 or malware) else 0

df["high_risk"] = df.apply(compute_high_risk, axis=1)

# ---------------------------
# Extract features from nested "features" dict
# ---------------------------
features_df = pd.json_normalize(df["features"])

# Merge back into main dataframe
for col in features_df.columns:
    df[col] = features_df[col]

# Fill missing values
df["ioc_type"] = df["ioc_type"].fillna("unknown")
df["threat_type"] = df["threat_type"].fillna("unknown")
df["confidence"] = df["confidence"].fillna(0)
df["has_malware"] = df["has_malware"].fillna(0)
df["days_since_first_seen"] = df["days_since_first_seen"].fillna(0)
df["days_since_last_seen"] = df["days_since_last_seen"].fillna(0)
df["seen_duration_days"] = df["seen_duration_days"].fillna(0)

# ---------------------------
# Select features
# ---------------------------
categorical = ["ioc_type", "threat_type"]
numeric = ["confidence", "has_malware", "days_since_first_seen", "days_since_last_seen", "seen_duration_days"]

X_cat = df[categorical]
X_num = df[numeric]
y = df["high_risk"]

# One-hot encode categorical features
encoder = OneHotEncoder(sparse_output=False, handle_unknown="ignore")
X_cat_encoded = encoder.fit_transform(X_cat)
X_cat_df = pd.DataFrame(X_cat_encoded, columns=encoder.get_feature_names_out(categorical))

# Combine numeric + encoded categorical
X_final = pd.concat([X_num.reset_index(drop=True), X_cat_df.reset_index(drop=True)], axis=1)

# ---------------------------
# Train/test split
# ---------------------------
X_train, X_test, y_train, y_test = train_test_split(X_final, y, test_size=0.2, random_state=42)

# ---------------------------
# Train RandomForest
# ---------------------------
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# ---------------------------
# Evaluate
# ---------------------------
y_pred = clf.predict(X_test)
print("Classification report:\n")
print(classification_report(y_test, y_pred))

# ---------------------------
# Feature importance
# ---------------------------
importances = clf.feature_importances_
feature_names = X_final.columns
print("\nFeature importances:")
for name, imp in zip(feature_names, importances):
    print(f"{name}: {imp:.3f}")
