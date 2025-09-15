"""
Train a RandomForest model on processed IOCs with proper balanced labels.
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

    # Convert to datetime object
    if isinstance(first_seen, str):
        try:
            first_seen_dt = datetime.strptime(first_seen, "%Y-%m-%d %H:%M:%S")
        except Exception:
            return 0
    else:
        first_seen_dt = first_seen

    # Make tz-aware (UTC)
    if first_seen_dt.tzinfo is None:
        first_seen_dt = first_seen_dt.replace(tzinfo=timezone.utc)

    # Compute hours difference
    delta_hours = (now - first_seen_dt).total_seconds() / 3600
    return 1 if (delta_hours <= 48 or malware) else 0

df["high_risk"] = df.apply(compute_high_risk, axis=1)

# ---------------------------
# Feature engineering
# ---------------------------
# Days since first_seen
def compute_days_since_first_seen(x):
    if not x:
        return 0
    if isinstance(x, str):
        try:
            dt = datetime.strptime(x, "%Y-%m-%d %H:%M:%S")
        except Exception:
            return 0
    else:
        dt = x
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (now - dt).days

df["days_since_first_seen"] = df["first_seen"].apply(compute_days_since_first_seen)

# Fill missing threat_type / ioc_type
df["ioc_type"] = df["ioc_type"].fillna("unknown")
df["threat_type"] = df["threat_type"].fillna("unknown")

# Select features
features = ["ioc_type", "threat_type", "days_since_first_seen"]
X = df[features]
y = df["high_risk"]

# One-hot encode categorical features
encoder = OneHotEncoder(sparse_output=False, handle_unknown="ignore")
X_encoded = encoder.fit_transform(X[["ioc_type", "threat_type"]])
X_final = pd.DataFrame(X_encoded, columns=encoder.get_feature_names_out(["ioc_type", "threat_type"]))
X_final["days_since_first_seen"] = X["days_since_first_seen"].values

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
