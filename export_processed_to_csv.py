"""
Export all documents from misp.processed_iocs to CSV for ML model training.
Usage:
  python3 export_processed_to_csv.py
Output:
  processed_iocs.csv in the current directory
"""
import csv
from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017/")
db = client["misp"]
coll = db["processed_iocs"]

fields = [
  "value", "ioc_type", "first_seen", "last_seen", "malware", "threat_type", "reporter",
  "features.confidence", "features.has_malware", "features.ioc_type", "features.threat_type", "features.days_since_first_seen"
]

with open("processed_iocs.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(fields)
    for doc in coll.find({}):
        row = [
            doc.get("value"),
            doc.get("ioc_type"),
            doc.get("first_seen"),
            doc.get("last_seen"),
            doc.get("malware"),
            doc.get("threat_type"),
            doc.get("reporter"),
            doc.get("features", {}).get("confidence"),
            doc.get("features", {}).get("has_malware"),
            doc.get("features", {}).get("ioc_type"),
            doc.get("features", {}).get("threat_type"),
            doc.get("features", {}).get("days_since_first_seen"),
        ]
        writer.writerow(row)
print("Exported processed_iocs to processed_iocs.csv")
