"""
Advanced feature extraction from MongoDB for ML model training.
Reads from misp.processed_iocs and outputs a rich CSV for ML.
Usage:
  python3 feature_extraction_advanced.py
Output:
  processed_iocs_advanced.csv
"""
import csv
import re
from pymongo import MongoClient

def domain_features(domain):
    # Example: extract TLD, length, digit count, hyphen count
    tld = domain.split('.')[-1] if '.' in domain else ''
    length = len(domain)
    digits = sum(c.isdigit() for c in domain)
    hyphens = domain.count('-')
    return tld, length, digits, hyphens

def ip_features(ip):
    # Example: count octets, check for port
    octets = ip.split('.')
    port = None
    if ':' in ip:
        ip_part, port_part = ip.split(':', 1)
        port = port_part
    return len(octets), port

client = MongoClient("mongodb://localhost:27017/")
db = client["misp"]
coll = db["processed_iocs"]

fields = [
    "value", "ioc_type", "first_seen", "last_seen", "malware", "threat_type", "reporter",
    "features.confidence", "features.has_malware", "features.ioc_type", "features.threat_type",
    "features.days_since_first_seen", "features.days_since_last_seen", "features.seen_duration_days",
    "domain_tld", "domain_length", "domain_digits", "domain_hyphens", "ip_octets", "ip_port"
]

with open("processed_iocs_advanced.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(fields)
    for doc in coll.find({}):
        value = doc.get("value", "")
        ioc_type = doc.get("ioc_type", "")
        # Domain features
        domain_tld, domain_length, domain_digits, domain_hyphens = ("", "", "", "")
        ip_octets, ip_port = ("", "")
        if ioc_type == "domain":
            domain_tld, domain_length, domain_digits, domain_hyphens = domain_features(value)
        elif ioc_type == "ip":
            ip_octets, ip_port = ip_features(value)
        row = [
            value,
            ioc_type,
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
            doc.get("features", {}).get("days_since_last_seen"),
            doc.get("features", {}).get("seen_duration_days"),
            domain_tld,
            domain_length,
            domain_digits,
            domain_hyphens,
            ip_octets,
            ip_port
        ]
        writer.writerow(row)
print("Exported advanced features to processed_iocs_advanced.csv")
