"""
ETL preprocessing script
- Reads from `misp.iocs`, `misp.ioc_domains`, `misp.ioc_ips`
- Produces simplified processed documents into `misp.processed_iocs`

Usage:
  python3 etl_preprocess.py --limit 100

"""
import argparse
from datetime import datetime, timezone
from pymongo import MongoClient, UpdateOne

client = MongoClient("mongodb://localhost:27017/")
db = client["misp"]

iocs = db["iocs"]
domains = db["ioc_domains"]
ips = db["ioc_ips"]
processed = db["processed_iocs"]

parser = argparse.ArgumentParser()
parser.add_argument("--limit", type=int, default=100, help="Number of events to process (0 = all)")
args = parser.parse_args()

limit = args.limit

query = {}
cursor = iocs.find(query).sort([("timestamp", -1)])
if limit and limit > 0:
    cursor = cursor.limit(limit)

ops = []
count = 0
for ev in cursor:
    # Each event may have Attribute list
    attrs = ev.get("Attribute", [])
    for a in attrs:
        # determine canonical fields
        ioc_type = a.get("type")
        value = a.get("value")
        first_seen = a.get("first_seen") or a.get("first_seen_utc")
        last_seen = a.get("last_seen") or a.get("last_seen_utc")

        # normalize timestamps
        def to_dt(x):
            if not x:
                return None
            if isinstance(x, str):
                try:
                    # ThreatFox used 'YYYY-MM-DD HH:MM:SS'
                    return datetime.strptime(x, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                except Exception:
                    try:
                        return datetime.fromisoformat(x)
                    except Exception:
                        return None
            if hasattr(x, 'tzinfo'):
                return x
            return None

        fs = to_dt(first_seen)
        ls = to_dt(last_seen)

        # simple features
        features = {
            "has_malware": 1 if a.get("malware") else 0,
            "confidence": a.get("confidence_level") or 0
        }

        doc = {
            "value": value,
            "ioc_type": ioc_type,
            "first_seen": fs,
            "last_seen": ls,
            "malware": a.get("malware"),
            "threat_type": a.get("threat_type"),
            "reporter": a.get("reporter"),
            "features": features,
            "updated_at": datetime.now(timezone.utc)
        }

        ops.append(UpdateOne({"value": value, "ioc_type": ioc_type}, {"$set": doc}, upsert=True))
        count += 1

# bulk write
if ops:
    res = processed.bulk_write(ops)
    print(f"Processed upserts: matched={res.matched_count}, upserted={len(res.upserted_ids)}")
else:
    print("No attributes found to process.")

print(f"Done. Processed {count} attributes.")
