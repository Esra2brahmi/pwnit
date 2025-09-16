import argparse
from datetime import datetime, timezone
from pymongo import MongoClient, UpdateOne

client = MongoClient("mongodb://localhost:27017/")
db = client["misp"]

iocs = db["iocs"]
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
now = datetime.now(timezone.utc)

def to_dt(x):
    if not x:
        return None
    if isinstance(x, str):
        try:
            return datetime.strptime(x, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except Exception:
            try:
                return datetime.fromisoformat(x)
            except Exception:
                return None
    if hasattr(x, 'tzinfo'):
        return x
    return None

for ev in cursor:
    attrs = ev.get("Attribute", [])
    for a in attrs:
        ioc_type = a.get("type") or "unknown"
        threat_type = a.get("threat_type") or "unknown"


        first_seen = to_dt(a.get("first_seen") or a.get("first_seen_utc"))
        last_seen = to_dt(a.get("last_seen") or a.get("last_seen_utc"))

        # Ensure both are timezone-aware (UTC)
        def make_aware(dt):
            if dt is None:
                return None
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt


    first_seen_aware = make_aware(first_seen)
    last_seen_aware = make_aware(last_seen)
    now_aware = make_aware(now)
    days_since_first_seen = (now_aware - first_seen_aware).days if first_seen_aware else None
    days_since_last_seen = (now_aware - last_seen_aware).days if last_seen_aware else days_since_first_seen
    seen_duration_days = (last_seen_aware - first_seen_aware).days if first_seen_aware and last_seen_aware else None

    features = {
            "has_malware": 1 if a.get("malware") else 0,
            "confidence": a.get("confidence_level") or 0,
            "ioc_type": ioc_type.lower(),
            "threat_type": threat_type.lower(),
            "days_since_first_seen": days_since_first_seen,
            "days_since_last_seen": days_since_last_seen,
            "seen_duration_days": seen_duration_days
        }
    
    doc = {
            "value": a.get("value"),
            "ioc_type": ioc_type,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "malware": a.get("malware"),
            "threat_type": threat_type,
            "reporter": a.get("reporter"),
            "features": features,
            "updated_at": now
        }
    
    ops.append(UpdateOne({"value": a.get("value"), "ioc_type": ioc_type}, {"$set": doc}, upsert=True))
    count += 1

if ops:
    res = processed.bulk_write(ops)
    print(f"Processed upserts: matched={res.matched_count}, upserted={len(res.upserted_ids)}")
else:
    print("No attributes found to process.")

print(f"Done. Processed {count} attributes.")
