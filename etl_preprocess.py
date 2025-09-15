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

# Categorical mappings
ioc_type_map = {"domain": 0, "ip": 1, "md5": 2, "sha1": 3, "sha256": 4, "sha512": 5, "url": 6, "unknown": 7}
threat_type_map = {}  # we will auto-fill as we see new threat types

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
        ioc_type_num = ioc_type_map.get(ioc_type.lower(), 7)
        
        threat_type = a.get("threat_type") or "unknown"
        if threat_type not in threat_type_map:
            threat_type_map[threat_type] = len(threat_type_map)  # assign numeric id
        threat_type_num = threat_type_map[threat_type]

        first_seen = to_dt(a.get("first_seen") or a.get("first_seen_utc"))
        last_seen = to_dt(a.get("last_seen") or a.get("last_seen_utc"))

        days_since_first_seen = (now - first_seen).days if first_seen else None

        features = {
            "has_malware": 1 if a.get("malware") else 0,
            "confidence": a.get("confidence_level") or 0,
            "ioc_type": ioc_type_num,
            "threat_type": threat_type_num,
            "days_since_first_seen": days_since_first_seen
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
