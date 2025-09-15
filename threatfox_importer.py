"""
threatfox_importer.py

Read ThreatFox JSON files saved in VAMF/ (the recent export format) and
import attributes into MongoDB collections:
 - misp.iocs (one event per ThreatFox id)
 - misp.ioc_domains
 - misp.ioc_ips
 - misp.ioc_hashes

The script creates unique indexes on (value,type) for attribute collections
and upserts attribute documents to avoid duplicates.

Run:
  python3 threatfox_importer.py

"""
import os
import json
from datetime import datetime
from pymongo import MongoClient, UpdateOne, ASCENDING

VAMF_DIR = "/home/esra/misp_ioc/VAMF"

client = MongoClient("mongodb://localhost:27017/")
db = client["misp"]
collection_iocs = db["iocs"]
domains_coll = db["ioc_domains"]
ips_coll = db["ioc_ips"]
hashes_coll = db["ioc_hashes"]

# ensure indexes
for coll in (domains_coll, ips_coll, hashes_coll):
    try:
        coll.create_index([("value", ASCENDING), ("type", ASCENDING)], unique=True)
    except Exception as e:
        print(f"Index create warning for {coll.name}: {e}")

# helper: normalize type mapping
def map_type(ioc_type):
    it = (ioc_type or "").lower()
    if "domain" in it or it in ("hostname", "fqdn"):
        return "domain"
    if it.startswith("ip") or it.startswith("ipv") or it in ("ip:port", "ip"):
        return "ip"
    if it in ("url", "uri"):
        return "url"
    # hashes
    if it in ("md5", "sha1", "sha256", "sha512"):
        return it
    # fallback
    return it or "unknown"

def parse_ts(ts_str):
    if not ts_str:
        return None
    try:
        return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    except Exception:
        try:
            return datetime.fromisoformat(ts_str)
        except Exception:
            return None

files = [f for f in os.listdir(VAMF_DIR) if f.endswith('.json')]
if not files:
    print("No JSON files found in VAMF/ to import.")
    raise SystemExit(0)

for fname in files:
    path = os.path.join(VAMF_DIR, fname)
    print(f"Processing {path}...")
    with open(path, 'r', encoding='utf-8') as fh:
        data = json.load(fh)

    # ThreatFox recent format: mapping of 'id' -> [ { ioc_value, ioc_type, ...}, ... ]
    domain_ops = []
    ip_ops = []
    hash_ops = []
    events_written = 0

    for tf_id, entries in data.items():
        # Build an Event-like doc to store in misp.iocs
        event = {
            "threatfox_id": tf_id,
            "source": "threatfox",
            "info": f"ThreatFox import {tf_id}",
            "timestamp": datetime.utcnow(),
            "Attribute": []
        }

        for rec in entries:
            value = rec.get("ioc_value") or rec.get("ioc") or rec.get("value")
            ioc_type = map_type(rec.get("ioc_type"))
            first_seen = parse_ts(rec.get("first_seen_utc") or rec.get("first_seen"))
            last_seen = parse_ts(rec.get("last_seen_utc") or rec.get("last_seen"))

            attr = {
                "type": ioc_type,
                "value": value,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "confidence_level": rec.get("confidence_level"),
                "malware": rec.get("malware"),
                "threat_type": rec.get("threat_type"),
                "reporter": rec.get("reporter"),
                "source": "threatfox",
                "threatfox_id": tf_id
            }

            event["Attribute"].append(attr)

            # Upsert into attribute collections based on normalized type
            if ioc_type == "domain":
                doc = {k: v for k, v in attr.items() if v is not None}
                domain_ops.append(UpdateOne({"value": value, "type": ioc_type}, {"$set": doc}, upsert=True))
            elif ioc_type == "ip":
                doc = {k: v for k, v in attr.items() if v is not None}
                ip_ops.append(UpdateOne({"value": value, "type": ioc_type}, {"$set": doc}, upsert=True))
            elif ioc_type in ("md5", "sha1", "sha256", "sha512"):
                doc = {k: v for k, v in attr.items() if v is not None}
                hash_ops.append(UpdateOne({"value": value, "type": ioc_type}, {"$set": doc}, upsert=True))
            else:
                # For other types (url, unknown), insert into iocs only
                pass

        # Upsert event into iocs collection (use threatfox_id as unique key)
        try:
            collection_iocs.update_one({"threatfox_id": tf_id}, {"$set": event}, upsert=True)
            events_written += 1
        except Exception as e:
            print(f"Failed to upsert event {tf_id}: {e}")

    # Bulk write attribute ops
    if domain_ops:
        try:
            res = domains_coll.bulk_write(domain_ops)
            print(f"Domains bulk_write: matched={res.matched_count}, upserted={len(res.upserted_ids)}")
        except Exception as e:
            print(f"Domain bulk write error: {e}")
    if ip_ops:
        try:
            res = ips_coll.bulk_write(ip_ops)
            print(f"IPs bulk_write: matched={res.matched_count}, upserted={len(res.upserted_ids)}")
        except Exception as e:
            print(f"IP bulk write error: {e}")
    if hash_ops:
        try:
            res = hashes_coll.bulk_write(hash_ops)
            print(f"Hashes bulk_write: matched={res.matched_count}, upserted={len(res.upserted_ids)}")
        except Exception as e:
            print(f"Hash bulk write error: {e}")

    print(f"Finished importing {fname}: events={events_written}")

print("All ThreatFox files processed.")
