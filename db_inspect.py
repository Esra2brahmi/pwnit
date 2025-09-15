"""
Inspect MongoDB 'misp' database: list collections, counts, sample docs,
and create unique indexes for attribute collections (value + type).
Run: python db_inspect.py
"""
from pymongo import MongoClient, ASCENDING

client = MongoClient("mongodb://localhost:27017/")
db = client["misp"]

collections = db.list_collection_names()
print("Collections in misp:", collections)

targets = ["iocs", "ioc_domains", "ioc_ips", "ioc_hashes"]

for name in targets:
    if name in collections:
        coll = db[name]
        count = coll.count_documents({})
        print(f"\nCollection '{name}' count: {count}")
        sample = coll.find_one()
        print("Sample document:")
        print(sample)
        # create recommended unique index for attribute collections
        if name != "iocs":
            try:
                idx_name = coll.create_index([("value", ASCENDING), ("type", ASCENDING)], unique=True)
                print(f"Created/ensured index on {name}: {idx_name}")
            except Exception as e:
                print(f"Could not create index on {name}: {e}")
    else:
        print(f"\nCollection '{name}' not found in database.")

print('\nDone.')
