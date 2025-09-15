# fetch_and_import.py

import requests
import os
import datetime

def fetch_recent_json(save_dir="VAMF"):
    """
    Fetch recent ThreatFox JSON dump (last 48h) and save it locally.
    """
    url = "https://threatfox.abuse.ch/export/json/recent/"
    
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise exception for HTTP errors
    except requests.RequestException as e:
        print(f"[!] Failed to fetch ThreatFox data: {e}")
        return None

    # Make sure the save directory exists
    os.makedirs(save_dir, exist_ok=True)

    # Save with timestamp in filename
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    file_path = os.path.join(save_dir, f"threatfox_recent_{timestamp}.json")

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(response.text)

    print(f"[+] Saved ThreatFox dump to {file_path}")
    return file_path

if __name__ == "__main__":
    fetch_recent_json()
