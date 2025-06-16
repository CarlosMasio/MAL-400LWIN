import requests
import json
import hashlib

# VirusTotal API Key (from context)
API_KEY = "7b4b8af1a55fbc543b04305552ad53165c33889de087fbce2e152dcf98dc0f9d"
VT_URL = "https://www.virustotal.com/api/v3/files/"

HEADERS = {
    "x-apikey": API_KEY
}


def get_file_hash(file_path):
    with open(file_path, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    return file_hash


def get_vt_report(file_path):
    file_hash = get_file_hash(file_path)
    url = VT_URL + file_hash

    response = requests.get(url, headers=HEADERS)

    if response.status_code == 200:
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        results = data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})

        malicious_engines = [
            engine for engine, result in results.items() if result["category"] == "malicious"
        ]

        return {
            "sha256": file_hash,
            "malicious_count": stats.get("malicious", 0),
            "suspicious_count": stats.get("suspicious", 0),
            "harmless_count": stats.get("harmless", 0),
            "undetected_count": stats.get("undetected", 0),
            "malicious_engines": malicious_engines
        }

    elif response.status_code == 404:
        return {"error": "File not found on VirusTotal. Try uploading it first."}
    elif response.status_code == 403:
        return {"error": "Invalid or quota-exceeded VirusTotal API key."}
    else:
        return {"error": f"VirusTotal Error: {response.status_code}"}
