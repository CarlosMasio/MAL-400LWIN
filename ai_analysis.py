# ai_analysis.py

import requests
import json

def analyze_with_ai(scan_result):
    query_prompt = f"""
You are an AI malware analyst. A file was scanned, and the following results were found:

{json.dumps(scan_result, indent=2)}

Please answer in this format:
1. Summary: <plain-English summary of the scan>
2. Risk: <Safe / Suspicious / Malicious>
3. Recommendation: <Should the user keep, delete, or investigate the file?>

Make sure your language is simple and easy to understand.
"""

    try:
        url = "https://xyris.vercel.app/api/llm-models/openai/gpt-4/"
        headers = {"Content-Type": "application/json"}

        response = requests.post(
            url,
            json={"query": query_prompt},
            headers=headers
        )
        response.raise_for_status()
        return response.json().get("content", "")
    except requests.RequestException as e:
        return f"[AI Error] Could not analyze: {e}"
