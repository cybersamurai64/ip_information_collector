import requests
import os
from datetime import datetime

def get_vt_score(ip):
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return {"error": "Missing VT_API_KEY from .env file!"}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            json_data = response.json()
            attr = json_data.get('data', {}).get('attributes', {})

            def format_date(ts):
                if not ts: return "N/A"
                return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

            stats = attr.get('last_analysis_stats', {})
            malicious_count = stats.get('malicious', 0)
            total_engines = sum(stats.values())

            votes = attr.get('total_votes', {})
            mal_votes = votes.get('malicious', 0)
            harmless_votes = votes.get('harmless', 0)

            tags = attr.get('tags', [])

            results = attr.get('last_analysis_results', {})
            category_summary = {}
            specific_results = {}

            for engine, data in results.items():
                cat = data.get('category', 'unknown')
                res = data.get('result')

                category_summary[cat] = category_summary.get(cat, 0) + 1

                if cat in ['malicious', 'suspicious'] and res:
                    specific_results[res] = specific_results.get(res, 0) + 1

            extraction = {
                "blacklist_count": f"[bold red]{malicious_count}[/bold red] / {total_engines} engines",
                "detected_threats": ", ".join([f"{k} ({v})" for k, v in specific_results.items()]) if specific_results else "None",
                "reputation_points": attr.get('reputation', 0),
                "community_votes": f"Malicious: {mal_votes} | Harmless: {harmless_votes}",
                "asn": attr.get('asn', 'N/A'),
                "as_owner": attr.get('as_owner', 'N/A'),
                "malicious": category_summary.get('malicious', 0),
                "suspicious": category_summary.get('suspicious', 0),
                "harmless": category_summary.get('harmless', 0),
                "undetected": category_summary.get('undetected', 0),
                "first_whois_seen": format_date(attr.get('whois_date')),
                "last_analysis": format_date(attr.get('last_analysis_date')),
                "last_modified": format_date(attr.get('last_modification_date')),
                "tags": ", ".join(tags) if tags else "None detected",
                "score": malicious_count
            }

            return extraction

        else:
            return {"error": f"VirusTotal error: {response.status_code}"}

    except Exception as e:
        return {"error": f"Connection error: {str(e)}"}