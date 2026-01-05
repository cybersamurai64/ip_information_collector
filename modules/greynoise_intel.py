import requests
import os

def get_greynoise_v3_details(ip):
    """
    Részletes IP lekérdezés a GreyNoise v3 API segítségével.
    Visszaadja a besorolást, az azonosított támadót, tag-eket és VPN/Tor adatokat.
    """
    api_key = os.getenv("GREYNOISE_API_KEY")
    if not api_key:
        return {"error": "Missing GREYNOISE_API_KEY from .env file!"}

    url = f"https://api.greynoise.io/v3/ip/{ip}"
    headers = {
        "accept": "application/json",
        "key": api_key
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            extraction = {}

            # 1. Business Service Intelligence (Üzleti adatok)
            biz = data.get('business_service_intelligence', {})
            if biz.get('found'):
                extraction["business_name"] = biz.get('name', 'N/A')
                extraction["business_category"] = biz.get('category', 'N/A')
                extraction["trust_level"] = biz.get('trust_level', 'N/A')
                extraction["description"] = biz.get('description', 'N/A')

            # 2. Internet Scanner Intelligence (Scanner/Támadó adatok)
            scan = data.get('internet_scanner_intelligence', {})
            extraction["seen_as_scanner"] = "YES" if scan.get('found') else "NO"

            if scan.get('found'):
                extraction["classification"] = scan.get('classification', 'unknown')
                extraction["actor"] = scan.get('actor', 'Unknown Actor')
                extraction["vpn"] = scan.get('vpn')
                extraction["tor"] = scan.get('tor')
                extraction["bot"] = scan.get('bot')
                extraction["spoofable"] = scan.get('spoofable')

                # Tag-ek kinyerése (pl. Mirai, Shodan)
                tags = scan.get('tags', [])
                extraction["tags"] = ", ".join([t.get('name') for t in tags]) if tags else "None"

                # CVE-k kinyerése
                cves = scan.get('cves', [])
                extraction["known_cves"] = ", ".join(cves) if cves else "None"

            return extraction

        elif response.status_code == 401:
            return {"error": "Invalid GreyNoise API key"}
        elif response.status_code == 404:
            return {"seen": "NO", "message": "IP not observed by GreyNoise"}
        elif response.status_code == 429:
            return {"error": "GreyNoise rate limit reached"}
        else:
            return {"error": f"GreyNoise error: {response.status_code}"}

    except Exception as e:
        return {"error": f"Connection error: {str(e)}"}