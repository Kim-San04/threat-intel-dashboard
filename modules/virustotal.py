import os
import re
import requests

VT_BASE = "https://www.virustotal.com/api/v3"


def _headers():
    return {"x-apikey": os.environ["VIRUSTOTAL_API_KEY"]}


def _detect_type(ioc: str) -> str:
    ip_re = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    hash_re = re.compile(r"^[a-fA-F0-9]{32,64}$")
    url_re = re.compile(r"^https?://")
    if ip_re.match(ioc):
        return "ip"
    if hash_re.match(ioc):
        return "file"
    if url_re.match(ioc):
        return "url"
    return "domain"


def analyze_virustotal(ioc: str) -> dict:
    ioc_type = _detect_type(ioc)
    endpoints = {
        "ip": f"{VT_BASE}/ip_addresses/{ioc}",
        "domain": f"{VT_BASE}/domains/{ioc}",
        "file": f"{VT_BASE}/files/{ioc}",
        "url": f"{VT_BASE}/urls/{_url_id(ioc)}",
    }
    url = endpoints[ioc_type]
    try:
        resp = requests.get(url, headers=_headers(), timeout=10)
        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        return {
            "source": "VirusTotal",
            "ioc": ioc,
            "ioc_type": ioc_type,
            "malicious": malicious,
            "total_engines": total,
            "reputation": data.get("reputation", 0),
            "country": data.get("country", ""),
            "as_owner": data.get("as_owner", ""),
            "categories": data.get("categories", {}),
            "last_analysis_stats": stats,
            "error": None,
        }
    except requests.exceptions.HTTPError as exc:
        return {"source": "VirusTotal", "ioc": ioc, "error": str(exc)}
    except Exception as exc:
        return {"source": "VirusTotal", "ioc": ioc, "error": str(exc)}


def _url_id(url: str) -> str:
    import base64
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
