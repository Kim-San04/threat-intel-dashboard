import os
import requests

ABUSE_BASE = "https://api.abuseipdb.com/api/v2"


def _headers():
    return {
        "Key": os.environ["ABUSEIPDB_API_KEY"],
        "Accept": "application/json",
    }


def analyze_abuseipdb(ip: str) -> dict:
    try:
        resp = requests.get(
            f"{ABUSE_BASE}/check",
            headers=_headers(),
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=10,
        )
        resp.raise_for_status()
        d = resp.json().get("data", {})
        reports = d.get("reports", [])
        categories_flat = []
        for r in reports:
            categories_flat.extend(r.get("categories", []))
        category_counts: dict[int, int] = {}
        for c in categories_flat:
            category_counts[c] = category_counts.get(c, 0) + 1
        return {
            "source": "AbuseIPDB",
            "ip": ip,
            "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
            "is_whitelisted": d.get("isWhitelisted", False),
            "country_code": d.get("countryCode", ""),
            "usage_type": d.get("usageType", ""),
            "isp": d.get("isp", ""),
            "domain": d.get("domain", ""),
            "total_reports": d.get("totalReports", 0),
            "num_distinct_users": d.get("numDistinctUsers", 0),
            "last_reported_at": d.get("lastReportedAt", ""),
            "category_counts": category_counts,
            "recent_reports": reports[:5],
            "error": None,
        }
    except requests.exceptions.HTTPError as exc:
        return {"source": "AbuseIPDB", "ip": ip, "error": str(exc)}
    except Exception as exc:
        return {"source": "AbuseIPDB", "ip": ip, "error": str(exc)}
