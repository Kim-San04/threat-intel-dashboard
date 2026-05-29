import requests

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cvss_scores(cve_ids: list[str]) -> dict[str, float]:
    """Return {cve_id: cvss_score} for a list of CVE IDs using the NVD API (no key needed)."""
    scores: dict[str, float] = {}
    for cve_id in cve_ids[:10]:  # cap to avoid rate-limiting
        try:
            resp = requests.get(
                NVD_BASE,
                params={"cveId": cve_id},
                timeout=8,
            )
            if not resp.ok:
                continue
            vulns = resp.json().get("vulnerabilities", [])
            if not vulns:
                continue
            metrics = vulns[0]["cve"].get("metrics", {})
            # Prefer CVSSv3.1 > v3.0 > v2
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics:
                    entry = metrics[key][0]
                    base = entry.get("cvssData", {}).get("baseScore") or entry.get("baseScore")
                    if base is not None:
                        scores[cve_id] = float(base)
                        break
        except Exception:
            continue
    return scores


def cvss_weighted_score(cve_ids: list[str]) -> int:
    """Compute a 0-20 contribution from CVE CVSS scores for the risk model."""
    if not cve_ids:
        return 0
    scores = fetch_cvss_scores(cve_ids)
    if not scores:
        # Fallback: 5 pts per CVE, capped
        return min(len(cve_ids) * 5, 20)
    # Weight: critical (≥9) = 10pts, high (≥7) = 6pts, medium (≥4) = 3pts, low = 1pt
    total = 0
    for s in scores.values():
        if s >= 9.0:
            total += 10
        elif s >= 7.0:
            total += 6
        elif s >= 4.0:
            total += 3
        else:
            total += 1
    return min(total, 20)
