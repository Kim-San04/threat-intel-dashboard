import os
import json
import datetime
from pathlib import Path

from flask import Flask, render_template, request, jsonify, session, send_file
from dotenv import load_dotenv

load_dotenv()

import re
import requests as _requests
from modules import analyze_virustotal, analyze_abuseipdb, analyze_shodan

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")

REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

def compute_risk_score(vt: dict, abuse: dict, shodan: dict) -> int:
    """Return a 0-100 composite risk score."""
    score = 0

    # VirusTotal contribution (max 45)
    if not vt.get("error"):
        malicious = vt.get("malicious", 0)
        total = vt.get("total_engines", 1) or 1
        ratio = malicious / total
        score += int(ratio * 40)
        if vt.get("reputation", 0) < -10:
            score += 5

    # AbuseIPDB contribution (max 35)
    if not abuse.get("error"):
        confidence = abuse.get("abuse_confidence_score", 0)
        score += int(confidence * 0.35)

    # Shodan contribution (max 20)
    if not shodan.get("error"):
        vuln_count = len(shodan.get("vulns", []))
        port_count = len(shodan.get("ports", []))
        score += min(vuln_count * 5, 15)
        score += min(port_count // 5, 5)

    return min(score, 100)


def geolocate_ip(ip: str) -> dict:
    """Free fallback geolocation via ip-api.com (no key required)."""
    try:
        resp = _requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "lat,lon,country,countryCode,city,org,isp"},
            timeout=5,
        )
        if resp.ok and resp.json().get("lat"):
            return resp.json()
    except Exception:
        pass
    return {}


def risk_label(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    history = session.get("history", [])
    return render_template("dashboard.html", history=history)


@app.route("/analyze", methods=["POST"])
def analyze():
    body = request.get_json(force=True)
    ioc = (body.get("ioc") or "").strip()
    if not ioc:
        return jsonify({"error": "IOC is required"}), 400

    vt_result = analyze_virustotal(ioc)
    shodan_result = {}
    abuse_result = {}
    geo_result = {}

    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc))

    if is_ip:
        abuse_result = analyze_abuseipdb(ioc)
        shodan_result = analyze_shodan(ioc)
        # Use Shodan geo if available, otherwise fallback to ip-api.com
        if shodan_result.get("latitude") is not None:
            geo_result = {
                "lat": shodan_result["latitude"],
                "lon": shodan_result["longitude"],
                "country": shodan_result.get("country_name", ""),
                "city": shodan_result.get("city", ""),
                "org": shodan_result.get("org", ""),
            }
        else:
            geo_result = geolocate_ip(ioc)

    score = compute_risk_score(vt_result, abuse_result, shodan_result)
    label = risk_label(score)

    payload = {
        "ioc": ioc,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "risk_score": score,
        "risk_label": label,
        "virustotal": vt_result,
        "abuseipdb": abuse_result,
        "shodan": shodan_result,
        "geo": geo_result,
    }

    # Persist in session history (keep last 20)
    history = session.get("history", [])
    history.insert(0, {
        "ioc": ioc,
        "timestamp": payload["timestamp"],
        "risk_score": score,
        "risk_label": label,
    })
    session["history"] = history[:20]

    return jsonify(payload)


@app.route("/export-pdf", methods=["POST"])
def export_pdf():
    try:
        from weasyprint import HTML
    except ImportError:
        return jsonify({"error": "weasyprint not installed"}), 500

    body = request.get_json(force=True)
    data = body.get("data", {})
    ioc = data.get("ioc", "unknown")

    html_content = render_template("pdf_report.html", data=data)
    safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in ioc)
    ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{safe_name}_{ts}.pdf"
    path = REPORTS_DIR / filename

    HTML(string=html_content).write_pdf(str(path))
    return send_file(str(path), as_attachment=True, download_name=filename)


@app.route("/tiles/<int:z>/<int:x>/<int:y>.png")
def tile_proxy(z, x, y):
    """Proxy OSM tiles through Flask so the browser doesn't need external access."""
    url = f"https://tile.openstreetmap.org/{z}/{x}/{y}.png"
    try:
        resp = _requests.get(
            url,
            headers={"User-Agent": "CTI-Dashboard/1.0 (educational project)"},
            timeout=10,
        )
        return resp.content, 200, {
            "Content-Type": "image/png",
            "Cache-Control": "public, max-age=86400",
        }
    except Exception:
        return b"", 502


@app.route("/history/clear", methods=["POST"])
def clear_history():
    session.pop("history", None)
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_ENV") == "development", host="0.0.0.0", port=5000)
