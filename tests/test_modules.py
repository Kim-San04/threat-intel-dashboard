"""Tests for API modules with mocked HTTP calls."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from unittest.mock import patch, MagicMock
import pytest

os.environ.setdefault("VIRUSTOTAL_API_KEY", "test-key")
os.environ.setdefault("ABUSEIPDB_API_KEY",  "test-key")
os.environ.setdefault("SHODAN_API_KEY",      "test-key")


# ------------------------------------------------------------------ #
#  VirusTotal
# ------------------------------------------------------------------ #
from modules.virustotal import analyze_virustotal, _detect_type

class TestDetectType:
    def test_ip(self):     assert _detect_type("1.2.3.4")            == "ip"
    def test_domain(self): assert _detect_type("evil.com")           == "domain"
    def test_url(self):    assert _detect_type("https://evil.com")   == "url"
    def test_md5(self):    assert _detect_type("a" * 32)             == "file"
    def test_sha256(self): assert _detect_type("b" * 64)             == "file"


class TestAnalyzeVT:
    def _mock_resp(self, stats, reputation=0, country="DE"):
        resp = MagicMock()
        resp.ok = True
        resp.json.return_value = {"data": {"attributes": {
            "last_analysis_stats": stats,
            "reputation": reputation,
            "country": country,
            "as_owner": "TestAS",
            "categories": {},
        }}}
        resp.raise_for_status = MagicMock()
        return resp

    @patch("modules.virustotal.requests.get")
    def test_ip_malicious(self, mock_get):
        stats = {"malicious": 10, "harmless": 80, "suspicious": 0, "undetected": 0, "timeout": 0}
        mock_get.return_value = self._mock_resp(stats)
        result = analyze_virustotal("1.2.3.4")
        assert result["malicious"] == 10
        assert result["total_engines"] == 90
        assert result["error"] is None

    @patch("modules.virustotal.requests.get")
    def test_api_error_returns_error_key(self, mock_get):
        mock_get.side_effect = Exception("timeout")
        result = analyze_virustotal("1.2.3.4")
        assert result["error"] is not None


# ------------------------------------------------------------------ #
#  AbuseIPDB
# ------------------------------------------------------------------ #
from modules.abuseipdb import analyze_abuseipdb

class TestAbuseIPDB:
    def _mock_resp(self, score=75, reports=10):
        resp = MagicMock()
        resp.ok = True
        resp.json.return_value = {"data": {
            "abuseConfidenceScore": score,
            "totalReports": reports,
            "numDistinctUsers": 3,
            "countryCode": "RU",
            "isp": "Test ISP",
            "domain": "test.com",
            "usageType": "Datacenter",
            "isWhitelisted": False,
            "lastReportedAt": "2026-01-01T00:00:00+00:00",
            "reports": [],
        }}
        resp.raise_for_status = MagicMock()
        return resp

    @patch("modules.abuseipdb.requests.get")
    def test_confidence_score(self, mock_get):
        mock_get.return_value = self._mock_resp(score=90)
        result = analyze_abuseipdb("1.2.3.4")
        assert result["abuse_confidence_score"] == 90
        assert result["error"] is None

    @patch("modules.abuseipdb.requests.get")
    def test_http_error(self, mock_get):
        mock_get.side_effect = Exception("connection refused")
        result = analyze_abuseipdb("1.2.3.4")
        assert result["error"] is not None


# ------------------------------------------------------------------ #
#  Flask routes (integration-light)
# ------------------------------------------------------------------ #
from app import app as flask_app

@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    flask_app.config["CACHE_TYPE"] = "NullCache"
    with flask_app.test_client() as c:
        yield c

class TestRoutes:
    def test_index_returns_200(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"CTI" in resp.data

    @patch("app.analyze_virustotal", return_value={
        "source": "VirusTotal", "ioc": "1.2.3.4", "ioc_type": "ip",
        "malicious": 5, "total_engines": 90, "reputation": -5,
        "country": "DE", "as_owner": "Test", "categories": {},
        "last_analysis_stats": {"malicious": 5, "harmless": 85}, "error": None,
    })
    @patch("app.analyze_abuseipdb", return_value={"error": None, "abuse_confidence_score": 50, "ip": "1.2.3.4",
        "is_whitelisted": False, "country_code": "DE", "usage_type": "", "isp": "", "domain": "",
        "total_reports": 3, "num_distinct_users": 1, "last_reported_at": "", "category_counts": {}, "recent_reports": []})
    @patch("app.analyze_shodan",   return_value={"error": "403", "ip": "1.2.3.4"})
    @patch("app.geolocate_ip",     return_value={"lat": 52.0, "lon": 13.0, "country": "Germany", "city": "Berlin"})
    def test_analyze_ip(self, mock_geo, mock_sh, mock_ab, mock_vt, client):
        resp = client.post("/analyze", json={"ioc": "1.2.3.4"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ioc"] == "1.2.3.4"
        assert "risk_score" in data
        assert 0 <= data["risk_score"] <= 100

    def test_analyze_empty_ioc(self, client):
        resp = client.post("/analyze", json={"ioc": ""})
        assert resp.status_code == 400

    def test_history_clear(self, client):
        resp = client.post("/history/clear")
        assert resp.status_code == 200
