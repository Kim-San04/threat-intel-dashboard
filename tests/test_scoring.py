"""Tests for risk scoring logic — no API calls needed."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from unittest.mock import patch
from app import compute_risk_score, risk_label


def _vt(malicious=0, total=90, reputation=0):
    return {"error": None, "malicious": malicious, "total_engines": total, "reputation": reputation}

def _ab(confidence=0):
    return {"error": None, "abuse_confidence_score": confidence}

def _sh(vulns=None, ports=None):
    return {"error": None, "vulns": vulns or [], "ports": ports or []}


class TestRiskLabel:
    def test_low(self):      assert risk_label(10)  == "low"
    def test_medium(self):   assert risk_label(25)  == "medium"
    def test_high(self):     assert risk_label(50)  == "high"
    def test_critical(self): assert risk_label(75)  == "critical"
    def test_boundary(self): assert risk_label(74)  == "high"


class TestComputeRiskScore:
    def test_all_clean(self):
        score = compute_risk_score(_vt(), _ab(), _sh())
        assert score == 0

    def test_vt_all_malicious(self):
        score = compute_risk_score(_vt(malicious=90, total=90), _ab(), _sh())
        assert score == 40

    def test_vt_bad_reputation(self):
        score = compute_risk_score(_vt(malicious=0, reputation=-20), _ab(), _sh())
        assert score == 5

    def test_abuse_full_confidence(self):
        score = compute_risk_score(_vt(), _ab(confidence=100), _sh())
        assert score == 35

    @patch("app.cvss_weighted_score", return_value=10)
    def test_shodan_vulns(self, _mock):
        score = compute_risk_score(_vt(), _ab(), _sh(vulns=["CVE-2021-44228", "CVE-2022-1234"]))
        assert score == 10

    @patch("app.cvss_weighted_score", return_value=20)
    def test_max_capped_at_100(self, _mock):
        score = compute_risk_score(
            _vt(malicious=90, total=90, reputation=-50),
            _ab(confidence=100),
            _sh(vulns=["CVE-" + str(i) for i in range(20)], ports=list(range(50))),
        )
        assert score == 100

    def test_vt_error_ignored(self):
        vt_err = {"error": "API fail", "malicious": 0, "total_engines": 0}
        score = compute_risk_score(vt_err, _ab(confidence=60), _sh())
        assert score == 21  # 60 * 0.35

    def test_shodan_error_ignored(self):
        sh_err = {"error": "403", "vulns": [], "ports": []}
        score = compute_risk_score(_vt(), _ab(), sh_err)
        assert score == 0
