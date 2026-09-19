"""Tests for Threat Intelligence: EPSS, NVD/OSV Fallback, CISA KEV, and Zero Fake Data Policy"""
from unittest.mock import patch
import httpx
from app.services.threat_intel import get_epss_score, get_cve_details, is_cve_in_kev
from app.services.cache import set_cached_response


def test_epss_live_and_cache(db_session):
    cve = "CVE-2024-19281"
    # Seed active cache
    set_cached_response(db_session, f"epss:{cve}", 0.61)

    score, is_stale, unavailable = get_epss_score(db_session, cve)
    assert score == 0.61
    assert is_stale is False
    assert unavailable is False


def test_epss_zero_fake_data_policy_on_failure(db_session):
    """When both live API and cache fail, must return None and data_unavailable=True. Never fake numbers."""
    cve = "CVE-9999-99999"
    with patch("app.services.threat_intel._fetch_epss_live", side_effect=httpx.ConnectError("Network down")):
        score, is_stale, unavailable = get_epss_score(db_session, cve)
        assert score is None
        assert unavailable is True
        assert is_stale is False


def test_nvd_osv_fallback(db_session):
    cve = "CVE-2023-38606"
    # Simulate NVD failure, OSV success
    with patch("app.services.threat_intel._fetch_nvd_cve", side_effect=httpx.HTTPStatusError("NVD 503", request=None, response=None)):
        with patch("app.services.threat_intel._fetch_osv_cve", return_value={"cvss_score": 7.8, "severity": "High", "cwe_id": "CWE-20", "source": "OSV.dev"}):
            details, is_stale, unavailable = get_cve_details(db_session, cve)
            assert details is not None
            assert details["source"] == "OSV.dev"
            assert details["cvss_score"] == 7.8
            assert details["severity"] == "High"
            assert unavailable is False


def test_cisa_kev_lookup(db_session):
    # Seed KEV cache
    set_cached_response(db_session, "cisa_kev_catalog", ["CVE-2024-19281", "CVE-2019-0708"])

    assert is_cve_in_kev(db_session, "CVE-2024-19281") is True
    assert is_cve_in_kev(db_session, "CVE-2019-0708") is True
    assert is_cve_in_kev(db_session, "CVE-2020-0001") is False
    assert is_cve_in_kev(db_session, None) is False
