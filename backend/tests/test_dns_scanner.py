"""Tests for DNS Enumeration and Email Hygiene Analysis"""
from app.services.dns_scanner import classify_asset, check_email_hygiene, enumerate_dns
from app.services.cache import set_cached_response


def test_classify_asset_types():
    domain = "company.com"

    # Primary Domain
    c1 = classify_asset("company.com", domain, {"A": ["93.184.216.34"]}, "Seed")
    assert c1["asset_type"] == "Primary Domain"
    assert c1["status"] == "monitored"
    assert 443 in c1["open_ports"]
    assert c1["discovery_confidence"] >= 0.95

    # Mail Server
    c2 = classify_asset("mail.company.com", domain, {"A": ["93.184.216.35"], "MX": ["mail.company.com"]}, "CT Logs")
    assert c2["asset_type"] == "Mail Server"
    assert 25 in c2["open_ports"]

    # Remote Access
    c3 = classify_asset("vpn.company.com", domain, {"A": ["93.184.216.36"]}, "CT Logs")
    assert c3["asset_type"] == "Remote Access"
    assert 3389 in c3["open_ports"]

    # Cloud Storage
    c4 = classify_asset("assets.company.com", domain, {"A": ["93.184.216.37"]}, "CT Logs")
    assert c4["asset_type"] == "Cloud Storage"

    # Shadow IT (no IP resolution)
    c5 = classify_asset("old-test.company.com", domain, {"A": [], "AAAA": []}, "CT Logs")
    assert c5["asset_type"] == "Shadow IT"
    assert c5["status"] == "unverified"
    assert c5["open_ports"] == []
    assert c5["discovery_confidence"] == 0.70


def test_email_hygiene_parsing(db_session):
    domain = "testdomain.com"
    # Seed cache with SPF and DMARC records
    set_cached_response(
        db_session,
        f"dns:{domain}",
        {"A": ["1.2.3.4"], "AAAA": [], "MX": ["mail.testdomain.com"], "TXT": ["v=spf1 include:_spf.google.com ~all"]},
    )
    set_cached_response(
        db_session,
        f"dns:_dmarc.{domain}",
        {"A": [], "AAAA": [], "MX": [], "TXT": ["v=DMARC1; p=reject; rua=mailto:dmarc@testdomain.com"]},
    )

    hygiene = check_email_hygiene(db_session, domain)
    assert hygiene["has_spf"] is True
    assert "v=spf1" in hygiene["spf_record"]
    assert hygiene["has_dmarc"] is True
    assert "v=DMARC1" in hygiene["dmarc_record"]
