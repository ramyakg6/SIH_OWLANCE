"""Integration Tests for GET /scan/{domain}"""
from unittest.mock import patch
from app.db.models import Asset, Finding


def test_passive_scan_endpoint_integration(client, db_session):
    domain = "acmecorp.com"

    # Mock crt.sh and DNS enumeration to avoid flaky external internet calls in unit tests
    mock_subdomains = ["portal.acmecorp.com", "mail.acmecorp.com"]
    mock_assets = [
        {
            "asset_name": "acmecorp.com",
            "domain": domain,
            "asset_type": "Primary Domain",
            "discovery_method": "Seed",
            "status": "monitored",
            "open_ports": [80, 443],
            "discovery_confidence": 0.98,
            "tech_stack": {"ip_addresses": ["93.184.216.34"]},
        },
        {
            "asset_name": "portal.acmecorp.com",
            "domain": domain,
            "asset_type": "Web Application",
            "discovery_method": "CT Logs",
            "status": "monitored",
            "open_ports": [80, 443],
            "discovery_confidence": 0.90,
            "tech_stack": {"ip_addresses": ["93.184.216.35"]},
        },
        {
            "asset_name": "mail.acmecorp.com",
            "domain": domain,
            "asset_type": "Mail Server",
            "discovery_method": "CT Logs",
            "status": "monitored",
            "open_ports": [25, 587],
            "discovery_confidence": 0.95,
            "tech_stack": {"ip_addresses": ["93.184.216.36"]},
        },
    ]
    mock_hygiene = {
        "has_spf": False,  # Will generate a missing SPF finding
        "spf_record": None,
        "has_dmarc": False,
        "dmarc_record": None,
        "has_dkim": False,
    }

    with patch("app.routers.scan.search_crt_sh", return_value=(mock_subdomains, False, False)):
        with patch("app.routers.scan.enumerate_dns", return_value=(mock_assets, mock_hygiene)):
            response = client.get(f"/scan/{domain}")
            assert response.status_code == 200
            data = response.json()

            assert data["domain"] == domain
            assert "scan_id" in data
            assert 300 <= data["org_score"] <= 900
            assert data["assets_count"] == 3
            assert data["findings_count"] >= 1

            # Verify assets returned and shape
            for a in data["assets"]:
                assert a["domain"] == domain
                assert "asset_name" in a
                assert "asset_type" in a
                assert "open_ports" in a
                assert "discovery_confidence" in a

            # Verify findings returned and shape
            for f in data["findings"]:
                assert "issue" in f
                assert "severity" in f
                assert "final_risk_score" in f
                assert f["exposure_multiplier"] == 1.0  # Confirmed 1.0 for P0

            # Verify database persistence
            db_assets = db_session.query(Asset).filter(Asset.scan_id == data["scan_id"]).all()
            assert len(db_assets) == 3

            db_findings = db_session.query(Finding).filter(Finding.scan_id == data["scan_id"]).all()
            assert len(db_findings) >= 1
