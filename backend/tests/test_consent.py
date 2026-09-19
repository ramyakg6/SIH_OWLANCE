"""Tests for POST /consent endpoint"""
from app.db.models import ConsentLog


def test_consent_logging_explicit_ip(client, db_session):
    payload = {
        "domain": "example.com",
        "requester_ip": "198.51.100.42",
        "consent_version": "1.0",
        "active_scan_allowed": True,
    }
    response = client.post("/consent", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["domain"] == "example.com"
    assert data["requester_ip"] == "198.51.100.42"
    assert data["consent_version"] == "1.0"
    assert data["active_scan_allowed"] is True
    assert "id" in data
    assert "timestamp" in data

    # Verify database persistence
    record = db_session.query(ConsentLog).filter(ConsentLog.id == data["id"]).first()
    assert record is not None
    assert record.domain == "example.com"
    assert record.active_scan_allowed is True


def test_consent_logging_auto_ip(client, db_session):
    payload = {
        "domain": "portal.company.org",
        "consent_version": "1.1",
        "active_scan_allowed": False,
    }
    response = client.post("/consent", json=payload, headers={"X-Forwarded-For": "203.0.113.195"})
    assert response.status_code == 201
    data = response.json()
    assert data["domain"] == "portal.company.org"
    assert data["requester_ip"] == "203.0.113.195"
    assert data["active_scan_allowed"] is False


def test_consent_invalid_domain(client):
    payload = {
        "domain": "invalid_domain_no_dot",
        "consent_version": "1.0",
        "active_scan_allowed": False,
    }
    response = client.post("/consent", json=payload)
    assert response.status_code == 422
