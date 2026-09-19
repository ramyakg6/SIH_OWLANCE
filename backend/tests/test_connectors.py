"""Tests for connector ingest.

Covers the six internal data sources: that each parser reads its vendor's
export shape, that a malformed upload fails with a message naming the missing
column rather than silently producing nothing, and that connector data
actually moves the organisation score.
"""
import io
import json

import pytest

from app.services.connectors import (
    SOURCE_IDS,
    get_template,
    parse_connector,
)


def _template_bytes(source_id):
    filename, content = get_template(source_id)
    return filename, content.encode("utf-8")


# --------------------------------------------------------------------------
# Every source parses its own sample export
# --------------------------------------------------------------------------

@pytest.mark.parametrize("source_id", SOURCE_IDS)
def test_each_source_parses_its_sample_export(source_id):
    filename, raw = _template_bytes(source_id)
    result = parse_connector(source_id, raw, filename, modelled_eal_lakhs=62)
    assert result["records"] > 0
    assert result["summary"]
    assert result["source"] == source_id


def test_unknown_source_is_rejected():
    with pytest.raises(ValueError, match="Unknown data source"):
        parse_connector("teleport", b"a,b\n1,2\n", "x.csv")


def test_empty_upload_is_rejected():
    with pytest.raises(ValueError, match="empty"):
        parse_connector("identity", b"", "x.csv")


# --------------------------------------------------------------------------
# Identity: MFA exposure
# --------------------------------------------------------------------------

def test_identity_flags_admin_without_mfa():
    csv = (
        b"Email Address,MFA Enrolled,Role\n"
        b"a@x.com,FALSE,Super Admin\n"
        b"b@x.com,TRUE,User\n"
    )
    result = parse_connector("identity", csv, "users.csv")
    assert result["metrics"]["admins_without_mfa"] == 1
    assert any(f["severity"] == "Critical" for f in result["findings"])


def test_identity_reports_full_mfa_coverage_cleanly():
    csv = b"Email Address,MFA Enrolled,Role\na@x.com,TRUE,User\nb@x.com,TRUE,User\n"
    result = parse_connector("identity", csv, "users.csv")
    assert result["metrics"]["mfa_coverage_pct"] == 100
    assert result["findings"] == []


def test_identity_without_mfa_column_says_which_column_is_missing():
    csv = b"Email Address,Department\na@x.com,Sales\n"
    with pytest.raises(ValueError, match="MFA"):
        parse_connector("identity", csv, "users.csv")


def test_identity_accepts_alternative_vendor_headers():
    """Workspace says '2sv_enrolled', M365 says 'StrongAuthenticationMethods'."""
    csv = b"userPrincipalName,2sv_enrolled\na@x.com,false\n"
    result = parse_connector("identity", csv, "users.csv")
    assert result["metrics"]["accounts"] == 1
    assert result["metrics"]["mfa_coverage_pct"] == 0


# --------------------------------------------------------------------------
# Cloud: IAM credential report
# --------------------------------------------------------------------------

def test_cloud_escalates_root_account_without_mfa():
    csv = (
        b"user,password_enabled,mfa_active,access_key_1_last_rotated\n"
        b"<root_account>,true,false,N/A\n"
    )
    result = parse_connector("cloud", csv, "credential-report.csv")
    assert any("Root" in f["issue"] and f["severity"] == "Critical" for f in result["findings"])


def test_cloud_counts_long_lived_access_keys():
    csv = (
        b"user,mfa_active,access_key_1_last_rotated\n"
        b"svc-a,true,2023-01-01T00:00:00+00:00\n"
        b"svc-b,true,N/A\n"
    )
    result = parse_connector("cloud", csv, "credential-report.csv")
    assert result["metrics"]["long_lived_keys"] == 1


# --------------------------------------------------------------------------
# Endpoint: fleet compliance
# --------------------------------------------------------------------------

def test_endpoint_severity_scales_with_non_compliance_rate():
    heavy = b"Hostname,Compliant\n" + b"".join(
        f"h{i},{'false' if i < 4 else 'true'}\n".encode() for i in range(10)
    )
    result = parse_connector("endpoint", heavy, "devices.csv")
    assert result["metrics"]["non_compliant"] == 4
    assert result["findings"][0]["severity"] == "Critical"

    light = b"Hostname,Compliant\n" + b"".join(
        f"h{i},{'false' if i < 1 else 'true'}\n".encode() for i in range(10)
    )
    result = parse_connector("endpoint", light, "devices.csv")
    assert result["findings"][0]["severity"] == "High"


def test_fully_compliant_fleet_produces_no_finding():
    csv = b"Hostname,Compliant\nh1,true\nh2,true\n"
    result = parse_connector("endpoint", csv, "devices.csv")
    assert result["findings"] == []
    assert result["metrics"]["compliant_pct"] == 100


# --------------------------------------------------------------------------
# SIEM: observed attacks raise likelihood
# --------------------------------------------------------------------------

def test_siem_observed_attack_gets_maximum_likelihood():
    """An attack being actively attempted is not a theoretical risk."""
    csv = b"Rule,Severity,Count\nBrute force against VPN,High,412\n"
    result = parse_connector("siem", csv, "alerts.csv")
    assert result["metrics"]["events"] == 412
    assert result["findings"][0]["likelihood"] == 5


def test_siem_accepts_json_export():
    payload = json.dumps({"results": [
        {"rule": "Suspicious sign-in", "severity": "critical", "count": 9},
    ]}).encode()
    result = parse_connector("siem", payload, "alerts.json")
    assert result["metrics"]["events"] == 9
    assert result["metrics"]["high_severity"] == 9


# --------------------------------------------------------------------------
# CMDB: business criticality overrides inference
# --------------------------------------------------------------------------

def test_cmdb_maps_criticality_vocabularies_to_weights():
    csv = (
        b"ci_name,business_criticality\n"
        b"portal.company.com,Critical\n"
        b"blog.company.com,Low\n"
        b"mail.company.com,Tier 2\n"
    )
    result = parse_connector("cmdb", csv, "cmdb.csv")
    overrides = result["criticality_overrides"]
    assert overrides["portal.company.com"] == 1.5
    assert overrides["blog.company.com"] == 0.8
    assert overrides["mail.company.com"] == 1.3
    assert result["metrics"]["crown_jewels"] == 1


def test_cmdb_rejects_unrecognised_criticality_values():
    csv = b"ci_name,business_criticality\nhost-a,banana\n"
    with pytest.raises(ValueError, match="no recognised values"):
        parse_connector("cmdb", csv, "cmdb.csv")


# --------------------------------------------------------------------------
# Insurance: coverage gap
# --------------------------------------------------------------------------

def test_insurance_finds_gap_when_cover_is_below_modelled_loss():
    csv = b"Section,Limit\nAggregate,Rs 50,00,000\n"
    result = parse_connector("insurance", csv, "policy.csv", modelled_eal_lakhs=62)
    assert result["metrics"]["limit_lakhs"] == pytest.approx(50.0, abs=0.1)
    assert result["metrics"]["gap_lakhs"] > 0
    assert result["findings"][0]["short"] == "Cover Gap"


def test_insurance_reports_no_gap_when_cover_is_sufficient():
    csv = b"Section,Limit\nAggregate,Rs 2 crore\n"
    result = parse_connector("insurance", csv, "policy.csv", modelled_eal_lakhs=62)
    assert result["metrics"]["gap_lakhs"] == 0
    assert result["findings"] == []


def test_insurance_without_amounts_is_rejected():
    with pytest.raises(ValueError, match="No coverage amounts"):
        parse_connector("insurance", b"Section,Limit\nAggregate,see schedule\n", "policy.csv")


# --------------------------------------------------------------------------
# Endpoint contract
# --------------------------------------------------------------------------

@pytest.mark.parametrize("source_id", SOURCE_IDS)
def test_upload_endpoint_accepts_each_sample(client, source_id):
    filename, raw = _template_bytes(source_id)
    resp = client.post(
        f"/connectors/{source_id}?modelled_eal_lakhs=62",
        files={"file": (filename, io.BytesIO(raw), "text/csv")},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["source"] == source_id
    assert body["records"] > 0


def test_upload_without_scan_id_persists_nothing_but_still_analyses(client):
    filename, raw = _template_bytes("identity")
    body = client.post(
        f"/connectors/identity",
        files={"file": (filename, io.BytesIO(raw), "text/csv")},
    ).json()
    assert body["persisted"] is False
    assert len(body["findings"]) >= 1


def test_malformed_upload_returns_422_with_a_useful_message(client):
    resp = client.post(
        "/connectors/identity",
        files={"file": ("junk.csv", io.BytesIO(b"a,b,c\n1,2,3\n"), "text/csv")},
    )
    assert resp.status_code == 422
    assert "MFA" in resp.json()["detail"]


def test_connector_findings_lower_the_org_score(client):
    """The whole point: real internal data must move the number."""
    scan = client.get("/scan/example.com").json()
    baseline = scan["org_score"]

    filename, raw = _template_bytes("identity")
    body = client.post(
        f"/connectors/identity?scan_id={scan['scan_id']}",
        files={"file": (filename, io.BytesIO(raw), "text/csv")},
    ).json()

    assert body["persisted"] is True
    assert body["org_score"] < baseline


def test_disconnect_removes_the_contribution(client):
    scan = client.get("/scan/example.com").json()
    scan_id = scan["scan_id"]
    filename, raw = _template_bytes("identity")
    connected = client.post(
        f"/connectors/identity?scan_id={scan_id}",
        files={"file": (filename, io.BytesIO(raw), "text/csv")},
    ).json()

    removed = client.delete(f"/connectors/identity?scan_id={scan_id}").json()
    assert removed["removed_findings"] >= 1
    assert removed["org_score"] > connected["org_score"]


def test_reupload_replaces_rather_than_stacks(client):
    scan = client.get("/scan/example.com").json()
    scan_id = scan["scan_id"]
    filename, raw = _template_bytes("identity")

    first = client.post(
        f"/connectors/identity?scan_id={scan_id}",
        files={"file": (filename, io.BytesIO(raw), "text/csv")},
    ).json()
    second = client.post(
        f"/connectors/identity?scan_id={scan_id}",
        files={"file": (filename, io.BytesIO(raw), "text/csv")},
    ).json()

    assert len(first["findings"]) == len(second["findings"])
    assert first["org_score"] == second["org_score"]


@pytest.mark.parametrize("source_id", SOURCE_IDS)
def test_template_endpoint_serves_a_parsable_sample(client, source_id):
    resp = client.get(f"/connectors/{source_id}/template")
    assert resp.status_code == 200
    assert resp.content
