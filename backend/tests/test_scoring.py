"""Tests for Composite Risk Scoring and Org Score Aggregation"""
from app.db.models import Finding
from app.services.scoring import (
    calculate_risk_score,
    get_cwe_weight,
    get_asset_criticality_weight,
    classify_severity,
    compute_org_score,
)


def test_composite_risk_scoring_formula():
    # Formula: EPSS x (CVSS / 10) x CWE_weight x Exposure_Multiplier x Asset_Criticality_Weight
    epss = 0.50
    cvss = 8.0  # cvss_weight = 0.8
    cwe_weight = 1.5  # CWE-89 SQLi
    exposure_multiplier = 1.0  # Standardized 1.0 for P0 external
    asset_criticality_weight = 1.5  # Primary Domain

    # Expected: 0.50 * 0.8 * 1.5 * 1.0 * 1.5 = 0.9000
    expected = 0.50 * 0.8 * 1.5 * 1.0 * 1.5
    score = calculate_risk_score(epss, cvss, cwe_weight, exposure_multiplier, asset_criticality_weight)
    assert abs(score - expected) < 0.0001


def test_cwe_weights():
    assert get_cwe_weight("CWE-89") == 1.5
    assert get_cwe_weight("CWE-78") == 1.6
    assert get_cwe_weight("CWE-287") == 1.4
    assert get_cwe_weight("CWE-999") == 1.0  # Default fallback
    assert get_cwe_weight(None) == 1.0


def test_asset_criticality_weights():
    assert get_asset_criticality_weight("Primary Domain") == 1.5
    assert get_asset_criticality_weight("Remote Access") == 1.4
    assert get_asset_criticality_weight("Mail Server") == 1.3
    assert get_asset_criticality_weight("Web Application") == 1.0
    assert get_asset_criticality_weight("Shadow IT") == 0.8


def test_cisa_kev_hard_escalation():
    # When is_kev is True, severity MUST be Critical regardless of low score
    low_risk_score = 0.02
    assert classify_severity(low_risk_score, is_kev=True) == "Critical"
    assert classify_severity(low_risk_score, is_kev=False) == "Low"


def test_compute_org_score():
    # Empty findings -> perfect 900 score
    assert compute_org_score([]) == 900

    f1 = Finding(id=1, final_risk_score=0.45, reduction=25)
    f2 = Finding(id=2, final_risk_score=0.25, reduction=15)
    findings = [f1, f2]

    initial_score = compute_org_score(findings)
    assert 300 <= initial_score < 900

    # Zeroing out fixed finding f1 must raise the score
    projected_score = compute_org_score(findings, fixed_ids={1})
    assert projected_score > initial_score
    assert projected_score <= 900
