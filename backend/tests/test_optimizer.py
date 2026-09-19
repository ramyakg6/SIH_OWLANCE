"""Tests for /optimize and Greedy Knapsack Budget Optimizer"""
import time
from app.db.models import Finding, Asset
from app.services.optimizer import run_budget_optimizer


def test_greedy_knapsack_free_fixes_first():
    # Setup findings: 2 free fixes, and paid fixes with different reduction/cost ratios
    f_free1 = Finding(id=1, cost=0, reduction=12, final_risk_score=0.15)
    f_free2 = Finding(id=2, cost=0, reduction=35, final_risk_score=0.30)
    # Ratio: 22 / 8000 = 0.00275
    f_high_ratio = Finding(id=3, cost=8000, reduction=22, final_risk_score=0.25)
    # Ratio: 18 / 25000 = 0.00072
    f_low_ratio = Finding(id=4, cost=25000, reduction=18, final_risk_score=0.35)

    findings = [f_free1, f_free2, f_high_ratio, f_low_ratio]
    budget = 10000.0

    result = run_budget_optimizer(findings, budget)

    selected_ids = [f.id for f in result["selected_findings"]]
    # Free fixes must be included
    assert 1 in selected_ids
    assert 2 in selected_ids
    # Higher ratio fix (id=3, cost 8000 <= 10000) must be included
    assert 3 in selected_ids
    # Lower ratio fix (id=4, cost 25000 > remaining 2000) must NOT be included
    assert 4 not in selected_ids

    assert result["total_cost"] == 8000
    assert result["remaining_budget"] == 2000.0
    assert result["total_reduction"] == (12 + 35 + 22)
    assert 300 <= result["projected_score"] <= 900
    assert "savings" not in result  # Confirmed: No rupee savings in P0


def test_optimizer_latency_benchmark_50_findings():
    """Verify that optimizer runs in well under 100ms for 50 findings."""
    findings = []
    for i in range(50):
        cost = 0 if i % 10 == 0 else (i * 1000 + 500)
        reduction = (i % 20) + 5
        findings.append(Finding(id=i + 1, cost=cost, reduction=reduction, final_risk_score=0.05))

    budget = 25000.0
    start = time.perf_counter()
    result = run_budget_optimizer(findings, budget)
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    # Must be well under 100ms
    assert elapsed_ms < 50.0
    assert len(result["selected_findings"]) > 0


def test_post_optimize_endpoint(client, db_session):
    scan_id = "test-scan-uuid-1234"
    # Seed asset
    asset = Asset(
        scan_id=scan_id,
        domain="company.com",
        asset_name="portal.company.com",
        asset_type="Web Application",
        discovery_method="Seed",
        status="monitored",
        open_ports=[80, 443],
    )
    db_session.add(asset)
    db_session.commit()
    db_session.refresh(asset)

    # Seed findings
    f1 = Finding(
        scan_id=scan_id,
        asset_id=asset.id,
        issue="Enable MFA",
        short="Enable MFA",
        cost=0,
        reduction=35,
        final_risk_score=0.20,
    )
    f2 = Finding(
        scan_id=scan_id,
        asset_id=asset.id,
        issue="CMS Patch",
        short="CMS Patch",
        cost=8000,
        reduction=22,
        final_risk_score=0.30,
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    # Call endpoint with query params
    response = client.post(f"/optimize?scan_id={scan_id}&budget=10000")
    assert response.status_code == 200
    data = response.json()
    assert data["scan_id"] == scan_id
    assert data["budget"] == 10000.0
    assert data["total_cost"] == 8000
    assert data["remaining_budget"] == 2000.0
    assert data["total_reduction"] == 57
    assert 300 <= data["projected_score"] <= 900
    assert len(data["selected_findings"]) == 2
    assert "savings" not in data
