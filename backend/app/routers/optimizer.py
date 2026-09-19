"""Budget Optimizer Router: POST /optimize"""
import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import Finding, Asset, User
from app.services.auth import get_current_user_optional, record_event
from app.schemas.optimizer import OptimizeRequest, OptimizeResponse
from app.schemas.findings import FindingResponse
from app.services.optimizer import run_budget_optimizer
from app.services.scoring import compute_org_score

logger = logging.getLogger(__name__)

router = APIRouter(prefix="", tags=["Optimizer"])


@router.post(
    "/optimize",
    response_model=OptimizeResponse,
    summary="Run Greedy Ratio Knapsack Investment Optimizer",
)
def optimize_budget(
    payload: Optional[OptimizeRequest] = None,
    scan_id: Optional[str] = Query(None, description="UUID of the scan run"),
    budget: Optional[float] = Query(None, ge=0, description="Remediation budget in ₹"),
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_current_user_optional),
):
    """
    Greedy ratio knapsack optimizer for a given scan_id and budget:
    - Free fixes (cost == 0) are unconditionally included first.
    - Remaining fixes are sorted by efficiency ratio (reduction / cost) descending.
    - Reuses compute_org_score() to determine the projected score (300-900) by zeroing selected fixes.
    - Excludes rupee savings figure in P0.
    """
    # Accept either JSON body or query parameters
    effective_scan_id = payload.scan_id if payload else scan_id
    effective_budget = payload.budget if payload else budget

    if not effective_scan_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="scan_id is required either in request body or query parameter",
        )
    if effective_budget is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="budget is required either in request body or query parameter",
        )

    # Fetch findings for the scan_id. A scan with nothing to fix is a valid
    # outcome, not an error, so return an empty plan rather than a 404 -- the
    # dashboard should render "nothing to spend on", not break.
    findings = db.query(Finding).filter(Finding.scan_id == effective_scan_id).all()
    if not findings:
        logger.info("No findings for scan_id %s; returning empty plan", effective_scan_id)
        return OptimizeResponse(
            scan_id=effective_scan_id,
            budget=effective_budget,
            total_cost=0.0,
            remaining_budget=effective_budget,
            total_reduction=0.0,
            projected_score=compute_org_score([], assessed=False),
            selected_findings=[],
        )

    # Fetch asset names for response enrichment
    asset_records = db.query(Asset).filter(Asset.scan_id == effective_scan_id).all()
    asset_id_to_name = {a.id: a.asset_name for a in asset_records}

    # Execute knapsack optimization
    result = run_budget_optimizer(findings, effective_budget)

    # Map selected findings to FindingResponse
    selected_finding_responses: List[FindingResponse] = [
        FindingResponse(
            id=f.id,
            scan_id=f.scan_id,
            asset_id=f.asset_id,
            asset=asset_id_to_name.get(f.asset_id, "unknown"),
            cve_id=f.cve_id,
            cvss_score=f.cvss_score,
            epss_score=f.epss_score,
            cwe_id=f.cwe_id,
            is_kev=f.is_kev,
            exposure_multiplier=f.exposure_multiplier,
            asset_criticality_weight=f.asset_criticality_weight,
            final_risk_score=f.final_risk_score,
            issue=f.issue,
            short=f.short,
            severity=f.severity,
            category=f.category,
            confidence=f.confidence,
            cost=f.cost,
            reduction=f.reduction,
            eal=f.eal,
            impact=f.impact,
            likelihood=f.likelihood,
            data_unavailable=f.data_unavailable,
            is_stale_cache=f.is_stale_cache,
        )
        for f in result["selected_findings"]
    ]

    record_event(
        db,
        action="optimizer.run",
        detail=f"Budget optimizer run at ₹{int(effective_budget):,}",
        meta={
            "budget": effective_budget,
            "selected": len(selected_finding_responses),
            "total_cost": result["total_cost"],
            "projected_score": result["projected_score"],
        },
        user_id=user.id if user else None,
        scan_id=effective_scan_id,
    )

    return OptimizeResponse(
        scan_id=effective_scan_id,
        budget=effective_budget,
        total_cost=result["total_cost"],
        remaining_budget=result["remaining_budget"],
        total_reduction=result["total_reduction"],
        projected_score=result["projected_score"],
        selected_findings=selected_finding_responses,
    )
