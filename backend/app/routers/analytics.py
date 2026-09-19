"""Derived analytics router: /analytics/{scan_id}

Compliance coverage, attack paths, and category risk, all computed from the
findings a scan actually produced rather than read from stored constants.
"""
import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models import Asset, Finding
from app.schemas.analytics import AnalyticsResponse
from app.services.analytics import (
    compute_attack_graph,
    compute_attack_paths,
    compute_category_risk,
    compute_compliance,
    compute_insurance_readiness,
    compute_causal_graph,
)
from app.services.scoring import compute_org_score

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/analytics", tags=["Analytics"])

CONNECTOR_PREFIX = "connector:"


@router.get(
    "/{scan_id}",
    response_model=AnalyticsResponse,
    summary="Compliance coverage, attack paths, and category risk for a scan",
)
def analytics(scan_id: str, db: Session = Depends(get_db)):
    assets: List[Asset] = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    findings: List[Finding] = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    if not assets and not findings:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No scan found with id {scan_id}",
        )

    connected = [
        a.discovery_method[len(CONNECTOR_PREFIX):]
        for a in assets
        if (a.discovery_method or "").startswith(CONNECTOR_PREFIX)
    ]
    # Connector placeholders are not part of the external attack surface.
    real_assets = [a for a in assets if not (a.discovery_method or "").startswith(CONNECTOR_PREFIX)]

    return AnalyticsResponse(
        scan_id=scan_id,
        org_score=compute_org_score(findings, assessed=bool(findings or real_assets)),
        compliance=compute_compliance(findings, real_assets, connected),
        attack_paths=compute_attack_paths(findings, assets),
        attack_graph=compute_attack_graph(findings, assets),
        category_risk=compute_category_risk(findings),
        connected_sources=connected,
        insurance=compute_insurance_readiness(findings, real_assets, connected),
        causal_graph=compute_causal_graph(findings, real_assets, connected),
    )
