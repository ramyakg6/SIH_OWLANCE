"""Passive Scan Router: GET /scan/{domain}"""
import logging
import uuid
import re
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import Asset, Finding, ScanHistory, User
from app.services.auth import get_current_user_optional, record_event
from app.schemas.scan import ScanResponse, AssetResponse
from app.schemas.findings import FindingResponse
from app.services.ct_search import search_crt_sh
from app.services.dns_scanner import enumerate_dns
from app.services.scoring import (
    evaluate_asset_findings,
    compute_org_score,
    apply_confidence_ceiling,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="", tags=["Scan"])


def clean_domain(raw_domain: str) -> str:
    domain = raw_domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0].split(":")[0]
    if not domain or "." not in domain or len(domain) > 253:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid domain name format",
        )
    return domain


@router.get(
    "/scan/{domain}",
    response_model=ScanResponse,
    summary="Passive Attack Surface Discovery and Composite Risk Scoring",
)
def passive_scan(
    domain: str,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_current_user_optional),
):
    """
    Performs passive attack surface discovery:
    1. Certificate Transparency logs via crt.sh (no auth required)
    2. DNS enumeration via dnspython (A/AAAA/MX/TXT; parses SPF/DKIM/DMARC)
    3. Caches every external response with a 24-hour TTL and tenacity backoff
    4. Persists discovered assets to the 'assets' table
    5. Calculates composite risk scores and persists findings to the 'findings' table
    6. Returns complete inventory and risk posture (org score 300-900).
    """
    valid_domain = clean_domain(domain)
    scan_id = str(uuid.uuid4())
    scanned_at = datetime.now(timezone.utc)

    logger.info("Initiating passive scan %s for domain: %s", scan_id, valid_domain)

    # 1. Certificate Transparency lookup via crt.sh
    subdomains, is_stale_ct, ct_unavailable = search_crt_sh(db, valid_domain)

    # 2. DNS enumeration (A/AAAA/MX/TXT + SPF/DKIM/DMARC)
    assets_raw, email_hygiene = enumerate_dns(db, valid_domain, subdomains)

    # 3. Store assets in database
    db_assets: List[Asset] = []
    for item in assets_raw:
        asset_record = Asset(
            scan_id=scan_id,
            user_id=user.id if user else None,
            domain=valid_domain,
            asset_name=item["asset_name"],
            asset_type=item["asset_type"],
            discovery_method=item["discovery_method"],
            discovered_at=scanned_at,
            tech_stack=item["tech_stack"],
            open_ports=item["open_ports"],
            status=item["status"],
            discovery_confidence=item["discovery_confidence"],
        )
        db.add(asset_record)
        db_assets.append(asset_record)

    db.commit()
    for a in db_assets:
        db.refresh(a)

    # 4. Evaluate findings & composite risk scoring across discovered assets
    all_findings: List[Finding] = []
    for asset in db_assets:
        findings = evaluate_asset_findings(db, scan_id, asset, email_hygiene)
        for f in findings:
            db.add(f)
            all_findings.append(f)

    db.commit()
    for f in all_findings:
        db.refresh(f)

    # 5. Determine how much of this scan actually rested on live intelligence.
    #    A domain we could not reach is unknown, not clean, so an unassessed
    #    scan must never be scored 900.
    resolved_assets = [
        a for a in db_assets
        if (a.tech_stack or {}).get("ip_addresses") or (a.tech_stack or {}).get("mail_exchangers")
    ]
    notes: List[str] = []
    if ct_unavailable:
        notes.append(
            "Certificate Transparency (crt.sh) was unreachable - subdomain "
            "discovery is limited to DNS for this run."
        )
    if is_stale_ct:
        notes.append("Certificate Transparency results served from cache older than 24h.")
    if not resolved_assets:
        notes.append(
            "No DNS records resolved for this domain - findings could not be "
            "established and the score is reported as insufficient data."
        )

    assessed = bool(resolved_assets)
    if not assessed:
        data_confidence = "insufficient"
    elif ct_unavailable or is_stale_ct:
        data_confidence = "partial"
    else:
        data_confidence = "high"

    # 6. Compute organization risk score (300 - 900)
    org_score = apply_confidence_ceiling(
        compute_org_score(all_findings, assessed=assessed), data_confidence
    )
    if data_confidence != "high":
        notes.append(
            f"Score capped at {org_score} because discovery coverage was "
            f"{data_confidence}; a full score requires complete asset discovery."
        )

    # 7. Build response representations
    asset_id_to_name = {a.id: a.asset_name for a in db_assets}
    asset_responses: List[AssetResponse] = []
    for a in db_assets:
        # Determine highest severity finding on this asset
        asset_findings = [f for f in all_findings if f.asset_id == a.id]
        highest_risk = "Low"
        for sev in ["Critical", "High", "Medium", "Low"]:
            if any(f.severity == sev for f in asset_findings):
                highest_risk = sev
                break

        asset_responses.append(
            AssetResponse(
                id=a.id,
                scan_id=a.scan_id,
                domain=a.domain,
                asset_name=a.asset_name,
                asset_type=a.asset_type,
                discovery_method=a.discovery_method,
                discovered_at=a.discovered_at,
                tech_stack=a.tech_stack,
                open_ports=a.open_ports,
                status=a.status,
                discovery_confidence=a.discovery_confidence,
                risk=highest_risk,
            )
        )

    finding_responses: List[FindingResponse] = [
        FindingResponse(
            id=f.id,
            scan_id=f.scan_id,
            asset_id=f.asset_id,
            asset=asset_id_to_name.get(f.asset_id, valid_domain),
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
        for f in all_findings
    ]

    # Record the run so the trend line is a real series, and append to the
    # audit chain so the assessment is attributable after the fact.
    db.add(ScanHistory(
        scan_id=scan_id,
        user_id=user.id if user else None,
        domain=valid_domain,
        org_score=org_score,
        findings_count=len(finding_responses),
        assets_count=len(asset_responses),
        data_confidence=data_confidence,
        scanned_at=scanned_at,
    ))
    db.commit()

    record_event(
        db,
        action="scan.completed",
        detail=f"Passive scan of {valid_domain} scored {org_score}",
        meta={
            "domain": valid_domain,
            "org_score": org_score,
            "assets": len(asset_responses),
            "findings": len(finding_responses),
            "data_confidence": data_confidence,
        },
        user_id=user.id if user else None,
        scan_id=scan_id,
    )

    return ScanResponse(
        scan_id=scan_id,
        domain=valid_domain,
        scanned_at=scanned_at,
        org_score=org_score,
        assets_count=len(asset_responses),
        findings_count=len(finding_responses),
        assets=asset_responses,
        findings=finding_responses,
        cached=is_stale_ct,
        data_confidence=data_confidence,
        notes=notes,
    )
