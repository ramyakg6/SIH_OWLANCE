"""Connector ingest router: /connectors/*

Accepts an administrator's export from one of the six supported data sources,
parses it, and folds the result into the scan: new findings are persisted
against the scan, CMDB criticality ratings re-weight existing findings, and
the organisation score is recomputed.

Connector findings carry a higher confidence than externally-inferred ones,
because they come from inside the organisation rather than from what can be
observed from the internet.
"""
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models import Asset, Finding, User
from app.services.auth import get_current_user_optional, record_event
from app.schemas.connectors import ConnectorResponse, ConnectorStatus
from app.schemas.findings import FindingResponse
from app.services.connectors import (
    SOURCE_IDS,
    SOURCE_LABELS,
    get_template,
    parse_connector,
)
from app.services.scoring import (
    calculate_risk_score,
    compute_org_score,
    get_cwe_weight,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/connectors", tags=["Connectors"])

MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB

# Findings created from a connector record which source produced them, so a
# disconnect can remove exactly those and leave the passive scan intact.
CONNECTOR_PREFIX = "connector:"


def _connector_asset(db: Session, scan_id: str, source_id: str) -> Asset:
    """Get or create the synthetic asset that connector findings hang from."""
    name = f"{SOURCE_LABELS[source_id]} ({source_id})"
    existing = (
        db.query(Asset)
        .filter(Asset.scan_id == scan_id, Asset.asset_name == name)
        .first()
    )
    if existing:
        return existing

    domain = "internal"
    any_asset = db.query(Asset).filter(Asset.scan_id == scan_id).first()
    if any_asset:
        domain = any_asset.domain

    asset = Asset(
        scan_id=scan_id,
        domain=domain,
        asset_name=name,
        asset_type="Internal Source",
        discovery_method=f"{CONNECTOR_PREFIX}{source_id}",
        tech_stack={},
        open_ports=[],
        status="monitored",
        discovery_confidence=1.0,  # Supplied by the organisation itself.
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


def _serialise(f: Finding, asset_names: dict) -> FindingResponse:
    return FindingResponse(
        id=f.id,
        scan_id=f.scan_id,
        asset_id=f.asset_id,
        asset=asset_names.get(f.asset_id, "internal"),
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


@router.get(
    "/{source_id}/template",
    response_class=PlainTextResponse,
    summary="Download a sample export for a data source",
)
def connector_template(source_id: str):
    """
    Returns a small CSV in the same shape as the real vendor export, so the
    ingest path can be exercised without first obtaining a live export.
    """
    try:
        filename, content = get_template(source_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    return PlainTextResponse(
        content,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        media_type="text/csv",
    )


@router.get("", response_model=List[ConnectorStatus], summary="List connected sources for a scan")
def list_connectors(scan_id: str = Query(...), db: Session = Depends(get_db)):
    assets = (
        db.query(Asset)
        .filter(Asset.scan_id == scan_id, Asset.discovery_method.like(f"{CONNECTOR_PREFIX}%"))
        .all()
    )
    out: List[ConnectorStatus] = []
    for a in assets:
        source_id = a.discovery_method[len(CONNECTOR_PREFIX):]
        count = db.query(Finding).filter(Finding.asset_id == a.id).count()
        out.append(ConnectorStatus(
            source=source_id,
            label=SOURCE_LABELS.get(source_id, source_id),
            connected=True,
            findings_count=count,
        ))
    return out


@router.post(
    "/{source_id}",
    response_model=ConnectorResponse,
    summary="Ingest an export from an internal data source",
)
async def ingest_connector(
    source_id: str,
    file: UploadFile = File(..., description="CSV, JSON, or PDF export from the vendor console"),
    scan_id: Optional[str] = Query(None, description="Scan to attach the result to"),
    modelled_eal_lakhs: float = Query(
        0.0, ge=0, description="Modelled annual loss, used to size the insurance coverage gap"
    ),
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_current_user_optional),
):
    """
    Parse a vendor export and fold it into the scan.

    The API-connector form of each source runs this same parser behind an
    OAuth token; only the transport differs.
    """
    if source_id not in SOURCE_IDS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown data source '{source_id}'. Expected one of: {', '.join(SOURCE_IDS)}",
        )

    raw = await file.read()
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit",
        )

    try:
        parsed = parse_connector(source_id, raw, file.filename or "upload", modelled_eal_lakhs)
    except ValueError as exc:
        # A malformed upload is the user's problem to fix, and the message
        # tells them exactly which column was missing.
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    except Exception as exc:
        logger.exception("Connector parse failed for %s", source_id)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Could not parse this file: {exc}",
        )

    logger.info(
        "Connector '%s' ingested %s: %d records, %d finding(s)",
        source_id, file.filename, parsed["records"], len(parsed["findings"]),
    )

    # Without a scan to attach to, still return the analysis -- the parse is
    # the valuable part and the caller may be running against sample data.
    # Nothing is written to the database in this path.
    if not scan_id:
        transient: List[FindingResponse] = []
        for i, spec in enumerate(parsed["findings"]):
            cwe_weight = get_cwe_weight(spec.get("cwe_id"))
            transient.append(FindingResponse(
                id=-(i + 1),          # negative ids mark unpersisted findings
                scan_id="",
                asset_id=0,
                asset=parsed["label"],
                cve_id=spec.get("cve_id"),
                cvss_score=spec.get("cvss_score"),
                epss_score=spec.get("epss_score"),
                cwe_id=spec.get("cwe_id"),
                is_kev=spec.get("is_kev", False),
                exposure_multiplier=1.0,
                asset_criticality_weight=1.2,
                final_risk_score=calculate_risk_score(
                    spec.get("epss_score") or 0.0,
                    spec.get("cvss_score") or 0.0,
                    cwe_weight, 1.0, 1.2,
                ),
                issue=spec["issue"],
                short=spec["short"],
                severity=spec.get("severity", "Medium"),
                category=spec.get("category", "Identity"),
                confidence=spec.get("confidence", 97),
                cost=spec.get("cost", 0),
                reduction=spec.get("reduction", 10),
                eal=spec.get("eal", 5.0),
                impact=spec.get("impact", 3),
                likelihood=spec.get("likelihood", 3),
                data_unavailable=False,
                is_stale_cache=False,
            ))
        return ConnectorResponse(
            source=source_id,
            label=parsed["label"],
            filename=parsed["filename"],
            records=parsed["records"],
            summary=parsed["summary"],
            replaces_inference=parsed.get("replaces_inference"),
            metrics=parsed["metrics"],
            findings=transient,
            persisted=False,
            org_score=None,
            reweighted_findings=0,
        )

    asset = _connector_asset(db, scan_id, source_id)

    # Replace any previous upload from this source rather than stacking.
    db.query(Finding).filter(Finding.asset_id == asset.id).delete(synchronize_session=False)
    db.commit()

    created: List[Finding] = []
    for spec in parsed["findings"]:
        cwe_weight = get_cwe_weight(spec.get("cwe_id"))
        final = calculate_risk_score(
            spec.get("epss_score") or 0.0,
            spec.get("cvss_score") or 0.0,
            cwe_weight,
            1.0,
            1.2,  # Internal sources describe assets that matter to the business.
        )
        f = Finding(
            scan_id=scan_id,
            asset_id=asset.id,
            cve_id=spec.get("cve_id"),
            cvss_score=spec.get("cvss_score"),
            epss_score=spec.get("epss_score"),
            cwe_id=spec.get("cwe_id"),
            is_kev=spec.get("is_kev", False),
            exposure_multiplier=1.0,
            asset_criticality_weight=1.2,
            final_risk_score=final,
            issue=spec["issue"],
            short=spec["short"],
            severity=spec.get("severity", "Medium"),
            category=spec.get("category", "Identity"),
            confidence=spec.get("confidence", 97),
            cost=spec.get("cost", 0),
            reduction=spec.get("reduction", 10),
            eal=spec.get("eal", 5.0),
            impact=spec.get("impact", 3),
            likelihood=spec.get("likelihood", 3),
            data_unavailable=False,
            is_stale_cache=False,
        )
        db.add(f)
        created.append(f)

    # A CMDB re-weights findings on the assets it rates, because criticality
    # was previously inferred from asset type.
    reweighted = 0
    overrides = parsed.get("criticality_overrides") or {}
    if overrides:
        scan_assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
        by_name = {a.asset_name.lower(): a for a in scan_assets}
        for name, weight in overrides.items():
            target = by_name.get(name)
            if not target:
                continue
            for f in db.query(Finding).filter(Finding.asset_id == target.id).all():
                f.asset_criticality_weight = weight
                f.final_risk_score = calculate_risk_score(
                    f.epss_score or 0.0,
                    f.cvss_score or 0.0,
                    get_cwe_weight(f.cwe_id),
                    f.exposure_multiplier,
                    weight,
                )
                # Business classification is a fact, not an inference.
                f.confidence = min(99, (f.confidence or 85) + 5)
                reweighted += 1

    db.commit()
    for f in created:
        db.refresh(f)

    all_findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    org_score = compute_org_score(all_findings, assessed=True)

    record_event(
        db,
        action="connector.ingested",
        detail=f"{parsed['label']} connected from {parsed['filename']}",
        meta={
            "source": source_id,
            "records": parsed["records"],
            "findings": len(created),
            "reweighted": reweighted,
            "org_score": org_score,
        },
        user_id=user.id if user else None,
        scan_id=scan_id,
    )

    asset_names = {a.id: a.asset_name for a in db.query(Asset).filter(Asset.scan_id == scan_id).all()}

    return ConnectorResponse(
        source=source_id,
        label=parsed["label"],
        filename=parsed["filename"],
        records=parsed["records"],
        summary=parsed["summary"],
        replaces_inference=parsed.get("replaces_inference"),
        metrics=parsed["metrics"],
        findings=[_serialise(f, asset_names) for f in created],
        persisted=True,
        org_score=org_score,
        reweighted_findings=reweighted,
    )


@router.delete("/{source_id}", summary="Disconnect a data source")
def disconnect_connector(
    source_id: str,
    scan_id: str = Query(...),
    db: Session = Depends(get_db),
):
    """Removes findings contributed by this source and recomputes the score."""
    if source_id not in SOURCE_IDS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Unknown data source '{source_id}'")

    asset = (
        db.query(Asset)
        .filter(
            Asset.scan_id == scan_id,
            Asset.discovery_method == f"{CONNECTOR_PREFIX}{source_id}",
        )
        .first()
    )
    removed = 0
    if asset:
        removed = db.query(Finding).filter(Finding.asset_id == asset.id).delete(synchronize_session=False)
        db.delete(asset)
        db.commit()

    remaining = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    return {
        "source": source_id,
        "disconnected": True,
        "removed_findings": removed,
        "org_score": compute_org_score(remaining, assessed=True),
    }
