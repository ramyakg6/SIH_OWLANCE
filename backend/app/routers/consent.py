"""Consent Logging Router: POST /consent"""
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import ConsentLog
from app.schemas.consent import ConsentCreate, ConsentResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="", tags=["Consent"])


@router.post(
    "/consent",
    response_model=ConsentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Record assessment authorization and active scan consent",
)
def record_consent(
    payload: ConsentCreate,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Logs user consent for a domain assessment.
    Stores {domain, requester_ip, timestamp, consent_version, active_scan_allowed}
    in the consent_log table.
    """
    # Extract client IP if not provided
    client_ip = payload.requester_ip
    if not client_ip:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()
        elif request.client:
            client_ip = request.client.host

    log_time = payload.timestamp or datetime.now(timezone.utc)

    consent_record = ConsentLog(
        domain=payload.domain,
        requester_ip=client_ip,
        timestamp=log_time,
        consent_version=payload.consent_version,
        active_scan_allowed=payload.active_scan_allowed,
    )

    db.add(consent_record)
    db.commit()
    db.refresh(consent_record)

    logger.info(
        "Consent recorded for domain '%s' from IP '%s' (active_scan_allowed=%s)",
        consent_record.domain,
        consent_record.requester_ip,
        consent_record.active_scan_allowed,
    )

    return consent_record
