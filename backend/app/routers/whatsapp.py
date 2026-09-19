"""
WhatsApp passport delivery.

  GET  /whatsapp/status           are credentials present (never echoes them)
  POST /whatsapp/preview          compose the body without sending
  POST /whatsapp/send-passport    compose and send the full status snapshot

The send endpoint answers 200 even when delivery fails, carrying
delivered=false and a plain-language reason. A failed WhatsApp send is a
normal outcome the UI needs to render, not a server error.
"""
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.config import settings
from app.db.models import User
from app.db.session import get_db
from app.schemas.whatsapp import (
    PreviewRequest,
    PreviewResponse,
    SendPassportRequest,
    SendPassportResponse,
    WhatsAppStatusResponse,
)
from app.services.auth import get_current_user_optional, record_event
from app.services.whatsapp import (
    compose_passport_message,
    configuration_status,
    delivery_mode,
    is_configured,
    mask_phone,
    normalise_phone,
    send_whatsapp,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/whatsapp", tags=["WhatsApp"])


@router.get(
    "/status",
    response_model=WhatsAppStatusResponse,
    summary="Whether Twilio WhatsApp credentials are configured",
)
def whatsapp_status():
    """
    Lets the UI show real delivery vs preview-only before the user clicks
    send. Reports which variables are missing; never returns the auth token.
    """
    info = configuration_status()
    if info["configured"]:
        detail = (
            "Twilio is configured. Messages will be delivered for real "
            + ("as an approved template (TWILIO_CONTENT_SID is set)."
               if info["mode"] == "template" else "as free-form text.")
        )
    else:
        detail = (
            "Twilio is not configured, so sends return a preview instead. "
            f"Set {', '.join(info['missing'])} in backend/.env."
        )
    return WhatsAppStatusResponse(**info, detail=detail)


@router.post(
    "/preview",
    response_model=PreviewResponse,
    summary="Compose the message body without sending it",
)
def preview_passport(payload: PreviewRequest):
    """Render the exact text a send would deliver, for the in-app phone mock."""
    body = compose_passport_message(payload.snapshot.model_dump(exclude_none=True))
    return PreviewResponse(body=body, characters=len(body), configured=is_configured())


@router.post(
    "/send-passport",
    response_model=SendPassportResponse,
    summary="Send the full current posture snapshot to a WhatsApp number",
)
def send_passport(
    payload: SendPassportRequest,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_current_user_optional),
):
    """
    One-click full status: score, confidence, loss exposure, open issues,
    the ranked fix list, framework coverage, and the passport link.

    The snapshot comes from the client because the on-screen figures reflect
    the user's live optimizer position and revenue calibration.
    """
    try:
        to_e164 = normalise_phone(payload.phone)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc

    snapshot = payload.snapshot.model_dump(exclude_none=True)
    snapshot.setdefault("passport_url", f"{settings.PASSPORT_BASE_URL}/{(snapshot.get('domain') or 'org')}")

    body = compose_passport_message(snapshot)
    delivered, detail = send_whatsapp(to_e164, body, snapshot)

    # Sending a posture summary off-platform is a disclosure, so it belongs
    # in the audit chain whether or not it reached the recipient. The number
    # is recorded masked.
    try:
        record_event(
            db,
            action="passport.whatsapp_send",
            detail=(
                f"Risk passport sent to {mask_phone(to_e164)}"
                if delivered else
                f"Risk passport send to {mask_phone(to_e164)} not delivered "
                f"({detail.get('status')})"
            ),
            meta={
                "to": mask_phone(to_e164),
                "delivered": delivered,
                "status": detail.get("status"),
                "twilio_code": detail.get("twilio_code"),
                "mode": delivery_mode(),
                "domain": snapshot.get("domain"),
                "score": snapshot.get("score"),
                "characters": len(body),
            },
            user_id=user.id if user else None,
            scan_id=payload.scan_id,
        )
    except Exception:
        # An audit-write failure must not lose a message that already went.
        logger.exception("Could not record passport send in the audit chain")

    return SendPassportResponse(
        delivered=delivered,
        configured=is_configured(),
        status=detail.get("status", "unknown"),
        to=mask_phone(to_e164),
        body=body,
        message=detail.get("message", ""),
        sid=detail.get("sid"),
        twilio_code=detail.get("twilio_code"),
        hint=detail.get("hint"),
    )
