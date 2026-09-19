"""Authentication, scan history, and the audit log: /auth/* and /audit/*"""
import logging
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.config import settings
from app.db.models import AuditEvent, ScanHistory, User
from app.db.session import get_db
from app.schemas.auth import (
    AuditEntry,
    AuditVerification,
    LoginRequest,
    RegisterRequest,
    ScanHistoryEntry,
    TokenResponse,
    UserResponse,
)
from app.services.auth import (
    create_access_token,
    get_current_user_optional,
    hash_password,
    password_problems,
    record_event,
    require_user,
    verify_chain,
    verify_password,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Auth"])


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _token_response(user: User) -> TokenResponse:
    token, expires_in = create_access_token(user)
    return TokenResponse(
        access_token=token,
        expires_in=expires_in,
        user=UserResponse.model_validate(user),
    )


@router.post(
    "/auth/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an account",
)
def register(payload: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()

    problems = password_problems(payload.password)
    if problems:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password must " + ", ".join(problems) + ".",
        )

    if db.query(User).filter(User.email == email).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    user = User(
        email=email,
        password_hash=hash_password(payload.password),
        org_name=(payload.org_name or "").strip() or None,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    record_event(
        db, action="account.created", detail=f"Account created for {email}",
        user_id=user.id, meta={"ip": _client_ip(request)},
    )
    logger.info("Registered new account %s", email)
    return _token_response(user)


@router.post("/auth/login", response_model=TokenResponse, summary="Sign in")
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    user = db.query(User).filter(User.email == email).first()

    # One message for both cases, so the response cannot be used to work out
    # which email addresses have accounts.
    if not user or not verify_password(payload.password, user.password_hash):
        record_event(
            db, action="auth.failed", detail=f"Failed sign-in for {email}",
            meta={"ip": _client_ip(request)},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
        )

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This account is disabled.")

    user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)

    record_event(
        db, action="auth.login", detail=f"{email} signed in",
        user_id=user.id, meta={"ip": _client_ip(request)},
    )
    return _token_response(user)


@router.get("/auth/me", response_model=UserResponse, summary="Current account")
def me(user: User = Depends(require_user)):
    return UserResponse.model_validate(user)


@router.get(
    "/history",
    response_model=List[ScanHistoryEntry],
    summary="Score history for the signed-in account",
)
def scan_history(
    domain: Optional[str] = Query(None, description="Restrict to one domain"),
    limit: int = Query(24, ge=1, le=200),
    user: Optional[User] = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    """
    Real score history, oldest first, so the trend line plots actual scans.

    Signed out there is nothing to return: history is what an account buys.
    """
    if not user:
        return []

    q = db.query(ScanHistory).filter(ScanHistory.user_id == user.id)
    if domain:
        q = q.filter(ScanHistory.domain == domain.strip().lower())
    rows = q.order_by(ScanHistory.scanned_at.desc()).limit(limit).all()
    return [ScanHistoryEntry.model_validate(r) for r in reversed(rows)]


@router.get("/audit", response_model=List[AuditEntry], summary="Audit log")
def audit_log(
    limit: int = Query(25, ge=1, le=200),
    scan_id: Optional[str] = Query(None),
    user: Optional[User] = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    """
    The most recent entries, newest first.

    Signed in, the log is scoped to the account. Signed out it shows only
    entries that belong to no account, so one visitor's activity is never
    visible to another.
    """
    q = db.query(AuditEvent)
    q = q.filter(AuditEvent.user_id == user.id) if user else q.filter(AuditEvent.user_id.is_(None))
    if scan_id:
        q = q.filter(AuditEvent.scan_id == scan_id)
    rows = q.order_by(AuditEvent.id.desc()).limit(limit).all()
    return [AuditEntry.model_validate(r) for r in rows]


@router.get(
    "/audit/verify",
    response_model=AuditVerification,
    summary="Verify the audit log has not been tampered with",
)
def audit_verify(db: Session = Depends(get_db)):
    """
    Recomputes every hash from the first entry forward.

    Because each entry hashes the previous entry's hash, altering or deleting
    any historical row breaks every hash after it, and this reports the first
    entry where the chain fails.
    """
    return AuditVerification(**verify_chain(db))
