"""
Authentication and the tamper-evident audit log.

Passwords are hashed with bcrypt; the plaintext is never stored, logged, or
returned. Sessions are stateless JWTs signed with SECRET_KEY.

The audit log is append-only and hash-chained: each entry hashes its own
contents together with the previous entry's hash, so editing or removing any
historical row invalidates every hash after it. Verification is one pass.
"""
import hashlib
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.config import settings
from app.db.models import AuditEvent, User
from app.db.session import get_db

logger = logging.getLogger(__name__)

ALGORITHM = "HS256"

# Auth is optional on read paths so the demo still works when signed out;
# auto_error=False lets the dependency return None instead of raising.
bearer_scheme = HTTPBearer(auto_error=False)

# bcrypt truncates silently past 72 bytes, which would make two different long
# passwords equivalent. Reject rather than truncate.
MAX_PASSWORD_BYTES = 72


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    raw = password.encode("utf-8")
    if len(raw) > MAX_PASSWORD_BYTES:
        raise ValueError("Password must be 72 bytes or fewer")
    return bcrypt.hashpw(raw, bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        raw = password.encode("utf-8")
        if len(raw) > MAX_PASSWORD_BYTES:
            return False
        return bcrypt.checkpw(raw, password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def password_problems(password: str) -> List[str]:
    """Return a list of reasons a password is unacceptable, empty if fine."""
    problems: List[str] = []
    if len(password) < 8:
        problems.append("be at least 8 characters")
    if not any(c.isalpha() for c in password):
        problems.append("contain a letter")
    if not any(c.isdigit() for c in password):
        problems.append("contain a number")
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        problems.append("be 72 bytes or fewer")
    return problems


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------

def create_access_token(user: User) -> Tuple[str, int]:
    """Return (token, expires_in_seconds)."""
    expires_in = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)
    return token, expires_in


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        logger.info("Rejected an expired token")
        return None
    except jwt.InvalidTokenError as exc:
        logger.info("Rejected an invalid token: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> Optional[User]:
    """
    Resolve the signed-in user, or None.

    Scanning is deliberately usable signed out: the platform's value is
    visible before an account exists, and history simply is not retained.
    """
    if not credentials or not credentials.credentials:
        return None
    payload = decode_token(credentials.credentials)
    if not payload:
        return None
    user = db.query(User).filter(User.id == int(payload.get("sub", 0))).first()
    if not user or not user.is_active:
        return None
    return user


def require_user(user: Optional[User] = Depends(get_current_user_optional)) -> User:
    """For endpoints that genuinely need an identity, such as history."""
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sign in to access this resource",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def _canonical_ts(value: datetime) -> str:
    """
    Normalise a timestamp for hashing.

    The database layer does not always preserve tzinfo -- SQLite returns naive
    datetimes -- so a value hashed at write time as "+00:00" would read back
    bare and produce a different hash, breaking the chain on every verify.
    Naive values are treated as UTC, and everything is reduced to the same
    UTC-naive ISO form on both sides.
    """
    if value.tzinfo is None:
        return value.isoformat()
    return value.astimezone(timezone.utc).replace(tzinfo=None).isoformat()


def _compute_hash(
    prev_hash: str,
    action: str,
    detail: str,
    meta: Dict[str, Any],
    timestamp: datetime,
    user_id: Optional[int],
    scan_id: Optional[str],
) -> str:
    """Hash an entry's contents together with the previous entry's hash."""
    payload = json.dumps(
        {
            "prev": prev_hash,
            "action": action,
            "detail": detail,
            "meta": meta,
            "ts": _canonical_ts(timestamp),
            "user": user_id,
            "scan": scan_id,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def record_event(
    db: Session,
    action: str,
    detail: str = "",
    meta: Optional[Dict[str, Any]] = None,
    user_id: Optional[int] = None,
    scan_id: Optional[str] = None,
) -> AuditEvent:
    """Append an entry to the chain. Never raises into the caller's path."""
    meta = meta or {}
    last = db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
    prev_hash = last.entry_hash if last else ""
    timestamp = datetime.now(timezone.utc)

    event = AuditEvent(
        user_id=user_id,
        scan_id=scan_id,
        action=action,
        detail=detail[:512],
        meta=meta,
        timestamp=timestamp,
        prev_hash=prev_hash,
        entry_hash=_compute_hash(prev_hash, action, detail[:512], meta, timestamp, user_id, scan_id),
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def verify_chain(db: Session) -> Dict[str, Any]:
    """
    Recompute the chain from the beginning and report the first break.

    An intact chain means no historical entry has been altered or removed
    since it was written.
    """
    events = db.query(AuditEvent).order_by(AuditEvent.id.asc()).all()
    prev_hash = ""
    for event in events:
        expected = _compute_hash(
            prev_hash, event.action, event.detail, event.meta or {},
            event.timestamp, event.user_id, event.scan_id,
        )
        if event.prev_hash != prev_hash or event.entry_hash != expected:
            return {
                "intact": False,
                "entries": len(events),
                "broken_at_id": event.id,
                "detail": f"Entry {event.id} does not match the chain; "
                          "it has been altered or a prior entry was removed.",
            }
        prev_hash = event.entry_hash

    return {
        "intact": True,
        "entries": len(events),
        "broken_at_id": None,
        "detail": f"All {len(events)} entries verified against the hash chain.",
        "head_hash": prev_hash,
    }


def generate_secret() -> str:
    return secrets.token_urlsafe(48)
