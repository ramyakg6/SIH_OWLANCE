"""24-Hour TTL Caching Service for External Threat Intel and Discovery"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, Any
from sqlalchemy.orm import Session
from app.db.models import CacheEntry
from app.config import settings

logger = logging.getLogger(__name__)


def get_cached_response(
    db: Session, cache_key: str, allow_stale: bool = False
) -> Tuple[Optional[Any], bool]:
    """
    Retrieve cached data for cache_key.
    Returns: (cached_data, is_stale)
    - If unexpired, returns (data, False)
    - If expired and allow_stale is True, returns (data, True)
    - Otherwise returns (None, False)
    """
    try:
        entry = db.query(CacheEntry).filter(CacheEntry.cache_key == cache_key).first()
        if not entry:
            return None, False

        now = datetime.now(timezone.utc)
        # Ensure entry.expires_at is timezone-aware for comparison
        expires_at = entry.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if now <= expires_at:
            return entry.cached_data, False
        elif allow_stale:
            logger.info("Serving stale cached entry for key %s", cache_key)
            return entry.cached_data, True
        else:
            return None, False
    except Exception as e:
        logger.error("Error reading cache for key %s: %s", cache_key, e)
        return None, False


def set_cached_response(
    db: Session, cache_key: str, data: Any, ttl_hours: Optional[int] = None
) -> None:
    """Store or update cached data with TTL (default 24 hours)."""
    if ttl_hours is None:
        ttl_hours = settings.CACHE_TTL_HOURS
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=ttl_hours)

    try:
        entry = db.query(CacheEntry).filter(CacheEntry.cache_key == cache_key).first()
        if entry:
            entry.cached_data = data
            entry.expires_at = expires_at
            entry.created_at = now
        else:
            entry = CacheEntry(
                cache_key=cache_key,
                cached_data=data,
                expires_at=expires_at,
                created_at=now,
            )
            db.add(entry)
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error("Error writing cache for key %s: %s", cache_key, e)
