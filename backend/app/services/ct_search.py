"""Certificate Transparency Lookup via crt.sh with Tenacity Retries and 24h Cache"""
import logging
from typing import List, Tuple, Set
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from sqlalchemy.orm import Session
from app.config import settings
from app.services.cache import get_cached_response, set_cached_response

logger = logging.getLogger(__name__)


@retry(
    stop=stop_after_attempt(2),
    wait=wait_exponential(multiplier=1, min=1, max=3),
    retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError)),
    reraise=True,
)
def _fetch_crt_sh(domain: str) -> List[dict]:
    """Execute raw HTTP call to crt.sh with exponential backoff."""
    url = f"{settings.CRT_SH_URL}/?q=%.{domain}&output=json"
    headers = {"User-Agent": "OwLance-Scanner/1.0"}
    # crt.sh is frequently slow or 502s under load. Two bounded attempts,
    # then the caller degrades to stale cache or an explicit "unavailable"
    # flag -- the scan must never block on it.
    with httpx.Client(timeout=settings.REQUEST_TIMEOUT, follow_redirects=True) as client:
        resp = client.get(url, headers=headers)
        resp.raise_for_status()
        return resp.json()


def search_crt_sh(db: Session, domain: str) -> Tuple[List[str], bool, bool]:
    """
    Look up subdomains in Certificate Transparency logs via crt.sh.
    Returns: (subdomains_list, is_stale, data_unavailable)
    - Checks 24h cache first.
    - If crt.sh call fails after retries, attempts fallback to stale cache.
    - If neither succeeds, returns empty list with data_unavailable=True (never fake data).
    """
    cache_key = f"ct:{domain.lower()}"
    cached_data, is_stale = get_cached_response(db, cache_key, allow_stale=False)
    if cached_data is not None:
        logger.info("Retrieved CT logs for %s from active cache", domain)
        return cached_data, False, False

    try:
        raw_certs = _fetch_crt_sh(domain)
        discovered: Set[str] = set()
        for item in raw_certs:
            name_value = item.get("name_value", "")
            for name in name_value.split("\n"):
                clean_name = name.strip().lower()
                # Remove wildcard prefix
                if clean_name.startswith("*."):
                    clean_name = clean_name[2:]
                if clean_name.endswith(domain.lower()) and len(clean_name) <= 255:
                    discovered.add(clean_name)

        result_list = sorted(list(discovered))
        set_cached_response(db, cache_key, result_list)
        return result_list, False, False

    except Exception as exc:
        logger.warning("crt.sh request failed for %s: %s. Attempting stale cache fallback.", domain, exc)
        stale_data, was_stale = get_cached_response(db, cache_key, allow_stale=True)
        if stale_data is not None:
            return stale_data, True, False

        # No fabricated data allowed
        logger.error("No cached CT data available for %s after failure. Marking data unavailable.", domain)
        return [], False, True
