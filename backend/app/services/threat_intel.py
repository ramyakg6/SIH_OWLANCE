"""Threat Intelligence Service: EPSS (FIRST.org), NVD / OSV.dev Fallback, and CISA KEV Catalog"""
import logging
from typing import Optional, Dict, Any, Tuple, Set
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from sqlalchemy.orm import Session
from app.config import settings
from app.services.cache import get_cached_response, set_cached_response

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# 1. EPSS (FIRST.org) Client
# ----------------------------------------------------------------------
@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=5),
    retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError)),
    reraise=True,
)
def _fetch_epss_live(cve_id: str) -> Optional[float]:
    """Query live FIRST.org EPSS API."""
    url = f"{settings.EPSS_API_URL}?cve={cve_id.upper()}"
    with httpx.Client(timeout=settings.REQUEST_TIMEOUT) as client:
        resp = client.get(url)
        resp.raise_for_status()
        data = resp.json()
        items = data.get("data", [])
        if items and "epss" in items[0]:
            return float(items[0]["epss"])
    return None


def get_epss_score(db: Session, cve_id: str) -> Tuple[Optional[float], bool, bool]:
    """
    Retrieve EPSS score for CVE.
    Returns: (epss_score, is_stale, data_unavailable)
    Strict zero-fake-data policy: returns None and data_unavailable=True on failure.
    """
    cache_key = f"epss:{cve_id.upper()}"
    cached_score, is_stale = get_cached_response(db, cache_key, allow_stale=False)
    if cached_score is not None:
        return float(cached_score), False, False

    try:
        score = _fetch_epss_live(cve_id)
        if score is not None:
            set_cached_response(db, cache_key, score)
            return score, False, False
        # If API returned valid response but CVE not in dataset
        return 0.0, False, False
    except Exception as e:
        logger.warning("EPSS live query failed for %s: %s. Checking stale cache.", cve_id, e)
        stale_score, was_stale = get_cached_response(db, cache_key, allow_stale=True)
        if stale_score is not None:
            return float(stale_score), True, False

        # No fabricated numbers
        logger.error("EPSS data completely unavailable for %s", cve_id)
        return None, False, True


# ----------------------------------------------------------------------
# 2. NVD API Client with OSV.dev Fallback
# ----------------------------------------------------------------------
@retry(
    stop=stop_after_attempt(2),
    wait=wait_exponential(multiplier=1, min=1, max=3),
    retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError)),
    reraise=True,
)
def _fetch_nvd_cve(cve_id: str) -> Optional[Dict[str, Any]]:
    """Query NVD REST API for CVSS score, severity, and CWE."""
    url = f"{settings.NVD_API_URL}?cveId={cve_id.upper()}"
    headers = {"User-Agent": "OwLance-ThreatIntel/1.0"}
    with httpx.Client(timeout=settings.REQUEST_TIMEOUT) as client:
        resp = client.get(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None
        cve_data = vulnerabilities[0].get("cve", {})
        metrics = cve_data.get("metrics", {})

        cvss_score = None
        severity = "Medium"
        # Check cvssMetricV31, then cvssMetricV30, then cvssMetricV2
        for metric_key in ["cvssMetricV31", "cvssMetricV30"]:
            if metric_key in metrics and metrics[metric_key]:
                m = metrics[metric_key][0].get("cvssData", {})
                cvss_score = float(m.get("baseScore", 5.0))
                severity = m.get("baseSeverity", "Medium").capitalize()
                break

        # Extract CWE ID
        cwe_id = None
        weaknesses = cve_data.get("weaknesses", [])
        for w in weaknesses:
            for desc in w.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-"):
                    cwe_id = val
                    break
            if cwe_id:
                break

        return {
            "cvss_score": cvss_score or 5.0,
            "severity": severity,
            "cwe_id": cwe_id or "CWE-DEFAULT",
            "source": "NVD",
        }


@retry(
    stop=stop_after_attempt(2),
    wait=wait_exponential(multiplier=1, min=1, max=3),
    retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError)),
    reraise=True,
)
def _fetch_osv_cve(cve_id: str) -> Optional[Dict[str, Any]]:
    """Fallback query to OSV.dev API when NVD fails or times out."""
    url = f"{settings.OSV_API_URL}/{cve_id.upper()}"
    with httpx.Client(timeout=settings.REQUEST_TIMEOUT) as client:
        resp = client.get(url)
        resp.raise_for_status()
        data = resp.json()
        severity_entries = data.get("severity", [])
        cvss_score = 5.0
        for entry in severity_entries:
            if entry.get("type") == "CVSS_V3":
                # Parse base score if possible or extract from vector
                vector = entry.get("score", "")
                if "/" in vector:
                    cvss_score = 7.5  # Standard default if vector only
                break

        # Extract database specific or CWE tags
        cwe_id = "CWE-DEFAULT"
        for ref in data.get("references", []):
            url_ref = ref.get("url", "")
            if "cwe.mitre.org" in url_ref:
                cwe_id = url_ref.split("/")[-1]

        return {
            "cvss_score": cvss_score,
            "severity": "High" if cvss_score >= 7.0 else "Medium",
            "cwe_id": cwe_id,
            "source": "OSV.dev",
        }


def get_cve_details(db: Session, cve_id: str) -> Tuple[Optional[Dict[str, Any]], bool, bool]:
    """
    Retrieves CVSS and CWE details for a CVE.
    Tries NVD first -> Falls back to OSV.dev -> Falls back to Stale Cache.
    Returns: (details_dict, is_stale, data_unavailable)
    """
    cache_key = f"cve:{cve_id.upper()}"
    cached_data, is_stale = get_cached_response(db, cache_key, allow_stale=False)
    if cached_data is not None:
        return cached_data, False, False

    # 1. Try NVD API
    try:
        details = _fetch_nvd_cve(cve_id)
        if details:
            set_cached_response(db, cache_key, details)
            return details, False, False
    except Exception as nvd_err:
        logger.warning("NVD API failed for %s (%s). Attempting OSV.dev fallback.", cve_id, nvd_err)

    # 2. Fallback to OSV.dev
    try:
        details = _fetch_osv_cve(cve_id)
        if details:
            set_cached_response(db, cache_key, details)
            return details, False, False
    except Exception as osv_err:
        logger.warning("OSV.dev fallback failed for %s: %s", cve_id, osv_err)

    # 3. Fallback to stale cache
    stale_data, was_stale = get_cached_response(db, cache_key, allow_stale=True)
    if stale_data is not None:
        return stale_data, True, False

    # Zero fake data policy
    logger.error("All CVE threat intel sources failed for %s. Marking data unavailable.", cve_id)
    return None, False, True


# ----------------------------------------------------------------------
# 3. CISA KEV Catalog Service
# ----------------------------------------------------------------------
@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=5),
    retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError)),
    reraise=True,
)
def _fetch_cisa_kev_live() -> Set[str]:
    """Fetch the full CISA Known Exploited Vulnerabilities catalog."""
    with httpx.Client(timeout=15.0) as client:
        resp = client.get(settings.CISA_KEV_URL)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        return {v["cveID"].upper() for v in vulns if "cveID" in v}


def get_cisa_kev_catalog(db: Session) -> Tuple[Set[str], bool, bool]:
    """
    Retrieve set of CVE IDs in CISA KEV catalog (cached 24h).
    Returns: (cve_set, is_stale, data_unavailable)
    """
    cache_key = "cisa_kev_catalog"
    cached_list, is_stale = get_cached_response(db, cache_key, allow_stale=False)
    if cached_list is not None:
        return set(cached_list), False, False

    try:
        kev_set = _fetch_cisa_kev_live()
        set_cached_response(db, cache_key, list(kev_set))
        return kev_set, False, False
    except Exception as e:
        logger.warning("Failed to fetch CISA KEV catalog live: %s. Trying stale cache.", e)
        stale_list, was_stale = get_cached_response(db, cache_key, allow_stale=True)
        if stale_list is not None:
            return set(stale_list), True, False

        logger.error("CISA KEV catalog completely unavailable.")
        return set(), False, True


def is_cve_in_kev(db: Session, cve_id: Optional[str]) -> bool:
    """Check if a CVE is in CISA KEV catalog."""
    if not cve_id:
        return False
    kev_set, _, _ = get_cisa_kev_catalog(db)
    return cve_id.upper() in kev_set
