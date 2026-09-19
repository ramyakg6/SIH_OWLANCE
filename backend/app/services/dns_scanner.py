"""Passive DNS Enumeration Service using dnspython with Tenacity Retries and 24h Cache"""
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional, Tuple
import dns.resolver
import dns.exception
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from sqlalchemy.orm import Session
from app.config import settings
from app.services.cache import get_cached_response, set_cached_response

logger = logging.getLogger(__name__)


@retry(
    stop=stop_after_attempt(2),
    wait=wait_exponential(multiplier=1, min=0.5, max=2),
    retry=retry_if_exception_type((dns.exception.Timeout, dns.resolver.NoNameservers)),
    reraise=True,
)
def _resolve_record(resolver: dns.resolver.Resolver, name: str, rtype: str) -> List[str]:
    """Resolve DNS records for a given name and type with exponential backoff."""
    try:
        answers = resolver.resolve(name, rtype)
        return [str(r.to_text()).strip('"') for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []


def query_dns_records(db: Session, target: str) -> Tuple[Dict[str, List[str]], bool, bool]:
    """
    Query A, AAAA, MX, and TXT records for a hostname.
    Returns: (records_dict, is_stale, data_unavailable)
    """
    cache_key = f"dns:{target.lower()}"
    cached_data, is_stale = get_cached_response(db, cache_key, allow_stale=False)
    if cached_data is not None:
        return cached_data, False, False

    resolver = dns.resolver.Resolver()
    resolver.timeout = settings.DNS_TIMEOUT
    resolver.lifetime = settings.DNS_LIFETIME

    records: Dict[str, List[str]] = {"A": [], "AAAA": [], "MX": [], "TXT": []}
    live_success = False

    for rtype in ["A", "AAAA", "MX", "TXT"]:
        try:
            res = _resolve_record(resolver, target, rtype)
            records[rtype] = res
            live_success = True
        except Exception as e:
            logger.debug("DNS lookup %s for %s failed: %s", rtype, target, e)

    if live_success:
        set_cached_response(db, cache_key, records)
        return records, False, False

    # Attempt fallback to stale cache
    stale_data, was_stale = get_cached_response(db, cache_key, allow_stale=True)
    if stale_data is not None:
        return stale_data, True, False

    return records, False, True


def check_email_hygiene(db: Session, domain: str) -> Dict[str, Any]:
    """
    Inspects SPF, DKIM, and DMARC configuration for the domain.
    Returns dict indicating presence and raw record values.
    """
    hygiene = {
        "has_spf": False,
        "spf_record": None,
        "has_dmarc": False,
        "dmarc_record": None,
        "has_dkim": False,
        "dkim_selectors_checked": [],
    }

    # 1. SPF Check in root TXT records
    dns_res, _, _ = query_dns_records(db, domain)
    for txt in dns_res.get("TXT", []):
        if txt.lower().startswith("v=spf1"):
            hygiene["has_spf"] = True
            hygiene["spf_record"] = txt
            break

    # 2. DMARC Check at _dmarc.{domain}
    dmarc_target = f"_dmarc.{domain}"
    dmarc_res, _, _ = query_dns_records(db, dmarc_target)
    for txt in dmarc_res.get("TXT", []):
        if txt.lower().startswith("v=dmarc1"):
            hygiene["has_dmarc"] = True
            hygiene["dmarc_record"] = txt
            break

    # 3. DKIM Check across standard common selectors
    common_selectors = ["default", "google", "k1", "mail", "s1"]
    for selector in common_selectors:
        dkim_target = f"{selector}._domainkey.{domain}"
        dkim_res, _, _ = query_dns_records(db, dkim_target)
        hygiene["dkim_selectors_checked"].append(selector)
        for txt in dkim_res.get("TXT", []):
            if "v=dkim1" in txt.lower() or "p=" in txt.lower():
                hygiene["has_dkim"] = True
                break
        if hygiene["has_dkim"]:
            break

    return hygiene


def classify_asset(asset_name: str, domain: str, records: Dict[str, List[str]], discovery_method: str) -> Dict[str, Any]:
    """
    Classifies an asset by role, status, open ports, and confidence based on passive signals.
    """
    has_ips = bool(records.get("A") or records.get("AAAA"))
    has_mx = bool(records.get("MX"))
    lower_name = asset_name.lower()

    if lower_name == domain.lower():
        asset_type = "Primary Domain"
        status = "monitored" if has_ips else "unverified"
        open_ports = [80, 443] if has_ips else []
        confidence = 0.98 if has_ips else 0.85
    elif has_mx or any(m in lower_name for m in ["mail.", "smtp.", "mx.", "webmail."]):
        asset_type = "Mail Server"
        status = "monitored" if has_ips else "unverified"
        open_ports = [25, 587, 993] if has_ips else []
        confidence = 0.95 if has_ips else 0.80
    elif any(v in lower_name for v in ["vpn.", "remote.", "rdp.", "gw."]):
        asset_type = "Remote Access"
        status = "monitored" if has_ips else "unverified"
        open_ports = [443, 3389] if has_ips else []
        confidence = 0.90 if has_ips else 0.75
    elif any(s in lower_name for s in ["assets.", "storage.", "s3.", "cdn.", "static."]):
        asset_type = "Cloud Storage"
        status = "monitored" if has_ips else "unverified"
        open_ports = [443] if has_ips else []
        confidence = 0.90 if has_ips else 0.75
    elif any(p in lower_name for p in ["api.", "portal.", "app.", "dev.", "staging."]):
        asset_type = "Web Application"
        status = "monitored" if has_ips else "unverified"
        open_ports = [80, 443] if has_ips else []
        confidence = 0.95 if has_ips else 0.80
    else:
        if has_ips:
            asset_type = "Web Application"
            status = "monitored"
            open_ports = [80, 443]
            confidence = 0.90
        else:
            asset_type = "Shadow IT"
            status = "unverified"
            open_ports = []
            confidence = 0.70

    return {
        "asset_type": asset_type,
        "status": status,
        "open_ports": open_ports,
        "discovery_confidence": confidence,
        "discovery_method": discovery_method,
    }


# Hostname fragments that tend to front the assets an attacker cares about.
# Used to order the target list before it is capped, so the cap keeps the
# interesting hosts rather than whatever crt.sh happened to list first.
PRIORITY_HINTS = (
    "mail", "smtp", "mx", "vpn", "remote", "rdp", "portal", "admin",
    "api", "auth", "sso", "login", "dev", "staging", "test", "uat",
    "git", "jenkins", "db", "sql", "ftp", "backup", "legacy", "old",
)


def prioritise_targets(domain: str, subdomains: List[str], limit: int) -> List[str]:
    """
    Order hostnames by how interesting they are, then cap the list.

    The seed domain always comes first. Then hosts matching PRIORITY_HINTS,
    then shallow hostnames (fewer labels are usually more production-facing),
    then everything else alphabetically for a deterministic, demo-safe order.
    """
    root = domain.lower()
    unique = [s for s in dict.fromkeys(s.lower() for s in subdomains) if s != root]

    def rank(host: str):
        label = host[: -(len(root) + 1)] if host.endswith("." + root) else host
        hinted = 0 if any(h in label for h in PRIORITY_HINTS) else 1
        return (hinted, host.count("."), host)

    ordered = [root] + sorted(unique, key=rank)
    if len(ordered) > limit:
        logger.info(
            "Capping scan targets for %s: %d discovered, resolving top %d",
            domain, len(ordered), limit,
        )
    return ordered[:limit]


def enumerate_dns(db: Session, domain: str, discovered_subdomains: List[str]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Performs passive DNS enumeration for the root domain and discovered hostnames.

    Targets are prioritised and capped (settings.MAX_SCAN_TARGETS) and resolved
    in a thread pool, because a real crt.sh result can contain hundreds of names
    and resolving them one at a time would take minutes.

    Returns: (list_of_asset_dicts, email_hygiene_dict)
    """
    all_targets = prioritise_targets(domain, discovered_subdomains, settings.MAX_SCAN_TARGETS)

    # Resolve in parallel. Each worker opens its own DB session because
    # SQLAlchemy sessions are not safe to share across threads.
    from app.db.session import SessionLocal

    def resolve_one(target: str) -> Tuple[str, Dict[str, List[str]], bool, bool]:
        worker_db = SessionLocal()
        try:
            records, is_stale, unavailable = query_dns_records(worker_db, target)
            return target, records, is_stale, unavailable
        except Exception as exc:
            logger.warning("DNS resolution failed for %s: %s", target, exc)
            return target, {"A": [], "AAAA": [], "MX": [], "TXT": []}, False, True
        finally:
            worker_db.close()

    # Wall-clock deadline: whatever has resolved when time runs out is what
    # we report. Unresolved targets are still returned, flagged unavailable,
    # so the endpoint degrades to partial results instead of hanging.
    deadline = time.monotonic() + settings.SCAN_DEADLINE_SECONDS
    empty = {"A": [], "AAAA": [], "MX": [], "TXT": []}
    resolved_map: Dict[str, Tuple[str, Dict[str, List[str]], bool, bool]] = {}

    workers = max(1, min(settings.DNS_WORKERS, len(all_targets)))
    # Deliberately not a `with` block: ThreadPoolExecutor.__exit__ joins every
    # running worker, which would re-introduce the hang the deadline exists to
    # prevent. Shut down without waiting and let stragglers die with the process.
    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        futures = {pool.submit(resolve_one, t): t for t in all_targets}
        try:
            for fut in as_completed(futures, timeout=max(1.0, deadline - time.monotonic())):
                target, records, is_stale, unavailable = fut.result()
                resolved_map[target] = (target, records, is_stale, unavailable)
        except TimeoutError:
            logger.warning(
                "Scan deadline of %.0fs reached for %s; returning %d/%d resolved targets",
                settings.SCAN_DEADLINE_SECONDS, domain, len(resolved_map), len(all_targets),
            )
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    resolved = [
        resolved_map.get(t, (t, dict(empty), False, True))
        for t in all_targets
    ]

    assets_data = []

    for target, records, is_stale, unavailable in resolved:
        is_seed = (target.lower() == domain.lower())
        method = "Seed" if is_seed else "CT Logs"

        classification = classify_asset(target, domain, records, method)

        tech_stack = {
            "dns_records": records,
            "ip_addresses": records.get("A", []) + records.get("AAAA", []),
            "mail_exchangers": records.get("MX", []),
        }

        assets_data.append({
            "asset_name": target,
            "domain": domain,
            "asset_type": classification["asset_type"],
            "discovery_method": classification["discovery_method"],
            "status": classification["status"],
            "open_ports": classification["open_ports"],
            "discovery_confidence": classification["discovery_confidence"],
            "tech_stack": tech_stack,
        })

    hygiene = check_email_hygiene(db, domain)
    return assets_data, hygiene
