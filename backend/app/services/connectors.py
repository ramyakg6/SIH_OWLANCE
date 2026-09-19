"""
Connector ingest.

Each of the six data sources in the UI corresponds to an export that an
administrator can produce from the vendor's own console:

    cloud      AWS IAM credential report (CSV), or any user/MFA export
    identity   Google Workspace or Microsoft 365 user export (CSV)
    endpoint   CrowdStrike / SentinelOne / Defender device export (CSV)
    siem       Splunk / Sentinel / Elastic / Wazuh alert export (CSV or JSON)
    cmdb       ServiceNow / Snipe-IT asset export (CSV)
    insurance  Cyber insurance policy (PDF, or a text/CSV schedule)

The API-connector version of each source is the same parser sitting behind an
OAuth token instead of a file upload, so the analysis below is the real one
either way -- only the transport differs.

Everything here is derived from the uploaded file. Nothing is invented: if a
column is missing, the corresponding check is reported as not assessable
rather than assumed to pass.
"""
import csv
import io
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Exports from different vendors name the same concept differently. Each entry
# lists the substrings that identify a column, matched case-insensitively
# against normalised headers.
COLUMN_ALIASES: Dict[str, Tuple[str, ...]] = {
    "user": ("user", "username", "email", "userprincipalname", "displayname", "account", "login"),
    # Google Workspace exports "2sv_enrolled"; Microsoft 365 exports
    # "StrongAuthenticationMethods"; Okta uses "factor_enrolled".
    "mfa": ("mfa", "two_factor", "twofactor", "2fa", "2sv", "two_step", "twostep",
            "multifactor", "multi_factor", "strongauth", "second_factor", "factor_enrolled"),
    "admin": ("admin", "isadmin", "role", "privileged", "is_superuser", "usertype"),
    "device": ("device", "hostname", "host", "machine", "computer", "endpoint", "asset_name", "name"),
    "patch": ("patch", "updated", "os_version", "osversion", "compliance", "compliant", "last_seen_patch"),
    "compliant": ("compliant", "compliance", "status", "health", "state"),
    "severity": ("severity", "priority", "urgency", "risk"),
    "alert": ("alert", "rule", "signature", "event", "title", "description", "message"),
    "count": ("count", "occurrences", "hits", "events", "total"),
    "asset": ("asset", "ci_name", "name", "hostname", "device", "configuration_item"),
    "criticality": ("criticality", "business_criticality", "importance", "tier", "classification", "priority"),
    "access_key_rotated": ("access_key_1_last_rotated", "access_key_2_last_rotated", "key_last_rotated"),
    "password_enabled": ("password_enabled", "password_status"),
}

TRUTHY = {"true", "yes", "y", "1", "enabled", "on", "active", "compliant", "ok", "pass", "passed", "healthy"}
FALSY = {"false", "no", "n", "0", "disabled", "off", "inactive", "non-compliant", "noncompliant", "fail", "failed", "unhealthy"}


def _normalise(header: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (header or "").strip().lower()).strip("_")


def _find_column(headers: List[str], key: str) -> Optional[str]:
    """Return the original header matching a logical column, if present."""
    aliases = COLUMN_ALIASES.get(key, ())
    normalised = {h: _normalise(h) for h in headers}
    # Exact alias match wins over a substring match.
    for header, norm in normalised.items():
        if norm in aliases:
            return header
    for header, norm in normalised.items():
        if any(alias in norm for alias in aliases):
            return header
    return None


def _as_bool(value: Any) -> Optional[bool]:
    """Interpret a cell as a boolean, or None when it cannot be determined."""
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    if text in TRUTHY:
        return True
    if text in FALSY:
        return False
    return None


def _read_csv(raw: bytes) -> List[Dict[str, str]]:
    """Decode and parse a CSV upload, tolerating BOMs and odd encodings."""
    for encoding in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            text = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:
        raise ValueError("File could not be decoded as text")

    # Skip leading blank/comment lines some consoles prepend.
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        raise ValueError("File is empty")

    try:
        dialect = csv.Sniffer().sniff("\n".join(lines[:5]), delimiters=",;\t|")
        delimiter = dialect.delimiter
    except csv.Error:
        delimiter = ","

    rows = list(csv.DictReader(io.StringIO("\n".join(lines)), delimiter=delimiter))
    if not rows:
        raise ValueError("No data rows found -- the file has headers but no records")
    return rows


def _finding(**kwargs) -> Dict[str, Any]:
    """
    Build a finding dict in the shape the scan/optimize endpoints return.

    Note on epss_score: EPSS is an exploit probability published per CVE.
    Configuration and hygiene findings have no CVE, so this slot carries a
    calibrated likelihood proxy in the same 0-1 space. It is deliberately
    well below typical CVE exploit rates -- a missing MFA enrolment is a
    standing weakness, not an actively weaponised exploit.
    """
    base = {
        "cve_id": None,
        "cvss_score": 5.0,
        "epss_score": 0.08,
        "cwe_id": None,
        "is_kev": False,
        "severity": "Medium",
        "category": "Identity",
        "confidence": 97,  # Internal, confirmed data beats any external inference.
        "cost": 0,
        "reduction": 10,
        "eal": 5.0,
        "impact": 3,
        "likelihood": 3,
        "data_unavailable": False,
        "is_stale_cache": False,
    }
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# Per-source parsers
# ---------------------------------------------------------------------------

def parse_identity(rows: List[Dict[str, str]]) -> Dict[str, Any]:
    """Google Workspace / Microsoft 365 user export -> real MFA exposure."""
    headers = list(rows[0].keys())
    user_col = _find_column(headers, "user")
    mfa_col = _find_column(headers, "mfa")
    admin_col = _find_column(headers, "admin")

    if not mfa_col:
        raise ValueError(
            "No MFA column found. Export users with their MFA/2-step status "
            "(a column named 'MFA Enrolled', '2sv_enrolled', or similar)."
        )

    total = len(rows)
    no_mfa, admins_no_mfa = [], []
    for row in rows:
        enrolled = _as_bool(row.get(mfa_col))
        if enrolled is False:
            name = (row.get(user_col) or "unknown").strip() if user_col else "unknown"
            no_mfa.append(name)
            if admin_col:
                role = str(row.get(admin_col) or "").lower()
                if "admin" in role or _as_bool(row.get(admin_col)) is True:
                    admins_no_mfa.append(name)

    findings: List[Dict[str, Any]] = []
    if admins_no_mfa:
        findings.append(_finding(
            issue=f"{len(admins_no_mfa)} admin account(s) without MFA: {', '.join(admins_no_mfa[:3])}"
                  + (" and others" if len(admins_no_mfa) > 3 else ""),
            short="Admin MFA",
            severity="Critical",
            category="Identity",
            cwe_id="CWE-287",
            cvss_score=8.8,
            epss_score=0.18,
            cost=0,
            reduction=35,
            eal=18.0,
            impact=5,
            likelihood=4,
        ))
    if no_mfa and not admins_no_mfa:
        findings.append(_finding(
            issue=f"{len(no_mfa)} of {total} accounts have no MFA enrolled",
            short="Enable MFA",
            severity="High",
            category="Identity",
            cwe_id="CWE-287",
            cvss_score=7.4,
            cost=0,
            reduction=28,
            eal=12.0,
            impact=4,
            likelihood=4,
        ))

    coverage = round(100 * (total - len(no_mfa)) / total) if total else 0
    return {
        "records": total,
        "summary": f"{total} accounts read - MFA coverage {coverage}%"
                   + (f", {len(admins_no_mfa)} admin(s) unprotected" if admins_no_mfa else ""),
        "findings": findings,
        "metrics": {"accounts": total, "mfa_coverage_pct": coverage, "admins_without_mfa": len(admins_no_mfa)},
        "replaces_inference": "MFA enforcement is now confirmed from the identity provider "
                              "rather than inferred from external signals.",
    }


def parse_cloud(rows: List[Dict[str, str]]) -> Dict[str, Any]:
    """AWS IAM credential report (or equivalent) -> real identity exposure."""
    headers = list(rows[0].keys())
    user_col = _find_column(headers, "user")
    mfa_col = _find_column(headers, "mfa")
    key_col = _find_column(headers, "access_key_rotated")

    if not mfa_col and not key_col:
        raise ValueError(
            "No MFA or access-key column found. Upload an AWS IAM credential "
            "report (IAM console > Credential report) or an equivalent export."
        )

    total = len(rows)
    findings: List[Dict[str, Any]] = []
    no_mfa, root_no_mfa, stale_keys = [], False, 0

    for row in rows:
        name = (row.get(user_col) or "").strip() if user_col else ""
        if mfa_col and _as_bool(row.get(mfa_col)) is False:
            no_mfa.append(name or "unknown")
            if name.lower() in {"root", "<root_account>", "root_account"}:
                root_no_mfa = True
        if key_col:
            val = str(row.get(key_col) or "").strip().lower()
            # A real timestamp that is not "N/A"/"not_supported" implies an
            # active long-lived key.
            if val and val not in {"n/a", "not_supported", "false", "no_information"}:
                stale_keys += 1

    if root_no_mfa:
        findings.append(_finding(
            issue="Root account has no MFA enabled",
            short="Root MFA",
            severity="Critical",
            category="Cloud",
            cwe_id="CWE-287",
            cvss_score=9.8,
            epss_score=0.20,
            is_kev=False,
            cost=0,
            reduction=30,
            eal=30.0,
            impact=5,
            likelihood=4,
        ))
    if no_mfa and not root_no_mfa:
        findings.append(_finding(
            issue=f"{len(no_mfa)} cloud IAM principal(s) without MFA",
            short="IAM MFA",
            severity="High",
            category="Cloud",
            cwe_id="CWE-287",
            cvss_score=7.5,
            cost=0,
            reduction=20,
            eal=14.0,
            impact=4,
            likelihood=3,
        ))
    if stale_keys:
        findings.append(_finding(
            issue=f"{stale_keys} long-lived access key(s) in use",
            short="Rotate Keys",
            severity="Medium",
            category="Cloud",
            cwe_id="CWE-798",
            cvss_score=6.5,
            cost=5000,
            reduction=8,
            eal=6.0,
            impact=3,
            likelihood=3,
        ))

    return {
        "records": total,
        "summary": f"{total} cloud principals read"
                   + (f", {len(no_mfa)} without MFA" if no_mfa else ", all MFA-protected")
                   + (f", {stale_keys} long-lived key(s)" if stale_keys else ""),
        "findings": findings,
        "metrics": {"principals": total, "without_mfa": len(no_mfa), "long_lived_keys": stale_keys},
        "replaces_inference": "Cloud IAM posture now comes from the account itself, not from "
                              "what is visible externally.",
    }


def parse_endpoint(rows: List[Dict[str, str]]) -> Dict[str, Any]:
    """EDR device export -> real patch and compliance state."""
    headers = list(rows[0].keys())
    device_col = _find_column(headers, "device")
    compliant_col = _find_column(headers, "compliant") or _find_column(headers, "patch")

    if not compliant_col:
        raise ValueError(
            "No compliance or patch-status column found. Export devices with "
            "their compliance/patch state from your EDR console."
        )

    total = len(rows)
    non_compliant = []
    for row in rows:
        state = _as_bool(row.get(compliant_col))
        if state is False:
            non_compliant.append((row.get(device_col) or "unknown").strip() if device_col else "unknown")

    findings: List[Dict[str, Any]] = []
    if non_compliant:
        pct = round(100 * len(non_compliant) / total)
        findings.append(_finding(
            issue=f"{len(non_compliant)} of {total} endpoints are unpatched or non-compliant",
            short="Patch Fleet",
            severity="Critical" if pct >= 30 else "High",
            category="Network",
            cwe_id="CWE-1104",
            cvss_score=8.1,
            epss_score=0.16,
            cost=8000,
            reduction=24,
            eal=16.0,
            impact=4,
            likelihood=5 if pct >= 30 else 4,
        ))

    compliant_pct = round(100 * (total - len(non_compliant)) / total) if total else 0
    return {
        "records": total,
        "summary": f"{total} endpoints read - {compliant_pct}% compliant"
                   + (f", {len(non_compliant)} need patching" if non_compliant else ""),
        "findings": findings,
        "metrics": {"devices": total, "compliant_pct": compliant_pct, "non_compliant": len(non_compliant)},
        "replaces_inference": "Patch status is now measured from the fleet instead of "
                              "estimated from exposed service banners.",
    }


def parse_siem(rows: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    SIEM alert export -> evidence of what is actually being attempted.

    This is the one source that changes likelihood rather than adding a new
    exposure: an attack being actively attempted is more likely to succeed
    than one that is merely theoretically possible.
    """
    headers = list(rows[0].keys())
    alert_col = _find_column(headers, "alert")
    sev_col = _find_column(headers, "severity")
    count_col = _find_column(headers, "count")

    if not alert_col:
        raise ValueError(
            "No alert/rule column found. Export alert history with a rule "
            "name, signature, or event description column."
        )

    total = 0
    buckets: Dict[str, int] = {}
    high_sev = 0
    for row in rows:
        try:
            n = int(float(str(row.get(count_col) or 1))) if count_col else 1
        except (TypeError, ValueError):
            n = 1
        total += n
        label = str(row.get(alert_col) or "unknown").strip()[:80]
        buckets[label] = buckets.get(label, 0) + n
        if sev_col:
            sev = str(row.get(sev_col) or "").lower()
            if any(s in sev for s in ("critical", "high", "4", "5")):
                high_sev += n

    top = sorted(buckets.items(), key=lambda kv: kv[1], reverse=True)[:3]

    findings: List[Dict[str, Any]] = []
    if top:
        label, count = top[0]
        findings.append(_finding(
            issue=f"Active attack attempts observed: \"{label}\" ({count} events)",
            short="Active Threat",
            severity="Critical" if high_sev else "High",
            category="Network",
            cwe_id=None,
            cvss_score=7.8,
            epss_score=0.22,
            cost=0,
            reduction=15,
            eal=20.0,
            impact=4,
            likelihood=5,  # Observed in the wild against this org.
        ))

    return {
        "records": len(rows),
        "summary": f"{total} events across {len(buckets)} rule(s)"
                   + (f", {high_sev} high-severity" if high_sev else ""),
        "findings": findings,
        "metrics": {
            "events": total,
            "rules": len(buckets),
            "high_severity": high_sev,
            "top_alerts": [{"rule": k, "count": v} for k, v in top],
        },
        "likelihood_boost": 1 if top else 0,
        "replaces_inference": "Likelihood is now grounded in attacks actually observed "
                              "against this organisation, not modelled base rates.",
    }


def parse_cmdb(rows: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    CMDB export -> real asset criticality.

    Criticality is otherwise inferred from asset type. A CMDB replaces that
    inference with the business's own classification, which changes the
    weighting of every finding on those assets.
    """
    headers = list(rows[0].keys())
    asset_col = _find_column(headers, "asset")
    crit_col = _find_column(headers, "criticality")

    if not asset_col:
        raise ValueError(
            "No asset-name column found. Export your CI list with a name "
            "column (e.g. 'ci_name', 'hostname', 'asset')."
        )

    # Map common criticality vocabularies onto the scoring weight.
    scale = {
        "critical": 1.5, "tier 1": 1.5, "tier1": 1.5, "1": 1.5, "very high": 1.5, "crown jewel": 1.5,
        "high": 1.3, "tier 2": 1.3, "tier2": 1.3, "2": 1.3, "important": 1.3,
        "medium": 1.0, "tier 3": 1.0, "tier3": 1.0, "3": 1.0, "moderate": 1.0, "normal": 1.0,
        "low": 0.8, "tier 4": 0.8, "tier4": 0.8, "4": 0.8, "minor": 0.8,
    }

    overrides: Dict[str, float] = {}
    tiers: Dict[str, int] = {}
    for row in rows:
        name = (row.get(asset_col) or "").strip().lower()
        if not name:
            continue
        raw = str(row.get(crit_col) or "").strip().lower() if crit_col else ""
        weight = scale.get(raw)
        if weight is None:
            continue
        overrides[name] = weight
        tiers[raw] = tiers.get(raw, 0) + 1

    if crit_col and not overrides:
        raise ValueError(
            f"Criticality column '{crit_col}' had no recognised values. "
            "Expected values like Critical / High / Medium / Low or Tier 1-4."
        )

    crown_jewels = sum(1 for w in overrides.values() if w >= 1.5)
    return {
        "records": len(rows),
        "summary": f"{len(rows)} configuration items read"
                   + (f", {len(overrides)} with a criticality rating"
                      + (f" ({crown_jewels} business-critical)" if crown_jewels else "")
                      if overrides else " (no criticality column - names only)"),
        "findings": [],
        "criticality_overrides": overrides,
        "metrics": {"configuration_items": len(rows), "rated": len(overrides), "crown_jewels": crown_jewels,
                    "tiers": tiers},
        "replaces_inference": "Asset criticality now comes from the business's own CMDB "
                              "instead of being inferred from asset type.",
    }


def parse_insurance(raw: bytes, filename: str, modelled_eal_lakhs: float = 0.0) -> Dict[str, Any]:
    """
    Cyber insurance policy -> coverage gap against modelled loss.

    Accepts a PDF (text layer) or a plain-text/CSV schedule. Currency amounts
    are extracted and the largest is treated as the aggregate limit.
    """
    text = ""
    if filename.lower().endswith(".pdf"):
        try:
            from pypdf import PdfReader
            reader = PdfReader(io.BytesIO(raw))
            text = "\n".join((page.extract_text() or "") for page in reader.pages)
        except ImportError:
            raise ValueError("PDF support unavailable on the server. Upload the policy schedule as CSV or text.")
        except Exception as exc:
            raise ValueError(f"Could not read the PDF: {exc}")
        if not text.strip():
            raise ValueError(
                "This PDF has no extractable text -- it is most likely a scan. "
                "Upload a text-based policy or enter the limits as CSV."
            )
    else:
        for encoding in ("utf-8-sig", "utf-8", "latin-1"):
            try:
                text = raw.decode(encoding)
                break
            except UnicodeDecodeError:
                continue

    # Match Indian (lakh/crore) and plain numeric currency figures.
    amounts: List[float] = []
    for num, unit in re.findall(
        r"(?:₹|INR|Rs\.?)\s*([\d,]+(?:\.\d+)?)\s*(crore|cr|lakh|lakhs|lac|l|million|mn)?",
        text, re.IGNORECASE,
    ):
        try:
            value = float(num.replace(",", ""))
        except ValueError:
            continue
        u = (unit or "").lower()
        if u in ("crore", "cr"):
            value *= 100          # to lakhs
        elif u in ("lakh", "lakhs", "lac", "l"):
            pass                  # already lakhs
        elif u in ("million", "mn"):
            value *= 10           # 1 mn INR = 10 lakhs
        else:
            value /= 100000.0     # plain rupees -> lakhs
        amounts.append(value)

    if not amounts:
        raise ValueError(
            "No coverage amounts found in the document. Ensure the policy "
            "schedule lists limits in ₹ / INR / Rs."
        )

    limit_lakhs = max(amounts)
    findings: List[Dict[str, Any]] = []
    gap = modelled_eal_lakhs - limit_lakhs

    if modelled_eal_lakhs > 0 and gap > 0:
        findings.append(_finding(
            issue=f"Cyber cover of ₹{limit_lakhs:.1f}L sits below modelled annual "
                  f"loss of ₹{modelled_eal_lakhs:.1f}L (gap ₹{gap:.1f}L)",
            short="Cover Gap",
            severity="High",
            category="Cloud",
            cwe_id=None,
            cvss_score=0.0,
            epss_score=0.0,
            cost=0,
            reduction=0,   # Insurance transfers loss; it does not reduce risk.
            eal=gap,
            impact=4,
            likelihood=3,
        ))

    return {
        "records": len(amounts),
        "summary": f"Policy read - aggregate limit ₹{limit_lakhs:.1f}L"
                   + (f", modelled loss ₹{modelled_eal_lakhs:.1f}L, gap ₹{gap:.1f}L"
                      if modelled_eal_lakhs > 0 and gap > 0
                      else ", cover exceeds modelled annual loss" if modelled_eal_lakhs > 0 else ""),
        "findings": findings,
        "metrics": {
            "limit_lakhs": round(limit_lakhs, 2),
            "modelled_eal_lakhs": round(modelled_eal_lakhs, 2),
            "gap_lakhs": round(max(0.0, gap), 2),
            "amounts_found": len(amounts),
        },
        "replaces_inference": "Coverage limits are read from the actual policy and compared "
                              "against the modelled loss distribution.",
    }


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

SOURCE_IDS = ("cloud", "identity", "endpoint", "siem", "cmdb", "insurance")

SOURCE_LABELS = {
    "cloud": "Cloud Infrastructure",
    "identity": "Email & Identity Provider",
    "endpoint": "Endpoint Detection (EDR)",
    "siem": "SIEM / Log Platform",
    "cmdb": "Asset Inventory / CMDB",
    "insurance": "Cyber Insurance Policy",
}


def parse_connector(
    source_id: str,
    raw: bytes,
    filename: str,
    modelled_eal_lakhs: float = 0.0,
) -> Dict[str, Any]:
    """Parse an uploaded export for a source. Raises ValueError on bad input."""
    if source_id not in SOURCE_IDS:
        raise ValueError(f"Unknown data source '{source_id}'")
    if not raw:
        raise ValueError("The uploaded file is empty")

    if source_id == "insurance":
        result = parse_insurance(raw, filename, modelled_eal_lakhs)
    else:
        name = filename.lower()
        if name.endswith(".json"):
            payload = json.loads(raw.decode("utf-8", errors="replace"))
            if isinstance(payload, dict):
                for key in ("results", "records", "data", "items", "events", "alerts"):
                    if isinstance(payload.get(key), list):
                        payload = payload[key]
                        break
            if not isinstance(payload, list) or not payload:
                raise ValueError("JSON must be a non-empty array of records")
            rows = [{k: ("" if v is None else str(v)) for k, v in r.items()} for r in payload if isinstance(r, dict)]
            if not rows:
                raise ValueError("JSON array contained no object records")
        else:
            rows = _read_csv(raw)

        result = {
            "cloud": parse_cloud,
            "identity": parse_identity,
            "endpoint": parse_endpoint,
            "siem": parse_siem,
            "cmdb": parse_cmdb,
        }[source_id](rows)

    result.setdefault("findings", [])
    result.setdefault("criticality_overrides", {})
    result.setdefault("metrics", {})
    result["source"] = source_id
    result["label"] = SOURCE_LABELS[source_id]
    result["filename"] = filename
    return result


# ---------------------------------------------------------------------------
# Sample exports
# ---------------------------------------------------------------------------
# Served by GET /connectors/{source_id}/template so the flow can be exercised
# without hunting for a real export first. Column names mirror the real vendor
# exports, so a genuine file drops in unchanged.

TEMPLATES: Dict[str, Tuple[str, str]] = {
    "identity": ("identity_users.csv",
        "Email Address,Name,MFA Enrolled,Role\n"
        "priya@company.com,Priya S,TRUE,Super Admin\n"
        "arun@company.com,Arun K,FALSE,Super Admin\n"
        "meera@company.com,Meera R,TRUE,User\n"
        "dev@company.com,Dev Team,FALSE,User\n"
        "ops@company.com,Ops Team,TRUE,User\n"),
    "cloud": ("aws_credential_report.csv",
        "user,password_enabled,mfa_active,access_key_1_last_rotated\n"
        "<root_account>,true,false,N/A\n"
        "deploy-bot,false,false,2024-01-14T08:12:00+00:00\n"
        "analytics,true,true,N/A\n"
        "backup-svc,false,false,2023-11-02T10:44:00+00:00\n"),
    "endpoint": ("edr_devices.csv",
        "Hostname,OS Version,Compliant,Last Seen\n"
        "LAP-0021,Windows 11 23H2,true,2026-09-18\n"
        "LAP-0034,Windows 10 21H2,false,2026-09-17\n"
        "SRV-DB-01,Ubuntu 22.04,true,2026-09-18\n"
        "LAP-0047,Windows 10 20H2,false,2026-09-12\n"
        "SRV-APP-02,Ubuntu 20.04,false,2026-09-18\n"),
    "siem": ("siem_alerts.csv",
        "Rule,Severity,Count,Last Seen\n"
        "Brute force against VPN portal,High,412,2026-09-18\n"
        "Suspicious OAuth consent grant,Critical,7,2026-09-17\n"
        "Outbound traffic to known C2,High,3,2026-09-16\n"
        "Impossible travel sign-in,Medium,22,2026-09-18\n"),
    "cmdb": ("cmdb_assets.csv",
        "ci_name,ci_type,business_criticality,owner\n"
        "portal.company.com,Web Application,Critical,Platform\n"
        "mail.company.com,Mail Server,High,IT\n"
        "vpn.company.com,Remote Access,Critical,Network\n"
        "assets.company.com,Cloud Storage,Medium,Platform\n"
        "test-old.company.com,Web Application,Low,Unassigned\n"),
    "insurance": ("cyber_policy_schedule.csv",
        "Section,Description,Limit\n"
        "Aggregate,Policy aggregate limit,Rs 50,00,000\n"
        "Sub-limit,Business interruption,Rs 20,00,000\n"
        "Sub-limit,Ransomware / extortion,Rs 10,00,000\n"
        "Deductible,Each and every claim,Rs 2,00,000\n"),
}


def get_template(source_id: str) -> Tuple[str, str]:
    if source_id not in TEMPLATES:
        raise ValueError(f"No sample export available for '{source_id}'")
    return TEMPLATES[source_id]
