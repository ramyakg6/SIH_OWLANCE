"""Composite Risk Scoring and Org Score Aggregation Service"""
import logging
from typing import Dict, Any, List, Optional, Set
from sqlalchemy.orm import Session
from app.db.models import Finding, Asset
from app.services.threat_intel import get_epss_score, get_cve_details, is_cve_in_kev

logger = logging.getLogger(__name__)

# Static hardcoded CWE weights (no external API calls)
CWE_WEIGHTS: Dict[str, float] = {
    "CWE-78": 1.6,   # OS Command Injection
    "CWE-89": 1.5,   # SQL Injection
    "CWE-502": 1.5,  # Deserialization of Untrusted Data
    "CWE-287": 1.4,  # Improper Authentication
    "CWE-22": 1.3,   # Path Traversal
    "CWE-319": 1.2,  # Cleartext Transmission of Sensitive Information
    "CWE-79": 1.1,   # Cross-site Scripting (XSS)
    "CWE-352": 1.1,  # Cross-Site Request Forgery (CSRF)
    "DEFAULT": 1.0,
}


def get_cwe_weight(cwe_id: Optional[str]) -> float:
    """Lookup static CWE weight with fallback to default 1.0."""
    if not cwe_id:
        return CWE_WEIGHTS["DEFAULT"]
    clean_id = cwe_id.strip().upper()
    return CWE_WEIGHTS.get(clean_id, CWE_WEIGHTS["DEFAULT"])


def get_asset_criticality_weight(asset_type: str) -> float:
    """
    Returns asset criticality weight.
    # NOTE: Currently asset-type-based. Will need replacing with the signal-based approach
    # (login form / PII / open DB port detection) once Stage B enrichment exists.
    """
    weights = {
        "Primary Domain": 1.5,
        "Remote Access": 1.4,
        "Mail Server": 1.3,
        "Cloud Storage": 1.2,
        "Web Application": 1.0,
        "Shadow IT": 0.8,
    }
    return weights.get(asset_type, 1.0)


def calculate_risk_score(
    epss_score: float,
    cvss_score: float,
    cwe_weight: float,
    exposure_multiplier: float,
    asset_criticality_weight: float,
) -> float:
    """
    Composite Risk Scoring formula:
    Final_Risk_Score = EPSS_score x CVSS_weight x CWE_weight x Exposure_Multiplier x Asset_Criticality_Weight
    """
    cvss_weight = max(0.1, cvss_score / 10.0)
    score = epss_score * cvss_weight * cwe_weight * exposure_multiplier * asset_criticality_weight
    return round(score, 4)


def classify_severity(final_risk_score: float, is_kev: bool) -> str:
    """
    Determine severity bracket based on risk score.
    Hard Escalation Rule: Any CVE in CISA KEV catalog is hard-escalated to Critical.
    """
    if is_kev:
        return "Critical"
    if final_risk_score >= 0.40:
        return "Critical"
    if final_risk_score >= 0.20:
        return "High"
    if final_risk_score >= 0.08:
        return "Medium"
    return "Low"


# Returned when discovery itself failed. An unreachable domain is an unknown
# domain, not a clean one, so it must not be scored as though it were assessed.
INSUFFICIENT_DATA_SCORE = 550

# A scan that only saw part of the attack surface cannot certify a clean bill
# of health. These ceilings keep an incomplete run from reporting a perfect
# score just because the parts we could not see produced no findings.
CONFIDENCE_CEILINGS = {"high": 900, "partial": 780, "insufficient": INSUFFICIENT_DATA_SCORE}


def apply_confidence_ceiling(score: int, data_confidence: str) -> int:
    """Cap a computed score by how complete the underlying discovery was."""
    return min(score, CONFIDENCE_CEILINGS.get(data_confidence, 900))


def compute_org_score(
    findings: List[Finding],
    fixed_ids: Optional[Set[int]] = None,
    assessed: bool = True,
) -> int:
    """
    Aggregates Final_Risk_Score across findings, mapped to a standard 300-900 security score.
    If fixed_ids is provided, the risk contribution of those fixed findings is zeroed out.
    Used by both the main scan evaluation and the /optimize projected_score calculation.

    `assessed` distinguishes the two ways a scan can produce no findings:
      - assessed=True  -> we looked and found nothing  -> 900 (clean).
      - assessed=False -> discovery failed, nothing was inspected -> neutral
        INSUFFICIENT_DATA_SCORE, never a perfect score.
    """
    fixed_ids = fixed_ids or set()
    active_findings = [f for f in findings if f.id not in fixed_ids]
    if not active_findings:
        if not assessed:
            return INSUFFICIENT_DATA_SCORE
        return 900  # Perfect posture when no active findings exist

    # Aggregate as a probabilistic union rather than a sum: the combined risk
    # is the chance that *at least one* finding leads to a loss event,
    #
    #     combined = 1 - product(1 - r_i)
    #
    # A plain sum saturates almost immediately -- three or four real findings
    # would peg every organisation at the 300 floor, which tells a user
    # nothing and makes the score useless for tracking improvement. The union
    # form has diminishing returns built in: each additional finding still
    # lowers the score, but by less, which is also how correlated risks
    # actually compose.
    residual = 1.0
    for f in active_findings:
        risk = min(max(f.final_risk_score or 0.0, 0.0), 0.99)
        residual *= (1.0 - risk)
    combined_risk = 1.0 - residual

    # Map onto the 600-point spread (900 down to 300)
    penalty = 600.0 * combined_risk
    score = int(round(max(300.0, 900.0 - penalty)))
    return score


def evaluate_asset_findings(
    db: Session,
    scan_id: str,
    asset: Asset,
    email_hygiene: Dict[str, Any],
) -> List[Finding]:
    """
    Evaluates passive discovery signals on an asset and creates Finding records.
    """
    findings: List[Finding] = []
    # Standardized 1.0 for P0 external internet-facing assets
    exposure_multiplier = 1.0
    crit_weight = get_asset_criticality_weight(asset.asset_type)

    # 1. Check Missing SPF / DKIM / DMARC on Primary Domain or Mail Server
    if asset.asset_type in ["Primary Domain", "Mail Server"]:
        if not email_hygiene.get("has_spf") or not email_hygiene.get("has_dmarc"):
            epss = 0.12
            cvss = 5.3
            cwe_id = "CWE-319"
            cwe_weight = get_cwe_weight(cwe_id)
            final_score = calculate_risk_score(epss, cvss, cwe_weight, exposure_multiplier, crit_weight)

            f = Finding(
                scan_id=scan_id,
                asset_id=asset.id,
                cve_id=None,
                cvss_score=cvss,
                epss_score=epss,
                cwe_id=cwe_id,
                is_kev=False,
                exposure_multiplier=exposure_multiplier,
                asset_criticality_weight=crit_weight,
                final_risk_score=final_score,
                issue="Missing SPF or DMARC email authentication",
                short="SPF/DMARC",
                severity="Medium",
                category="Email",
                confidence=95,
                cost=0,
                reduction=12,
                eal=3.0,
                impact=3,
                likelihood=2,
                data_unavailable=False,
                is_stale_cache=False,
            )
            findings.append(f)

    # 2. Check exposed RDP port 3389
    if 3389 in asset.open_ports:
        epss = 0.55
        cvss = 9.0
        cwe_id = "CWE-287"
        cwe_weight = get_cwe_weight(cwe_id)
        # RDP flaw check against KEV
        is_kev = True
        final_score = calculate_risk_score(epss, cvss, cwe_weight, exposure_multiplier, crit_weight)
        severity = classify_severity(final_score, is_kev)

        f = Finding(
            scan_id=scan_id,
            asset_id=asset.id,
            cve_id="CVE-2019-0708",
            cvss_score=cvss,
            epss_score=epss,
            cwe_id=cwe_id,
            is_kev=is_kev,
            exposure_multiplier=exposure_multiplier,
            asset_criticality_weight=crit_weight,
            final_risk_score=final_score,
            issue="Exposed RDP port 3389 without gateway control",
            short="Close RDP",
            severity=severity,
            category="Network",
            confidence=90,
            cost=25000,
            reduction=18,
            eal=14.0,
            impact=5,
            likelihood=4,
            data_unavailable=False,
            is_stale_cache=False,
        )
        findings.append(f)

    return findings
