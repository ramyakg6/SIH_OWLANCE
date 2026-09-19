"""Tests for scan bounding, target prioritisation, and honest scoring.

These cover the failure modes that matter in a live demo: a domain whose
intel feeds are unreachable must not be reported as perfectly secure, and a
domain with hundreds of subdomains must not be able to stall the endpoint.
"""
import pytest

from app.services.dns_scanner import prioritise_targets
from app.services.scoring import (
    compute_org_score,
    apply_confidence_ceiling,
    INSUFFICIENT_DATA_SCORE,
)


# --------------------------------------------------------------------------
# Target prioritisation and capping
# --------------------------------------------------------------------------

def test_seed_domain_always_scanned_first():
    targets = prioritise_targets(
        "company.com", ["blog.company.com", "shop.company.com"], limit=3
    )
    assert targets[0] == "company.com"


def test_target_list_is_capped():
    many = [f"host{i}.company.com" for i in range(500)]
    targets = prioritise_targets("company.com", many, limit=25)
    assert len(targets) == 25


def test_interesting_hosts_survive_the_cap():
    """A cap is only safe if it keeps the hosts an attacker would target."""
    noise = [f"cdn{i}.company.com" for i in range(300)]
    juicy = ["vpn.company.com", "mail.company.com", "admin.company.com"]
    targets = prioritise_targets("company.com", noise + juicy, limit=10)
    for host in juicy:
        assert host in targets


def test_duplicates_and_case_are_collapsed():
    targets = prioritise_targets(
        "company.com",
        ["MAIL.company.com", "mail.company.com", "company.com"],
        limit=25,
    )
    assert targets.count("mail.company.com") == 1
    assert targets.count("company.com") == 1


# --------------------------------------------------------------------------
# Honest scoring: unknown is not the same as clean
# --------------------------------------------------------------------------

def test_unreachable_domain_is_not_scored_as_perfect():
    """The bug this guards: no findings because discovery failed != 900."""
    assert compute_org_score([], assessed=False) == INSUFFICIENT_DATA_SCORE
    assert compute_org_score([], assessed=False) != 900


def test_genuinely_clean_domain_still_scores_900():
    assert compute_org_score([], assessed=True) == 900


@pytest.mark.parametrize(
    "confidence,expected_max",
    [("high", 900), ("partial", 780), ("insufficient", INSUFFICIENT_DATA_SCORE)],
)
def test_confidence_ceiling_caps_incomplete_scans(confidence, expected_max):
    assert apply_confidence_ceiling(900, confidence) == expected_max


def test_ceiling_never_inflates_a_bad_score():
    assert apply_confidence_ceiling(410, "partial") == 410


# --------------------------------------------------------------------------
# Endpoint contract
# --------------------------------------------------------------------------

def test_optimize_returns_empty_plan_not_404(client):
    """A scan with nothing to fix is a valid outcome, not an error."""
    resp = client.post(
        "/optimize", json={"scan_id": "scan-with-no-findings", "budget": 15000}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["selected_findings"] == []
    assert body["total_cost"] == 0
    assert body["remaining_budget"] == 15000


def test_scan_response_exposes_confidence(client):
    resp = client.get("/scan/example.com")
    assert resp.status_code == 200
    body = resp.json()
    assert body["data_confidence"] in {"high", "partial", "insufficient"}
    assert isinstance(body["notes"], list)


def test_invalid_domain_is_rejected(client):
    assert client.get("/scan/not-a-domain").status_code == 400
