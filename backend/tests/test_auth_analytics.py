"""
Tests for authentication, the tamper-evident audit log, score history, and
the analytics derived from real findings.
"""
import pytest

from app.db.models import AuditEvent, Finding, Asset
from app.services.analytics import (
    compute_attack_paths,
    compute_category_risk,
    compute_compliance,
)
from app.services.auth import (
    create_access_token,
    decode_token,
    hash_password,
    password_problems,
    record_event,
    verify_chain,
    verify_password,
)


# --------------------------------------------------------------------------
# Passwords
# --------------------------------------------------------------------------

def test_password_hash_is_not_the_password():
    hashed = hash_password("owlance2026")
    assert hashed != "owlance2026"
    assert "owlance2026" not in hashed
    assert verify_password("owlance2026", hashed)


def test_wrong_password_is_rejected():
    assert not verify_password("wrong", hash_password("owlance2026"))


def test_same_password_hashes_differently_each_time():
    """Distinct salts, so identical passwords do not share a hash."""
    assert hash_password("owlance2026") != hash_password("owlance2026")


def test_overlong_password_is_rejected_not_truncated():
    """bcrypt silently ignores bytes past 72; two long passwords must not collide."""
    with pytest.raises(ValueError):
        hash_password("a" * 100)


def test_password_strength_rules():
    assert password_problems("owlance2026") == []
    assert "be at least 8 characters" in password_problems("ab1")
    assert "contain a number" in password_problems("abcdefgh")
    assert "contain a letter" in password_problems("12345678")


# --------------------------------------------------------------------------
# Tokens
# --------------------------------------------------------------------------

def test_token_round_trip(db_session):
    from app.db.models import User
    user = User(id=1, email="a@b.com", password_hash="x")
    token, expires_in = create_access_token(user)
    payload = decode_token(token)
    assert payload["sub"] == "1"
    assert payload["email"] == "a@b.com"
    assert expires_in > 0


def test_tampered_token_is_rejected():
    from app.db.models import User
    token, _ = create_access_token(User(id=1, email="a@b.com", password_hash="x"))
    assert decode_token(token[:-4] + "AAAA") is None
    assert decode_token("not-a-token") is None


# --------------------------------------------------------------------------
# Auth endpoints
# --------------------------------------------------------------------------

def test_register_then_login(client):
    reg = client.post("/auth/register", json={
        "email": "Founder@Example.com", "password": "owlance2026", "org_name": "Acme",
    })
    assert reg.status_code == 201
    assert reg.json()["user"]["email"] == "founder@example.com"  # normalised

    login = client.post("/auth/login", json={
        "email": "founder@example.com", "password": "owlance2026",
    })
    assert login.status_code == 200
    assert login.json()["access_token"]


def test_duplicate_registration_is_rejected(client):
    body = {"email": "dupe@example.com", "password": "owlance2026"}
    assert client.post("/auth/register", json=body).status_code == 201
    assert client.post("/auth/register", json=body).status_code == 409


def test_weak_password_gets_a_readable_message(client):
    resp = client.post("/auth/register", json={"email": "weak@example.com", "password": "abc"})
    assert resp.status_code == 422
    assert isinstance(resp.json()["detail"], str)
    assert "at least 8 characters" in resp.json()["detail"]


def test_login_does_not_reveal_whether_an_account_exists(client):
    client.post("/auth/register", json={"email": "known@example.com", "password": "owlance2026"})
    wrong_pw = client.post("/auth/login", json={"email": "known@example.com", "password": "nope12345"})
    no_account = client.post("/auth/login", json={"email": "ghost@example.com", "password": "nope12345"})
    assert wrong_pw.status_code == no_account.status_code == 401
    assert wrong_pw.json()["detail"] == no_account.json()["detail"]


def test_me_requires_a_token(client):
    assert client.get("/auth/me").status_code == 401


def test_me_returns_the_account_without_the_password_hash(client):
    token = client.post("/auth/register", json={
        "email": "me@example.com", "password": "owlance2026",
    }).json()["access_token"]
    body = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"}).json()
    assert body["email"] == "me@example.com"
    assert "password_hash" not in body
    assert "password" not in body


def test_scanning_works_without_signing_in(client):
    """The product must be visible before an account exists."""
    assert client.get("/scan/example.com").status_code == 200


# --------------------------------------------------------------------------
# Audit chain
# --------------------------------------------------------------------------

def test_chain_verifies_when_untouched(db_session):
    for i in range(5):
        record_event(db_session, action="test.event", detail=f"entry {i}")
    result = verify_chain(db_session)
    assert result["intact"] is True
    assert result["entries"] >= 5


def test_altering_an_entry_breaks_the_chain(db_session):
    """The whole point of the chain: edits do not go unnoticed."""
    for i in range(4):
        record_event(db_session, action="test.event", detail=f"entry {i}")

    victim = db_session.query(AuditEvent).order_by(AuditEvent.id.asc()).offset(1).first()
    victim.detail = "quietly rewritten"
    db_session.commit()

    result = verify_chain(db_session)
    assert result["intact"] is False
    assert result["broken_at_id"] == victim.id


def test_deleting_an_entry_breaks_the_chain(db_session):
    for i in range(4):
        record_event(db_session, action="test.event", detail=f"entry {i}")
    victim = db_session.query(AuditEvent).order_by(AuditEvent.id.asc()).offset(1).first()
    db_session.delete(victim)
    db_session.commit()
    assert verify_chain(db_session)["intact"] is False


def test_each_entry_links_to_the_previous(db_session):
    first = record_event(db_session, action="a", detail="1")
    second = record_event(db_session, action="b", detail="2")
    assert second.prev_hash == first.entry_hash
    assert second.entry_hash != first.entry_hash


def test_scan_appends_to_the_audit_log(client):
    scan = client.get("/scan/example.com").json()
    entries = client.get(f"/audit?scan_id={scan['scan_id']}").json()
    assert any(e["action"] == "scan.completed" for e in entries)


def test_audit_verify_endpoint(client):
    client.get("/scan/example.com")
    assert client.get("/audit/verify").json()["intact"] is True


# --------------------------------------------------------------------------
# History
# --------------------------------------------------------------------------

def test_history_is_empty_when_signed_out(client):
    client.get("/scan/example.com")
    assert client.get("/history").json() == []


def test_history_records_each_scan_for_the_account(client):
    token = client.post("/auth/register", json={
        "email": "hist@example.com", "password": "owlance2026",
    }).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    client.get("/scan/example.com", headers=headers)
    client.get("/scan/iana.org", headers=headers)

    history = client.get("/history", headers=headers).json()
    assert len(history) == 2
    assert {h["domain"] for h in history} == {"example.com", "iana.org"}
    assert all(300 <= h["org_score"] <= 900 for h in history)


def test_one_account_cannot_see_another_accounts_history(client):
    a = client.post("/auth/register", json={
        "email": "a@example.com", "password": "owlance2026"}).json()["access_token"]
    b = client.post("/auth/register", json={
        "email": "b@example.com", "password": "owlance2026"}).json()["access_token"]

    client.get("/scan/example.com", headers={"Authorization": f"Bearer {a}"})
    assert client.get("/history", headers={"Authorization": f"Bearer {b}"}).json() == []


# --------------------------------------------------------------------------
# Derived analytics
# --------------------------------------------------------------------------

def _finding(**kw):
    base = dict(
        id=1, scan_id="s", asset_id=1, category="Identity", severity="High",
        final_risk_score=0.2, eal=10.0, cost=0, reduction=30, short="Fix",
        issue="Issue", confidence=90, impact=4, likelihood=3,
    )
    base.update(kw)
    return Finding(**base)


def test_compliance_coverage_falls_when_findings_exist():
    clean = compute_compliance([], assets=[], connected_sources=["siem"])
    dirty = compute_compliance(
        [_finding(category="Identity"), _finding(id=2, category="Network")],
        assets=[], connected_sources=["siem"],
    )
    for a, b in zip(clean, dirty):
        assert b["coverage"] <= a["coverage"]


def test_monitoring_control_requires_a_log_source():
    without = compute_compliance([], assets=[], connected_sources=[])
    with_siem = compute_compliance([], assets=[], connected_sources=["siem"])
    assert with_siem[0]["coverage"] > without[0]["coverage"]


def test_compliance_reports_every_framework():
    names = {f["name"] for f in compute_compliance([], assets=[], connected_sources=[])}
    assert {"NIST CSF", "ISO 27001", "CIS Controls", "RBI Guidelines", "SEBI CSCRF"} <= names


def test_attack_path_marks_the_pivot_as_the_breakpoint():
    paths = compute_attack_paths([
        _finding(id=1, category="Web App", severity="Critical", eal=25.0, cost=8000, reduction=22),
        _finding(id=2, category="Identity", severity="High", eal=18.0, cost=0, reduction=35),
    ], assets=[])
    assert paths
    breakpoints = [s for s in paths[0]["steps"] if s["breakpoint"]]
    assert len(breakpoints) == 1
    assert paths[0]["fix_cost"] == 0  # the free identity fix severs the chain


def test_no_findings_means_no_attack_paths():
    assert compute_attack_paths([], assets=[]) == []


def test_attack_paths_are_ordered_by_expected_loss():
    paths = compute_attack_paths([
        _finding(id=1, category="Web App", eal=5.0),
        _finding(id=2, category="Network", eal=40.0),
        _finding(id=3, category="Email", eal=20.0),
    ], assets=[])
    assert paths == sorted(paths, key=lambda p: p["eal"], reverse=True)


def test_category_risk_is_zero_where_there_are_no_findings():
    risk = {r["category"]: r["risk"] for r in compute_category_risk([_finding(category="Identity")])}
    assert risk["Identity"] > 0
    assert risk["Cloud"] == 0
    assert risk["Email"] == 0


def test_analytics_endpoint_reflects_a_real_scan(client):
    scan = client.get("/scan/example.com").json()
    body = client.get(f"/analytics/{scan['scan_id']}").json()
    assert body["scan_id"] == scan["scan_id"]
    assert len(body["compliance"]) == 5
    assert all(0 <= f["coverage"] <= 100 for f in body["compliance"])


def test_analytics_404s_for_an_unknown_scan(client):
    assert client.get("/analytics/does-not-exist").status_code == 404


# --------------------------------------------------------------------------
# Insurance readiness
# --------------------------------------------------------------------------

def test_readiness_treats_unevidenced_controls_as_not_met():
    """An underwriter gives no credit for a control nobody can demonstrate."""
    from app.services.analytics import compute_insurance_readiness

    bare = compute_insurance_readiness([], assets=[], connected_sources=[])
    assert bare["readiness"] < 100
    assert any(c["state"] == "unverified" for c in bare["controls"])


def test_connecting_a_source_can_evidence_a_control():
    from app.services.analytics import compute_insurance_readiness

    without = compute_insurance_readiness([], assets=[], connected_sources=[])
    with_siem = compute_insurance_readiness([], assets=[], connected_sources=["siem"])
    assert with_siem["readiness"] > without["readiness"]


def test_a_connected_source_with_open_findings_does_not_count_as_met():
    """Connecting a source can reveal you fail the control, not pass it."""
    from app.services.analytics import compute_insurance_readiness

    result = compute_insurance_readiness(
        [_finding(category="Identity", severity="Critical")],
        assets=[],
        connected_sources=["identity"],
    )
    mfa = next(c for c in result["controls"] if c["id"] == "mfa")
    assert mfa["state"] == "failing"
    assert mfa["met"] is False


def test_readiness_is_exposed_on_the_analytics_endpoint(client):
    scan = client.get("/scan/example.com").json()
    body = client.get(f"/analytics/{scan['scan_id']}").json()
    assert 0 <= body["insurance"]["readiness"] <= 100
    assert body["insurance"]["controls_total"] == len(body["insurance"]["controls"])


# --------------------------------------------------------------------------
# Causal risk graph
# --------------------------------------------------------------------------

def test_causal_graph_is_empty_without_findings():
    from app.services.analytics import compute_causal_graph
    graph = compute_causal_graph([], assets=[])
    assert graph["nodes"] == []
    assert graph["edges"] == []
    assert graph["raw_findings"] == 0


def test_causal_graph_spans_every_layer():
    """A dominant path must reach from threat all the way to financial loss."""
    from app.services.analytics import compute_causal_graph
    graph = compute_causal_graph(
        [_finding(id=1, category="Identity", eal=18.0),
         _finding(id=2, category="Network", eal=25.0)],
        assets=[],
    )
    layers = {n["layer"] for n in graph["nodes"]}
    assert layers == {0, 1, 2, 3, 4, 5, 6}


def test_dominant_paths_are_capped_and_ranked_by_loss():
    from app.services.analytics import compute_causal_graph
    findings = [_finding(id=i, category="Network", eal=float(i)) for i in range(1, 9)]
    graph = compute_causal_graph(findings, assets=[])
    assert graph["dominant_paths"] == 4
    eals = [p["eal"] for p in graph["paths"]]
    assert eals == sorted(eals, reverse=True)


def test_remaining_findings_collapse_into_one_noise_node():
    """The whole point of the view: many findings, few paths that matter."""
    from app.services.analytics import compute_causal_graph
    findings = [_finding(id=i, category="Network", eal=float(i)) for i in range(1, 21)]
    graph = compute_causal_graph(findings, assets=[])
    aggregates = [n for n in graph["nodes"] if n.get("aggregate")]
    assert len(aggregates) == 1
    assert aggregates[0]["count"] == 16
    assert graph["raw_findings"] == 20


def test_same_asset_collapses_to_one_node():
    """Findings from different connectors on one host must not draw it twice."""
    from app.services.analytics import compute_causal_graph

    class FakeAsset:
        def __init__(self, id, name):
            self.id, self.asset_name, self.tech_stack = id, name, {}

    graph = compute_causal_graph(
        [_finding(id=1, asset_id=1, category="Identity", eal=10.0),
         _finding(id=2, asset_id=2, category="Cloud", eal=9.0)],
        assets=[FakeAsset(1, "portal.acme.com"), FakeAsset(2, "portal.acme.com")],
    )
    asset_nodes = [n for n in graph["nodes"] if n["layer"] == 2]
    assert len(asset_nodes) == 1


def test_identity_layer_only_implicates_privileged_accounts_when_relevant():
    from app.services.analytics import compute_causal_graph
    email_only = compute_causal_graph([_finding(id=1, category="Email", eal=5.0)], assets=[])
    labels = {n["label"] for n in email_only["nodes"] if n["layer"] == 3}
    assert labels == {"Standard Users"}

    identity = compute_causal_graph([_finding(id=1, category="Identity", eal=5.0)], assets=[])
    labels = {n["label"] for n in identity["nodes"] if n["layer"] == 3}
    assert labels == {"Privileged Accounts"}


def test_causal_graph_is_exposed_on_the_analytics_endpoint(client):
    scan = client.get("/scan/example.com").json()
    graph = client.get(f"/analytics/{scan['scan_id']}").json()["causal_graph"]
    assert len(graph["layers"]) == 7
    assert all("from" in e and "to" in e for e in graph["edges"])
