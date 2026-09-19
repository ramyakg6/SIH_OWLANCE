"""
Tests for the attack graph and WhatsApp passport delivery.

The graph tests exist to pin down the one property that matters: the choke
point is *computed* from the findings present, not assumed. If someone later
reintroduces a hardcoded "MFA is always the breakpoint", these fail.
"""
import json

import pytest

from app.db.models import Finding
from app.services.analytics import compute_attack_graph, compute_attack_paths
from app.services.whatsapp import (
    _hint_for,
    build_payload,
    compose_passport_message,
    mask_phone,
    normalise_phone,
    send_whatsapp,
    template_variables,
)


def _finding(**kw):
    base = dict(
        id=1, scan_id="scan", asset_id=1, category="Network", severity="High",
        final_risk_score=0.2, eal=10.0, cost=0, reduction=30, short="Fix",
        issue="Issue", confidence=90, impact=4, likelihood=3, cve_id=None,
    )
    base.update(kw)
    return Finding(**base)


# ---------------------------------------------------------------------------
# Attack graph
# ---------------------------------------------------------------------------

def test_empty_findings_produce_an_empty_graph():
    graph = compute_attack_graph([], assets=[])
    assert graph == {"nodes": [], "edges": [], "paths": [], "choke_point": None}


def test_entries_converge_on_a_shared_pivot():
    """Two entries plus one pivot is a converging graph, not two parallel lines."""
    graph = compute_attack_graph([
        _finding(id=1, category="Web App", short="CMS Patch", eal=25.0, cost=8000),
        _finding(id=2, category="Network", short="Close RDP", eal=14.0, cost=25000),
        _finding(id=3, category="Identity", short="Enable MFA", eal=18.0, cost=0),
    ], assets=[])

    pivot_id = "f:3"
    inbound = [e for e in graph["edges"] if e["target"] == pivot_id]
    assert len(inbound) == 2, "both entries should reach the shared pivot"
    assert all(p["node_ids"][2] == pivot_id for p in graph["paths"])


def test_choke_point_is_the_node_severing_the_most_loss():
    graph = compute_attack_graph([
        _finding(id=1, category="Web App", short="CMS Patch", eal=25.0, cost=8000),
        _finding(id=2, category="Network", short="Close RDP", eal=14.0, cost=25000),
        _finding(id=3, category="Identity", short="Enable MFA", eal=18.0, cost=0),
    ], assets=[])

    choke = graph["choke_point"]
    assert choke["label"] == "Enable MFA"
    assert choke["severed_paths"] == choke["total_paths"] == 2
    assert choke["severed_eal"] > 0


def test_choke_point_moves_when_the_pivot_is_gone():
    """
    The breakpoint must follow the data. With the identity finding resolved,
    a different node has to become the choke point.
    """
    graph = compute_attack_graph([
        _finding(id=1, category="Web App", short="CMS Patch", eal=25.0, cost=8000),
        _finding(id=2, category="Network", short="Close RDP", eal=14.0, cost=25000),
    ], assets=[])

    assert graph["choke_point"]["label"] != "Enable MFA"
    assert graph["choke_point"]["severed_paths"] == 1


def test_severed_totals_are_recorded_on_every_finding_node():
    graph = compute_attack_graph([
        _finding(id=1, category="Web App", eal=25.0),
        _finding(id=3, category="Identity", eal=18.0, cost=0),
    ], assets=[])
    findings_nodes = [n for n in graph["nodes"] if n["kind"] in ("entry", "pivot")]
    assert findings_nodes
    assert all(n["severed_paths"] >= 1 for n in findings_nodes)
    assert sum(1 for n in graph["nodes"] if n["is_choke_point"]) == 1


def test_identity_only_findings_still_produce_a_path():
    """Credential attacks need no external foothold, so a pivot can start a path."""
    graph = compute_attack_graph([
        _finding(id=9, category="Identity", short="Enable MFA", eal=18.0, cost=0),
    ], assets=[])
    assert len(graph["paths"]) == 1
    assert graph["paths"][0]["fix"] == "Enable MFA"


def test_every_path_carries_exactly_one_breakpoint():
    paths = compute_attack_paths([
        _finding(id=1, category="Web App", eal=25.0, cost=8000),
        _finding(id=2, category="Network", eal=14.0, cost=25000),
        _finding(id=3, category="Identity", eal=18.0, cost=0),
    ], assets=[])
    for path in paths:
        assert sum(1 for s in path["steps"] if s["breakpoint"]) == 1


def test_path_list_and_graph_agree():
    findings = [
        _finding(id=1, category="Web App", eal=25.0, cost=8000),
        _finding(id=3, category="Identity", eal=18.0, cost=0),
    ]
    graph = compute_attack_graph(findings, assets=[])
    paths = compute_attack_paths(findings, assets=[])
    assert [p["eal"] for p in paths] == [p["eal"] for p in graph["paths"]]
    assert [p["fix"] for p in paths] == [p["fix"] for p in graph["paths"]]


def test_free_fix_reports_no_rosi_rather_than_dividing_by_zero():
    paths = compute_attack_paths([
        _finding(id=1, category="Web App", eal=25.0, cost=8000),
        _finding(id=3, category="Identity", eal=18.0, cost=0),
    ], assets=[])
    free = [p for p in paths if p["fix_cost"] == 0]
    assert free and all(p["rosi"] is None for p in free)


def test_analytics_endpoint_returns_a_graph(client):
    scan = client.get("/scan/example.com").json()
    body = client.get(f"/analytics/{scan['scan_id']}").json()
    assert "attack_graph" in body
    graph = body["attack_graph"]
    assert set(graph) >= {"nodes", "edges", "paths", "choke_point"}
    node_ids = {n["id"] for n in graph["nodes"]}
    for edge in graph["edges"]:
        assert edge["source"] in node_ids and edge["target"] in node_ids
    for path in graph["paths"]:
        assert all(n in node_ids for n in path["node_ids"])


# ---------------------------------------------------------------------------
# Phone handling
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("9876543210", "+919876543210"),
    ("+91 98765 43210", "+919876543210"),
    ("098765-43210", "+919876543210"),
    ("0091 9876543210", "+919876543210"),
    ("whatsapp:+919876543210", "+919876543210"),
    ("+1 (415) 523-8886", "+14155238886"),
])
def test_phone_numbers_normalise_to_e164(raw, expected):
    assert normalise_phone(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "abcd", "12", "+" + "9" * 20])
def test_unusable_phone_numbers_are_rejected(raw):
    with pytest.raises(ValueError):
        normalise_phone(raw)


def test_masked_phone_hides_the_subscriber_digits():
    masked = mask_phone("+919876543210")
    assert "98765432" not in masked
    assert masked.endswith("10")


# ---------------------------------------------------------------------------
# Message composition
# ---------------------------------------------------------------------------

def test_message_contains_the_whole_posture():
    body = compose_passport_message({
        "domain": "acmesteel.in", "score": 662, "confidence": 84,
        "insurance_readiness": 78, "median_eal": 7.0, "p90_eal": 21.4, "p99_eal": 48.9,
        "findings_summary": {"Critical": 1, "High": 2},
        "top_fixes": [{"name": "Enable MFA", "cost": 0, "reduction": 35}],
        "compliance": [{"name": "NIST CSF", "coverage": 71}],
        "passport_url": "https://owlance.in/p/acmesteel",
    })
    for fragment in ["acmesteel.in", "662/900", "Moderate", "84%", "78%",
                     "Enable MFA", "free", "NIST CSF 71%", "owlance.in/p/acmesteel"]:
        assert fragment in body


def test_partial_snapshot_omits_sections_rather_than_inventing_zeros():
    body = compose_passport_message({"domain": "acme.in", "score": 800})
    assert "800/900" in body and "Good" in body
    assert "Expected annual loss" not in body
    assert "What to fix first" not in body


def test_message_stays_within_the_whatsapp_limit():
    body = compose_passport_message({
        "domain": "x.in", "score": 500,
        "top_fixes": [{"name": "Fix " + "y" * 200, "cost": 1} for _ in range(40)],
    })
    assert len(body) <= 1600


def test_score_bands_match_the_dashboard():
    assert "Good" in compose_passport_message({"score": 800})
    assert "Moderate" in compose_passport_message({"score": 650})
    assert "High Risk" in compose_passport_message({"score": 450})


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

def test_status_reports_which_variables_are_missing(client):
    body = client.get("/whatsapp/status").json()
    assert body["configured"] is False
    # Naming the variable to set is the point of the endpoint.
    assert "TWILIO_ACCOUNT_SID" in body["missing"]
    assert "backend/.env" in body["detail"]


def test_status_never_returns_the_auth_token_value(monkeypatch, client):
    """Credentials may be echoed by name, never by value."""
    from app.config import settings
    monkeypatch.setattr(settings, "TWILIO_ACCOUNT_SID", "ACfake000000000000000000000000001")
    monkeypatch.setattr(settings, "TWILIO_AUTH_TOKEN", "super-secret-token-value")
    monkeypatch.setattr(settings, "TWILIO_WHATSAPP_FROM", "+14155238886")

    body = client.get("/whatsapp/status").json()
    assert body["configured"] is True
    assert "super-secret-token-value" not in str(body)
    assert "ACfake000000000000000000000000001" not in str(body)
    assert body["sender"] == "+14155238886"


def test_preview_composes_without_sending(client):
    body = client.post("/whatsapp/preview", json={
        "snapshot": {"domain": "acme.in", "score": 640},
    }).json()
    assert "640/900" in body["body"]
    assert body["characters"] == len(body["body"])


def test_send_without_credentials_returns_a_preview_not_a_false_success(client):
    body = client.post("/whatsapp/send-passport", json={
        "phone": "9876543210",
        "snapshot": {"domain": "acme.in", "score": 640},
    }).json()
    assert body["delivered"] is False
    assert body["configured"] is False
    assert body["status"] == "not_configured"
    assert "640/900" in body["body"]
    assert "+91********10" == body["to"]


def test_send_rejects_an_unusable_number(client):
    res = client.post("/whatsapp/send-passport", json={
        "phone": "abc", "snapshot": {"score": 600},
    })
    assert res.status_code == 400


def test_send_is_recorded_in_the_audit_chain(client):
    client.post("/whatsapp/send-passport", json={
        "phone": "9876543210", "snapshot": {"domain": "acme.in", "score": 640},
    })
    entries = client.get("/audit?limit=20").json()
    actions = [e["action"] for e in entries]
    assert "passport.whatsapp_send" in actions
    logged = [e for e in entries if e["action"] == "passport.whatsapp_send"][0]
    assert "9876543210" not in str(logged), "the raw number must never be stored"


# ---------------------------------------------------------------------------
# Delivery: sender, template vs free-form, and error hints
# ---------------------------------------------------------------------------

@pytest.fixture
def twilio_creds(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "TWILIO_ACCOUNT_SID", "ACfake000000000000000000000000001")
    monkeypatch.setattr(settings, "TWILIO_AUTH_TOKEN", "fake-token")
    monkeypatch.setattr(settings, "TWILIO_WHATSAPP_FROM", "+14155238886")
    return settings


class _FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


def test_freeform_payload_carries_body_and_no_content_sid(twilio_creds):
    payload = build_payload("+919876543210", "hello")
    assert payload["Body"] == "hello"
    assert "ContentSid" not in payload and "ContentVariables" not in payload
    assert payload["From"] == "whatsapp:+14155238886"
    assert payload["To"] == "whatsapp:+919876543210"


def test_template_payload_replaces_body_with_content_sid(twilio_creds, monkeypatch):
    """Twilio forbids Body alongside ContentSid, so the two must never mix."""
    monkeypatch.setattr(twilio_creds, "TWILIO_CONTENT_SID", "HX" + "a" * 32)
    payload = build_payload(
        "+919876543210", "long body",
        {"domain": "acme.in", "score": 640, "passport_url": "https://owlance.in/p/acme"},
    )
    assert payload["ContentSid"] == "HX" + "a" * 32
    assert "Body" not in payload
    assert json.loads(payload["ContentVariables"]) == {
        "1": "acme.in", "2": "640/900 (Moderate)", "3": "https://owlance.in/p/acme",
    }


def test_template_variables_are_never_empty_or_multiline(twilio_creds, monkeypatch):
    monkeypatch.setattr(twilio_creds, "TWILIO_CONTENT_VARIABLES",
                        '{"1": "{domain}", "2": "{confidence}", "3": "a\\n\\nb"}')
    values = template_variables({"domain": "acme.in"})   # no confidence
    assert values["2"] == "-"
    assert "\n" not in values["3"]


def test_malformed_content_variables_fall_back_to_defaults(twilio_creds, monkeypatch):
    monkeypatch.setattr(twilio_creds, "TWILIO_CONTENT_VARIABLES", "{not json")
    assert set(template_variables({"domain": "acme.in", "score": 800})) == {"1", "2", "3"}


def test_pasted_whatsapp_prefix_on_the_sender_is_not_doubled(twilio_creds, monkeypatch):
    monkeypatch.setattr(twilio_creds, "TWILIO_WHATSAPP_FROM", " whatsapp:+14155238886 ")
    assert build_payload("+919876543210", "x")["From"] == "whatsapp:+14155238886"


def test_send_posts_the_template_fields_to_twilio(twilio_creds, monkeypatch):
    monkeypatch.setattr(twilio_creds, "TWILIO_CONTENT_SID", "HX" + "b" * 32)
    seen = {}

    def fake_post(url, data, auth, timeout):
        seen.update(url=url, data=data)
        return _FakeResponse(201, {"sid": "SM1", "status": "queued"})

    monkeypatch.setattr("app.services.whatsapp.httpx.post", fake_post)
    delivered, detail = send_whatsapp("+919876543210", "ignored", {"domain": "acme.in", "score": 500})
    assert delivered is True and detail["sid"] == "SM1"
    assert seen["data"]["ContentSid"] == "HX" + "b" * 32
    assert "Body" not in seen["data"]


@pytest.mark.parametrize("code,message,expected", [
    (21608, "", "verified"),
    (None, "No Twilio trial phone number is assigned for messaging to this destination "
           "number. Please add the 'to' number as a verified recipient.", "TWILIO_WHATSAPP_FROM"),
    (92005, "", "TWILIO_CONTENT_SID"),
    (None, "ContentSid Required", "TWILIO_CONTENT_SID"),
    (63016, "", "TWILIO_CONTENT_SID"),
    (63015, "", "join"),
])
def test_known_rejections_get_an_actionable_hint(code, message, expected):
    assert expected in _hint_for(code, message)


def test_unknown_rejection_gets_no_invented_hint():
    assert _hint_for(99999, "something unrelated") is None


def test_rejected_send_surfaces_twilios_wording_and_a_hint(twilio_creds, monkeypatch):
    monkeypatch.setattr(
        "app.services.whatsapp.httpx.post",
        lambda *a, **k: _FakeResponse(400, {"code": 21608, "message": "unverified"}),
    )
    delivered, detail = send_whatsapp("+919876543210", "hi")
    assert delivered is False
    assert detail["status"] == "rejected" and detail["twilio_code"] == 21608
    assert detail["hint"]


def test_status_reports_delivery_mode(twilio_creds, monkeypatch, client):
    assert client.get("/whatsapp/status").json()["mode"] == "freeform"
    monkeypatch.setattr(twilio_creds, "TWILIO_CONTENT_SID", "HX" + "c" * 32)
    body = client.get("/whatsapp/status").json()
    assert body["mode"] == "template"
    assert "HX" + "c" * 32 not in str(body)
