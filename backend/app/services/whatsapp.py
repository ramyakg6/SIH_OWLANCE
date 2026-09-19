"""
WhatsApp delivery via the Twilio REST API.

Two things live here:

  compose_passport_message()  turns a posture snapshot into the plain-text
                              body an owner actually receives.
  send_whatsapp()             posts that body to Twilio.

Credentials come from .env (see TWILIO_* in config.py) and are never logged.
When they are absent the send is skipped rather than faked: the caller gets
delivered=False plus the composed body, so the UI can show the exact text
that would go out without claiming a message was delivered. That distinction
matters -- a demo that says "sent" when nothing was sent is the kind of
canned claim this platform is built to avoid.

Twilio's REST API is a form-encoded POST with HTTP basic auth, so httpx
(already a dependency) is enough and the `twilio` SDK is not needed.
"""
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

# Twilio caps a WhatsApp body at 1600 characters.
MAX_BODY_CHARS = 1600


# ---------------------------------------------------------------------------
# Phone numbers
# ---------------------------------------------------------------------------

def normalise_phone(raw: str) -> str:
    """
    Coerce user input into E.164 ("+919876543210").

    Accepts the forms people actually type: spaces, dashes, brackets, a
    leading 0, a bare 10-digit national number, or 00 international prefix.
    Raises ValueError when the result cannot be a real number, so the router
    can answer 400 instead of Twilio answering 400 later.
    """
    if not raw or not raw.strip():
        raise ValueError("Phone number is required")

    cleaned = re.sub(r"[\s\-()./]", "", raw.strip())
    cleaned = re.sub(r"^whatsapp:", "", cleaned, flags=re.IGNORECASE)

    if cleaned.startswith("00"):
        cleaned = "+" + cleaned[2:]

    if not cleaned.startswith("+"):
        # A leading zero is a national trunk prefix, not part of the number.
        cleaned = cleaned.lstrip("0")
        if not cleaned:
            raise ValueError("Phone number has no digits")
        cleaned = f"{settings.DEFAULT_PHONE_COUNTRY_CODE}{cleaned}"

    digits = cleaned[1:]
    if not digits.isdigit():
        raise ValueError("Phone number contains non-numeric characters")
    # E.164 allows at most 15 digits; below ~8 it cannot be a real number.
    if not 8 <= len(digits) <= 15:
        raise ValueError("Phone number must be between 8 and 15 digits")

    return f"+{digits}"


def mask_phone(e164: str) -> str:
    """Render a number for logs and audit entries without storing it whole."""
    if len(e164) <= 5:
        return "***"
    return f"{e164[:3]}{'*' * (len(e164) - 5)}{e164[-2:]}"


# ---------------------------------------------------------------------------
# Message composition
# ---------------------------------------------------------------------------

def _rupees(amount: float) -> str:
    """Indian-format a rupee amount: 2500000 -> '25,00,000'."""
    n = int(round(amount))
    sign = "-" if n < 0 else ""
    s = str(abs(n))
    if len(s) <= 3:
        return f"{sign}Rs {s}"
    head, tail = s[:-3], s[-3:]
    parts = []
    while len(head) > 2:
        parts.insert(0, head[-2:])
        head = head[:-2]
    if head:
        parts.insert(0, head)
    return f"{sign}Rs {','.join(parts)},{tail}"


def _lakhs(value: float) -> str:
    """Lakh figures read better than raw rupees for loss exposure."""
    if value >= 100:
        return f"Rs {value / 100:.2f} Cr"
    return f"Rs {value:.1f} L"


def _band(score: int) -> str:
    if score >= 750:
        return "Good"
    if score >= 600:
        return "Moderate"
    return "High Risk"


def compose_passport_message(snapshot: Dict[str, Any]) -> str:
    """
    Build the full-status WhatsApp body from a posture snapshot.

    Every section is omitted when the snapshot does not carry it, so a
    partial snapshot produces a shorter honest message rather than a
    padded one with zeros in it.
    """
    domain = snapshot.get("domain") or "your organisation"
    lines: List[str] = [f"*OwLance security status - {domain}*"]

    as_of = snapshot.get("as_of")
    if as_of:
        lines.append(f"_As of {as_of}_")
    lines.append("")

    # --- Score -------------------------------------------------------
    score = snapshot.get("score")
    if score is not None:
        score = int(score)
        line = f"*Risk score:* {score}/900 ({_band(score)})"
        confidence = snapshot.get("confidence")
        if confidence is not None:
            line += f"\nConfidence in this number: {int(confidence)}%"
        lines.append(line)

    readiness = snapshot.get("insurance_readiness")
    if readiness is not None:
        lines.append(f"*Insurance readiness:* {int(readiness)}% of the "
                     f"controls underwriters usually ask for")

    # --- Financial exposure ------------------------------------------
    median = snapshot.get("median_eal")
    if median is not None:
        exposure = [f"*Expected annual loss:* {_lakhs(float(median))} (median)"]
        p90, p99 = snapshot.get("p90_eal"), snapshot.get("p99_eal")
        if p90 is not None:
            exposure.append(f"  Bad year (P90): {_lakhs(float(p90))}")
        if p99 is not None:
            exposure.append(f"  Worst case (P99): {_lakhs(float(p99))}")
        lines.append("\n".join(exposure))

    # --- What is open -------------------------------------------------
    findings = snapshot.get("findings_summary") or {}
    if findings:
        counts = ", ".join(
            f"{v} {k.lower()}"
            for k, v in findings.items()
            if isinstance(v, int) and v > 0
        )
        if counts:
            lines.append(f"*Open issues:* {counts}")

    # --- What to do next ----------------------------------------------
    fixes = snapshot.get("top_fixes") or []
    if fixes:
        block = ["*What to fix first:*"]
        for i, fix in enumerate(fixes[:5], start=1):
            name = fix.get("name") or "Unnamed fix"
            cost = fix.get("cost")
            reduction = fix.get("reduction")
            bits = []
            if cost is not None:
                bits.append("free" if int(cost) == 0 else _rupees(cost))
            if reduction:
                bits.append(f"-{int(reduction)}% risk")
            suffix = f" ({', '.join(bits)})" if bits else ""
            block.append(f"{i}. {name}{suffix}")
        lines.append("\n".join(block))

    # --- Compliance ----------------------------------------------------
    compliance = snapshot.get("compliance") or []
    if compliance:
        summary = ", ".join(
            f"{c.get('name')} {int(c.get('coverage', 0))}%" for c in compliance[:5]
        )
        lines.append(f"*Framework coverage:* {summary}")

    # --- Provenance -----------------------------------------------------
    verification = snapshot.get("verification_hash")
    if verification:
        lines.append(f"*Verification:* {verification}\n"
                     f"_Hash-chained; tampering with the record breaks it._")

    link = snapshot.get("passport_url")
    if link:
        lines.append(f"Full passport: {link}")

    body = "\n\n".join(part for part in lines if part.strip())

    if len(body) > MAX_BODY_CHARS:
        body = body[: MAX_BODY_CHARS - 3].rstrip() + "..."
    return body


# ---------------------------------------------------------------------------
# Sender + template helpers
# ---------------------------------------------------------------------------

def _sender() -> str:
    """
    TWILIO_WHATSAPP_FROM as bare E.164.

    Tolerates a pasted "whatsapp:" prefix or stray spaces, either of which
    would otherwise become "whatsapp:whatsapp:+1..." and be rejected.
    """
    raw = (settings.TWILIO_WHATSAPP_FROM or "").strip()
    raw = re.sub(r"^whatsapp:", "", raw, flags=re.IGNORECASE)
    return raw.replace(" ", "")


def delivery_mode() -> str:
    """'template' when TWILIO_CONTENT_SID is set, otherwise 'freeform'."""
    return "template" if (settings.TWILIO_CONTENT_SID or "").strip() else "freeform"


_DEFAULT_TEMPLATE_VARS = {
    "1": "{domain}", "2": "{score}/900 ({band})", "3": "{passport_url}",
}


def _flatten(value: str) -> str:
    """
    WhatsApp rejects template variables containing newlines, tabs or long
    runs of spaces, and Twilio rejects empty ones. Collapse whitespace and
    substitute a dash for nothing.
    """
    return re.sub(r"\s+", " ", str(value)).strip() or "-"


def template_variables(snapshot: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """
    Build the ContentVariables map for a template send.

    TWILIO_CONTENT_VARIABLES maps each template slot to text containing
    {field} tokens. Unknown tokens become empty rather than raising, and a
    malformed JSON value falls back to the default three-slot mapping so a
    typo in .env degrades to a still-deliverable message.
    """
    snap = snapshot or {}
    score = snap.get("score")
    confidence = snap.get("confidence")
    fields = {
        "domain": snap.get("domain") or "your organisation",
        "as_of": snap.get("as_of") or "",
        "score": "" if score is None else str(int(score)),
        "band": "" if score is None else _band(int(score)),
        "confidence": "" if confidence is None else str(int(confidence)),
        "passport_url": snap.get("passport_url") or "",
    }

    try:
        spec = json.loads(settings.TWILIO_CONTENT_VARIABLES)
        if not isinstance(spec, dict) or not spec:
            raise ValueError("not a non-empty object")
    except ValueError:
        logger.warning("TWILIO_CONTENT_VARIABLES is not a valid JSON object; using defaults")
        spec = _DEFAULT_TEMPLATE_VARS

    def fill(text: str) -> str:
        return re.sub(r"\{(\w+)\}", lambda m: str(fields.get(m.group(1), "")), str(text))

    return {str(slot): _flatten(fill(text)) for slot, text in spec.items()}


def build_payload(
    to_e164: str, body: str, snapshot: Optional[Dict[str, Any]] = None
) -> Dict[str, str]:
    """
    The form fields for Twilio's Messages endpoint.

    Twilio treats Body and ContentSid as alternatives: a template send must
    not also carry Body, so the two branches never mix.
    """
    payload = {
        "From": f"whatsapp:{_sender()}",
        "To": f"whatsapp:{to_e164}",
    }
    if delivery_mode() == "template":
        payload["ContentSid"] = settings.TWILIO_CONTENT_SID.strip()
        payload["ContentVariables"] = json.dumps(template_variables(snapshot))
    else:
        payload["Body"] = body
    return payload


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------

def is_configured() -> bool:
    """True when all three Twilio values are present in the environment."""
    return bool(
        settings.TWILIO_ACCOUNT_SID
        and settings.TWILIO_AUTH_TOKEN
        and settings.TWILIO_WHATSAPP_FROM
    )


def configuration_status() -> Dict[str, Any]:
    """
    Report which credentials are set, without revealing them.

    Only the SID prefix and the sender number are echoed; the auth token is
    never returned in any form.
    """
    return {
        "configured": is_configured(),
        "account_sid_set": bool(settings.TWILIO_ACCOUNT_SID),
        "auth_token_set": bool(settings.TWILIO_AUTH_TOKEN),
        "sender_set": bool(settings.TWILIO_WHATSAPP_FROM),
        "sender": settings.TWILIO_WHATSAPP_FROM or None,
        "mode": delivery_mode(),
        "missing": [
            name for name, value in (
                ("TWILIO_ACCOUNT_SID", settings.TWILIO_ACCOUNT_SID),
                ("TWILIO_AUTH_TOKEN", settings.TWILIO_AUTH_TOKEN),
                ("TWILIO_WHATSAPP_FROM", settings.TWILIO_WHATSAPP_FROM),
            ) if not value
        ],
    }


def send_whatsapp(
    to_e164: str, body: str, snapshot: Optional[Dict[str, Any]] = None
) -> Tuple[bool, Dict[str, Any]]:
    """
    Send one WhatsApp message through Twilio.

    Returns (delivered, detail). delivered is False both when credentials are
    absent and when Twilio rejects the request; detail carries a
    human-readable `message` either way so the UI can say what happened
    instead of failing silently. Never raises on a transport error -- a demo
    should degrade to "not delivered", not to a 500.
    """
    if not is_configured():
        status = configuration_status()
        return False, {
            "status": "not_configured",
            "message": (
                "Twilio credentials are not set, so nothing was sent. "
                f"Add {', '.join(status['missing'])} to backend/.env."
            ),
            "missing": status["missing"],
        }

    url = f"{settings.TWILIO_API_BASE}/Accounts/{settings.TWILIO_ACCOUNT_SID}/Messages.json"
    payload = build_payload(to_e164, body, snapshot)

    try:
        response = httpx.post(
            url,
            data=payload,
            auth=(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN),
            timeout=settings.REQUEST_TIMEOUT,
        )
    except httpx.HTTPError as exc:
        logger.warning("Twilio request failed for %s: %s", mask_phone(to_e164), exc)
        return False, {
            "status": "transport_error",
            "message": f"Could not reach Twilio: {exc}",
        }

    if response.status_code in (200, 201):
        data = response.json()
        logger.info(
            "WhatsApp queued to %s (sid=%s)", mask_phone(to_e164), data.get("sid")
        )
        return True, {
            "status": data.get("status", "queued"),
            "sid": data.get("sid"),
            "message": f"WhatsApp message queued to {mask_phone(to_e164)}.",
        }

    # Twilio returns a structured error body; surface its own wording, which
    # is far more useful than a bare status code (e.g. "recipient has not
    # joined the sandbox").
    detail = f"HTTP {response.status_code}"
    twilio_code = None
    try:
        err = response.json()
        twilio_code = err.get("code")
        if err.get("message"):
            detail = err["message"]
    except ValueError:
        pass

    logger.warning(
        "Twilio rejected send to %s: %s (code=%s)",
        mask_phone(to_e164), detail, twilio_code,
    )
    return False, {
        "status": "rejected",
        "message": detail,
        "twilio_code": twilio_code,
        "hint": _hint_for(twilio_code, detail),
    }


_TRIAL_HINT = (
    "Twilio trial accounts can only message verified recipients, from the "
    "WhatsApp number Twilio assigned to you. Set TWILIO_WHATSAPP_FROM to the "
    "sender shown under Console > Messaging > Try it out > Send a WhatsApp "
    "message (not your personal number), and make sure the recipient is "
    "verified there and has joined."
)
_TEMPLATE_HINT = (
    "Twilio wants an approved message template here (trial accounts, and any "
    "chat outside the 24-hour window). Set TWILIO_CONTENT_SID in backend/.env "
    "to the template's HX... SID, or have the recipient WhatsApp the sandbox "
    "'join <code>' phrase first so a free-form message is allowed."
)

_HINTS_BY_CODE = {
    63007: "The From number is not a WhatsApp-enabled Twilio sender. "
           "Check TWILIO_WHATSAPP_FROM matches the sandbox number exactly.",
    63015: "The recipient has not joined your WhatsApp sandbox. They must "
           "WhatsApp the 'join <code>' phrase to the sandbox number once.",
    63016: "Outside the 24-hour session window, so a freeform message is "
           "blocked. The recipient must message you first, or set "
           "TWILIO_CONTENT_SID to send an approved template.",
    21211: "The To number is not valid E.164. Include the country code.",
    21608: _TRIAL_HINT,
    21654: _TEMPLATE_HINT,
    92005: _TEMPLATE_HINT,
    20003: "Authentication failed. Check TWILIO_ACCOUNT_SID and "
           "TWILIO_AUTH_TOKEN in backend/.env.",
}

# Some trial rejections arrive with a code this file does not know, so the
# wording is matched as a fallback. Order matters: first match wins.
_HINTS_BY_TEXT = (
    (("contentsid", "content sid", "content template"), _TEMPLATE_HINT),
    (("trial", "verified recipient", "unverified"), _TRIAL_HINT),
)


def _hint_for(code: Optional[int], message: str = "") -> Optional[str]:
    """Map a Twilio rejection to the next thing to check, by code then wording."""
    if code in _HINTS_BY_CODE:
        return _HINTS_BY_CODE[code]
    lowered = (message or "").lower()
    for needles, hint in _HINTS_BY_TEXT:
        if any(n in lowered for n in needles):
            return hint
    return None
