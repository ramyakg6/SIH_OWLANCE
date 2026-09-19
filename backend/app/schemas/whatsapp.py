"""Schemas for WhatsApp passport delivery."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class TopFix(BaseModel):
    name: str
    cost: Optional[int] = Field(None, description="Rupees; 0 means a free fix")
    reduction: Optional[int] = Field(None, description="Risk reduction, percent")


class FrameworkSummary(BaseModel):
    name: str
    coverage: int = Field(..., ge=0, le=100)


class PassportSnapshot(BaseModel):
    """
    The posture the dashboard is currently showing.

    Sent by the client rather than re-derived server-side, because the
    figures on screen include the user's live optimizer selection and
    revenue calibration. Every field is optional: a partial snapshot
    produces a shorter message instead of one padded with zeros.
    """
    domain: Optional[str] = None
    as_of: Optional[str] = None
    score: Optional[int] = Field(None, ge=0, le=900)
    confidence: Optional[int] = Field(None, ge=0, le=100)
    insurance_readiness: Optional[int] = Field(None, ge=0, le=100)
    median_eal: Optional[float] = Field(None, description="Lakhs")
    p90_eal: Optional[float] = Field(None, description="Lakhs")
    p99_eal: Optional[float] = Field(None, description="Lakhs")
    findings_summary: Dict[str, int] = Field(default_factory=dict)
    top_fixes: List[TopFix] = Field(default_factory=list)
    compliance: List[FrameworkSummary] = Field(default_factory=list)
    verification_hash: Optional[str] = None
    passport_url: Optional[str] = None


class SendPassportRequest(BaseModel):
    phone: str = Field(..., description="Recipient, any common format")
    snapshot: PassportSnapshot
    scan_id: Optional[str] = None


class SendPassportResponse(BaseModel):
    delivered: bool = Field(..., description="False when Twilio is unconfigured or rejected the send")
    configured: bool = Field(..., description="Whether Twilio credentials are present")
    status: str
    to: str = Field(..., description="Recipient, masked")
    body: str = Field(..., description="Exactly what was sent, or would be sent")
    message: str = Field(..., description="Plain-language outcome for the UI")
    sid: Optional[str] = None
    twilio_code: Optional[int] = None
    hint: Optional[str] = None


class WhatsAppStatusResponse(BaseModel):
    configured: bool
    account_sid_set: bool
    auth_token_set: bool
    sender_set: bool
    sender: Optional[str] = None
    mode: str = Field("freeform", description="'template' when TWILIO_CONTENT_SID is set, else 'freeform'")
    missing: List[str] = Field(default_factory=list)
    detail: str


class PreviewRequest(BaseModel):
    snapshot: PassportSnapshot


class PreviewResponse(BaseModel):
    body: str
    characters: int
    configured: bool


AnyDict = Dict[str, Any]
