"""Pydantic schemas for authentication, history, and the audit log"""
from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr
    # Deliberately no min_length here: the router's password_problems() check
    # produces a single readable sentence ("Password must be at least 8
    # characters, contain a number."), whereas a schema constraint returns
    # Pydantic's raw error array, which is not a message a user should see.
    password: str = Field(..., max_length=128)
    org_name: Optional[str] = Field(None, max_length=255)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=128)


class UserResponse(BaseModel):
    id: int
    email: str
    org_name: Optional[str] = None
    created_at: datetime
    last_login_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = Field(..., description="Token lifetime in seconds")
    user: UserResponse


class ScanHistoryEntry(BaseModel):
    scan_id: str
    domain: str
    org_score: int
    findings_count: int
    assets_count: int
    data_confidence: str
    scanned_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AuditEntry(BaseModel):
    id: int
    action: str
    detail: str
    meta: Dict[str, Any] = Field(default_factory=dict)
    scan_id: Optional[str] = None
    timestamp: datetime
    entry_hash: str

    model_config = ConfigDict(from_attributes=True)


class AuditVerification(BaseModel):
    intact: bool
    entries: int
    broken_at_id: Optional[int] = None
    detail: str
    head_hash: Optional[str] = None
