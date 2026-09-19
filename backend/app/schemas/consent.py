"""Pydantic schemas for /consent"""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, field_validator, ConfigDict
import re


class ConsentCreate(BaseModel):
    domain: str = Field(..., description="Target root domain e.g. company.com")
    requester_ip: Optional[str] = Field(None, description="IP address of requester (auto-detected if omitted)")
    timestamp: Optional[datetime] = Field(None, description="Timestamp of consent (defaults to server now)")
    consent_version: str = Field("1.0", description="Version of the consent agreement terms")
    active_scan_allowed: bool = Field(False, description="Whether active probing is explicitly authorized")

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        domain = v.strip().lower()
        # Strip protocol if user pasted http(s)://
        domain = re.sub(r"^https?://", "", domain)
        domain = domain.split("/")[0].split(":")[0]
        if not domain or "." not in domain or len(domain) > 253:
            raise ValueError("Invalid domain name format")
        return domain


class ConsentResponse(BaseModel):
    id: int
    domain: str
    requester_ip: Optional[str]
    timestamp: datetime
    consent_version: str
    active_scan_allowed: bool

    model_config = ConfigDict(from_attributes=True)
