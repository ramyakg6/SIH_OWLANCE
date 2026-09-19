"""Pydantic schemas for findings and risk metrics"""
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict


class FindingResponse(BaseModel):
    id: int
    scan_id: str
    asset_id: int
    asset: Optional[str] = Field(None, description="Asset hostname e.g. mail.company.com")
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    is_kev: bool = False
    exposure_multiplier: float = 1.0
    asset_criticality_weight: float = 1.0
    final_risk_score: float

    # UI presentation fields (matching OwLance.jsx FINDINGS shape)
    issue: str
    short: str
    severity: str  # Critical, High, Medium, Low
    category: str  # Email, Web App, Network, Identity, Cloud
    confidence: int  # 0-100
    cost: int  # in ₹
    reduction: int  # %
    eal: float  # Lakhs
    impact: int  # 1-5
    likelihood: int  # 1-5

    # Resilience metadata
    data_unavailable: bool = False
    is_stale_cache: bool = False

    model_config = ConfigDict(from_attributes=True)
