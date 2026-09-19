"""Pydantic schemas for /scan/{domain} and asset models"""
from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict
from app.schemas.findings import FindingResponse


class AssetResponse(BaseModel):
    id: int
    scan_id: str
    domain: str
    asset_name: str
    asset_type: str
    discovery_method: str
    discovered_at: datetime
    tech_stack: Dict[str, Any] = Field(default_factory=dict)
    open_ports: List[int] = Field(default_factory=list)
    status: str  # monitored, unverified, unmonitored
    discovery_confidence: float  # 0.0 to 1.0
    risk: Optional[str] = "Low"  # Derived from findings on this asset: Critical, High, Medium, Low

    model_config = ConfigDict(from_attributes=True)


class ScanResponse(BaseModel):
    scan_id: str
    domain: str
    scanned_at: datetime
    org_score: int = Field(..., description="Organization security score between 300 and 900")
    assets_count: int
    findings_count: int
    assets: List[AssetResponse]
    findings: List[FindingResponse]
    cached: bool = False
    data_confidence: str = Field(
        "high",
        description="high | partial | insufficient - how much of the scan rested on live intel",
    )
    notes: List[str] = Field(
        default_factory=list,
        description="Human-readable caveats, e.g. a feed being unreachable",
    )
