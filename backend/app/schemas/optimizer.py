"""Pydantic schemas for /optimize"""
from typing import List, Optional
from pydantic import BaseModel, Field
from app.schemas.findings import FindingResponse


class OptimizeRequest(BaseModel):
    scan_id: str = Field(..., description="UUID of the scan run")
    budget: float = Field(..., ge=0, description="Remediation budget in ₹")


class OptimizeResponse(BaseModel):
    scan_id: str
    budget: float
    total_cost: int
    remaining_budget: float
    total_reduction: int = Field(..., description="Total risk reduction percentage")
    projected_score: int = Field(..., description="Projected org score (300-900) after applying selected fixes")
    selected_findings: List[FindingResponse]
