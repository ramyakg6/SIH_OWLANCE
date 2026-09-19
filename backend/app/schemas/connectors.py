"""Pydantic schemas for the /connectors endpoints"""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from app.schemas.findings import FindingResponse


class ConnectorStatus(BaseModel):
    source: str
    label: str
    connected: bool = True
    findings_count: int = 0


class ConnectorResponse(BaseModel):
    source: str
    label: str
    filename: str
    records: int = Field(..., description="Rows or amounts read from the upload")
    summary: str = Field(..., description="Human-readable result of the ingest")
    replaces_inference: Optional[str] = Field(
        None, description="Which external inference this source replaces with a confirmed fact"
    )
    metrics: Dict[str, Any] = Field(default_factory=dict)
    findings: List[FindingResponse] = Field(default_factory=list)
    persisted: bool = Field(False, description="Whether the result was attached to a scan")
    org_score: Optional[int] = Field(None, description="Recomputed organisation score, when persisted")
    reweighted_findings: int = Field(0, description="Existing findings re-weighted by CMDB criticality")
