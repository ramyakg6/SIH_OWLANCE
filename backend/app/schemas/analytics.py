"""Pydantic schemas for derived analytics"""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ControlResult(BaseModel):
    id: str
    name: str
    met: bool
    severity: Optional[str] = None
    reason: str


class FrameworkCoverage(BaseModel):
    name: str
    full_name: str
    coverage: int = Field(..., ge=0, le=100)
    controls_met: int
    controls_total: int
    controls: List[ControlResult] = Field(default_factory=list)


class AttackStep(BaseModel):
    title: str
    sub: str
    icon: str
    breakpoint: bool = False


class MitreTechnique(BaseModel):
    id: str
    name: str


class AttackPath(BaseModel):
    id: int
    label: str
    steps: List[AttackStep]
    eal: float
    mitre: List[MitreTechnique]
    fix: str
    fix_cost: int
    rosi: Optional[int] = None


class GraphNode(BaseModel):
    """One node in the attack graph. Findings carry their own economics."""
    id: str
    kind: str = Field(..., description="source | entry | pivot | target")
    label: str
    sub: str = ""
    icon: str = "Server"
    category: Optional[str] = None
    finding_id: Optional[int] = None
    severity: Optional[str] = None
    eal: float = 0.0
    cost: int = 0
    reduction: int = 0
    mitre_id: Optional[str] = None
    mitre_name: Optional[str] = None
    is_choke_point: bool = False
    severed_paths: int = Field(0, description="Paths cut by removing this node")
    severed_eal: float = Field(0.0, description="Expected loss cut by removing it")


class GraphEdge(BaseModel):
    source: str
    target: str


class GraphPath(BaseModel):
    id: int
    label: str
    node_ids: List[str]
    eal: float
    mitre: List[MitreTechnique]
    fix: str
    fix_cost: int
    rosi: Optional[int] = None
    breakpoint_node_id: Optional[str] = None


class ChokePoint(BaseModel):
    """The node whose removal severs the most expected loss."""
    node_id: str
    finding_id: Optional[int] = None
    label: str
    cost: int = 0
    severed_paths: int
    total_paths: int
    severed_eal: float


class AttackGraph(BaseModel):
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    paths: List[GraphPath] = Field(default_factory=list)
    choke_point: Optional[ChokePoint] = None


class CategoryRisk(BaseModel):
    category: str
    risk: int
    findings: int
    worst: Optional[str] = None


class InsuranceControl(BaseModel):
    id: str
    name: str
    state: str = Field(..., description="met | failing | unverified")
    met: bool
    reason: str


class InsuranceReadiness(BaseModel):
    readiness: int = Field(..., ge=0, le=100)
    controls_met: int
    controls_total: int
    controls: List[InsuranceControl] = Field(default_factory=list)


class CausalNode(BaseModel):
    id: str
    layer: int = Field(..., ge=0, le=6)
    label: str
    kind: Optional[str] = None
    severity: Optional[str] = None
    cve: Optional[str] = None
    kev: bool = False
    eal: Optional[float] = None
    critical: bool = False
    aggregate: bool = False
    count: Optional[int] = None


class CausalEdge(BaseModel):
    from_: str = Field(..., alias="from")
    to: str
    path: Optional[int] = None

    model_config = ConfigDict(populate_by_name=True)


class CausalPath(BaseModel):
    path: int
    label: str
    finding_id: Optional[int] = None
    finding: Optional[str] = None
    eal: float
    severity: Optional[str] = None
    fix: Optional[str] = None
    fix_cost: int = 0
    breakpoint: Optional[str] = None


class CausalGraphResponse(BaseModel):
    nodes: List[CausalNode] = Field(default_factory=list)
    edges: List[CausalEdge] = Field(default_factory=list)
    paths: List[CausalPath] = Field(default_factory=list)
    raw_findings: int = 0
    attack_paths: int = 0
    dominant_paths: int = 0
    total_eal: float = 0
    layers: List[str] = Field(default_factory=list)


class AnalyticsResponse(BaseModel):
    scan_id: str
    org_score: int
    compliance: List[FrameworkCoverage]
    attack_paths: List[AttackPath]
    attack_graph: AttackGraph = Field(default_factory=AttackGraph)
    category_risk: List[CategoryRisk]
    connected_sources: List[str] = Field(default_factory=list)
    insurance: InsuranceReadiness
    causal_graph: CausalGraphResponse
