from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class AssessmentCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_provider: str = "mock"
    target_model: Optional[str] = None
    target_config: Dict[str, Any] = Field(default_factory=dict)


class AssessmentSummaryResponse(BaseModel):
    total_attacks: int
    successful_attacks: int
    success_rate: float
    duration: float


class AssessmentResponse(BaseModel):
    id: str
    target_id: Optional[str] = None
    target_provider: Optional[str] = None
    target_model: Optional[str] = None
    target_config: Dict[str, Any] = Field(default_factory=dict)
    status: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    error_message: Optional[str] = None
    summary: Optional[AssessmentSummaryResponse] = None


class FindingEvidenceResponse(BaseModel):
    attempt_id: Optional[str] = None
    agent_name: str
    attack_type: str
    payload: str
    response_excerpt: str
    data_leaked: List[str] = Field(default_factory=list)
    timestamp: str


class FindingResponse(BaseModel):
    id: str
    title: str
    severity: Literal["critical", "high", "medium", "low"]
    category: str
    description: str
    evidence: List[FindingEvidenceResponse] = Field(default_factory=list)
    first_seen_at: str
    last_seen_at: str
    remediation: str
    rationale: str


class EvidenceAttemptResponse(BaseModel):
    id: Optional[str] = None
    agent_name: str
    attack_type: str
    payload: str
    response: str
    success: bool
    data_leaked: List[str] = Field(default_factory=list)
    timestamp: str
    response_metadata: Dict[str, Any] = Field(default_factory=dict)
    tool_trace: List[Dict[str, Any]] = Field(default_factory=list)
    evaluator: Dict[str, Any] = Field(default_factory=dict)


class EvidenceResponse(BaseModel):
    id: str
    target_id: Optional[str] = None
    target_provider: Optional[str] = None
    target_model: Optional[str] = None
    status: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    error_message: Optional[str] = None
    attempts: List[EvidenceAttemptResponse] = Field(default_factory=list)


class ReportResponse(BaseModel):
    id: str
    target_id: Optional[str] = None
    target_provider: Optional[str] = None
    target_model: Optional[str] = None
    target_config: Dict[str, Any] = Field(default_factory=dict)
    status: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    error_message: Optional[str] = None
    schema_version: int
    generated_at: str
    summary: AssessmentSummaryResponse
    attacks_by_type: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    leaked_data_types: List[str] = Field(default_factory=list)
    vulnerabilities: List[str] = Field(default_factory=list)
    findings: List[FindingResponse] = Field(default_factory=list)
    results: List[EvidenceAttemptResponse] = Field(default_factory=list)
    available_exports: List[str] = Field(default_factory=list)
