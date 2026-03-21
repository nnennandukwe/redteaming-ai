from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class TargetCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    target_type: Literal["vulnerable_llm_app"]
    provider: Optional[str] = None
    model: Optional[str] = None
    config: Dict[str, Any] = Field(default_factory=dict)


class TargetResponse(BaseModel):
    id: str
    name: str
    target_type: str
    provider: Optional[str] = None
    model: Optional[str] = None
    config: Dict[str, Any] = Field(default_factory=dict)
    created_at: str


class AssessmentCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: str


class AssessmentSummaryResponse(BaseModel):
    total_attacks: int
    successful_attacks: int
    success_rate: float
    duration: float


class AssessmentResponse(BaseModel):
    id: str
    target_id: Optional[str] = None
    target_name: Optional[str] = None
    target_type: Optional[str] = None
    target_provider: Optional[str] = None
    target_model: Optional[str] = None
    status: str
    queued_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    error_message: Optional[str] = None
    summary: Optional[AssessmentSummaryResponse] = None


class ReportResultResponse(BaseModel):
    agent_name: str
    attack_type: str
    payload: str
    success: bool
    data_leaked: List[str] = Field(default_factory=list)


class ReportResponse(BaseModel):
    id: str
    target_id: Optional[str] = None
    target_name: Optional[str] = None
    target_type: Optional[str] = None
    target_provider: Optional[str] = None
    target_model: Optional[str] = None
    status: str
    queued_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    error_message: Optional[str] = None
    summary: Dict[str, Any] = Field(default_factory=dict)
    attacks_by_type: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    leaked_data_types: List[str] = Field(default_factory=list)
    vulnerabilities: List[str] = Field(default_factory=list)
    results: List[ReportResultResponse] = Field(default_factory=list)


class EvidenceAttemptResponse(BaseModel):
    id: str
    agent_name: str
    attack_type: str
    payload: str
    response: str
    success: bool
    data_leaked: List[str] = Field(default_factory=list)
    timestamp: str


class EvidenceResponse(BaseModel):
    id: str
    target_id: Optional[str] = None
    status: str
    queued_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    error_message: Optional[str] = None
    attempts: List[EvidenceAttemptResponse] = Field(default_factory=list)
