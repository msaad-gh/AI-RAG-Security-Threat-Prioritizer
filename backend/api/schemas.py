from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict
from enum import Enum

class EventTypeEnum(str, Enum):
    NETWORK_SCAN = "network_scan"
    MALWARE_DETECTED = "malware_detected"
    PHISHING_ATTEMPT = "phishing_attempt"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    COMMAND_CONTROL = "command_control"
    INITIAL_ACCESS = "initial_access"
    PERSISTENCE = "persistence"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    COLLECTION = "collection"
    IMPACT = "impact"
    UNKNOWN = "unknown"

class RiskLevelEnum(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class IncidentStatusEnum(str, Enum):
    NEW = "new"
    TRIAGING = "triaging"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"

class SecurityEventBase(BaseModel):
    event_type: EventTypeEnum = EventTypeEnum.UNKNOWN
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    process_name: Optional[str] = None
    file_hash: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    description: Optional[str] = None
    raw_event: Optional[Dict[str, Any]] = None
    base_severity: float = Field(ge=0.0, le=10.0, default=0.0)

class SecurityEventCreate(SecurityEventBase):
    event_id: Optional[str] = None
    timestamp: Optional[datetime] = None

class SecurityEventResponse(SecurityEventBase):
    id: int
    event_id: str
    timestamp: datetime
    anomaly_score: float = 0.0
    correlation_score: float = 0.0
    incident_id: Optional[int] = None
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)

class RiskScoreFactors(BaseModel):
    threat_severity_score: float = Field(ge=0.0, le=10.0)
    asset_criticality_score: float = Field(ge=0.0, le=10.0)
    attack_sophistication_score: float = Field(ge=0.0, le=10.0)
    confidence_score: float = Field(ge=0.0, le=10.0)
    exposure_score: float = Field(ge=0.0, le=10.0)
    temporal_score: float = Field(ge=0.0, le=10.0)
    mitigation_score: float = Field(ge=0.0, le=10.0)

class IncidentCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=512)
    description: Optional[str] = None

class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[IncidentStatusEnum] = None
    assigned_to: Optional[str] = None
    human_review_notes: Optional[str] = None

class AnalystActionRequest(BaseModel):
    action_type: str
    action_description: str
    target: str
    requires_approval: bool = True

class AnalystActionResponse(BaseModel):
    id: int
    incident_id: int
    action_type: str
    action_description: str
    target: str
    status: str
    requires_approval: bool
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)

class IncidentResponse(BaseModel):
    id: int
    incident_id: str
    title: str
    description: Optional[str] = None
    status: IncidentStatusEnum
    assigned_to: Optional[str] = None
    risk_factors: RiskScoreFactors
    overall_risk_score: float = Field(ge=0.0, le=100.0)
    risk_level: RiskLevelEnum
    mitre_tactics: Optional[List[str]] = None
    mitre_techniques: Optional[List[str]] = None
    cve_ids: Optional[List[str]] = None
    llm_explanation: Optional[str] = None
    llm_summary: Optional[str] = None
    llm_recommendations: Optional[List[str]] = None
    human_reviewed: bool = False
    human_review_notes: Optional[str] = None
    detected_at: datetime
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None
    event_count: int = 0
    actions: List[AnalystActionResponse] = []
    model_config = ConfigDict(from_attributes=True)

class DashboardStats(BaseModel):
    total_incidents: int
    critical_incidents: int
    high_incidents: int
    medium_incidents: int
    low_incidents: int
    new_incidents_24h: int
    resolved_incidents_24h: int
    avg_resolution_time_hours: Optional[float] = None
    total_events_24h: int
    unique_attackers_24h: int

class IncidentListItem(BaseModel):
    id: int
    incident_id: str
    title: str
    risk_level: RiskLevelEnum
    overall_risk_score: float
    status: IncidentStatusEnum
    event_count: int
    detected_at: datetime
    mitre_tactics: Optional[List[str]] = None

class IncidentListResponse(BaseModel):
    incidents: List[IncidentListItem]
    total: int
    page: int
    page_size: int
    total_pages: int

class RAGResult(BaseModel):
    id: int
    title: str
    content: str
    content_type: str
    mitre_id: Optional[str] = None
    cve_id: Optional[str] = None
    source: Optional[str] = None
    url: Optional[str] = None
    relevance_score: float

class RAGQueryRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=1024)
    top_k: int = Field(default=5, ge=1, le=20)
    include_mitre: bool = True
    include_cve: bool = True

class RAGQueryResponse(BaseModel):
    query: str
    results: List[RAGResult]
    total_results: int
    query_time_ms: float

class AnomalyScoreRequest(BaseModel):
    events: List[SecurityEventCreate]

class AnomalyScoreResponse(BaseModel):
    scores: List[float]
    threshold: float
    anomalies: List[int]

class HealthResponse(BaseModel):
    status: str
    version: str
    database: str
    llm_configured: bool
    rag_configured: bool
    demo_mode: bool

class ConfigResponse(BaseModel):
    demo_mode: bool
    llm_provider: str
    llm_model: str
    rag_enabled: bool
    anomaly_detection_enabled: bool
    max_events_per_incident: int