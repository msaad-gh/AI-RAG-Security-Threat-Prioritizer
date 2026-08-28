"""Incident schemas for ThreatIQ correlated alert groups."""

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel

from backend.models.event import NormalizedEvent


class IncidentStatus(str, Enum):
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    ESCALATED = "escalated"
    RESOLVED = "resolved"


class IncidentSummary(BaseModel):
    """High-level view of a correlated incident."""

    id: str
    created_at: datetime
    status: IncidentStatus
    asset: str
    asset_criticality: str
    total_score: int
    severity_label: str
    mitre_technique: Optional[str]
    latest_event_time: datetime
    events_count: int
    confidence: str


class IncidentDetail(IncidentSummary):
    """Full incident payload with events, scoring, RAG, and LLM context."""

    events: List[NormalizedEvent]
    score_factors: Optional[dict]
    rag_results: List[dict]
    llm_explanation: Optional[dict]
    analyst_actions: List[dict]
