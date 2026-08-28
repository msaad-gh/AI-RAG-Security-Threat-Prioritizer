from datetime import datetime
from typing import Optional, List, Dict, Any
from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Text, ForeignKey, JSON, Enum as SQLEnum
from sqlalchemy.orm import relationship, declarative_base
import enum

Base = declarative_base()

class EventType(str, enum.Enum):
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

class RiskLevel(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class IncidentStatus(str, enum.Enum):
    NEW = "new"
    TRIAGING = "triaging"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"

class SecurityEvent(Base):
    __tablename__ = "security_events"
    
    id = Column(Integer, primary_key=True)
    event_id = Column(String(64), unique=True, index=True, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    event_type = Column(SQLEnum(EventType), default=EventType.UNKNOWN)
    source_ip = Column(String(45), index=True)
    dest_ip = Column(String(45))
    source_port = Column(Integer)
    dest_port = Column(Integer)
    protocol = Column(String(16))
    hostname = Column(String(255))
    username = Column(String(128))
    process_name = Column(String(255))
    file_hash = Column(String(64))
    mitre_tactic = Column(String(128))
    mitre_technique = Column(String(32), index=True)
    raw_event = Column(JSON)
    description = Column(Text)
    base_severity = Column(Float, default=0.0)
    anomaly_score = Column(Float, default=0.0)
    correlation_score = Column(Float, default=0.0)
    incident_id = Column(Integer, ForeignKey("incidents.id"), index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    incident = relationship("Incident", back_populates="events")

class Incident(Base):
    __tablename__ = "incidents"
    
    id = Column(Integer, primary_key=True)
    incident_id = Column(String(64), unique=True, index=True, nullable=False)
    title = Column(String(512), nullable=False)
    description = Column(Text)
    status = Column(SQLEnum(IncidentStatus), default=IncidentStatus.NEW)
    assigned_to = Column(String(128))
    threat_severity_score = Column(Float, default=0.0)
    asset_criticality_score = Column(Float, default=0.0)
    attack_sophistication_score = Column(Float, default=0.0)
    confidence_score = Column(Float, default=0.0)
    exposure_score = Column(Float, default=0.0)
    temporal_score = Column(Float, default=0.0)
    mitigation_score = Column(Float, default=0.0)
    overall_risk_score = Column(Float, default=0.0)
    risk_level = Column(SQLEnum(RiskLevel), default=RiskLevel.INFO)
    mitre_tactics = Column(JSON)
    mitre_techniques = Column(JSON)
    cve_ids = Column(JSON)
    llm_explanation = Column(Text)
    llm_summary = Column(Text)
    llm_recommendations = Column(JSON)
    human_reviewed = Column(Boolean, default=False)
    human_review_notes = Column(Text)
    detected_at = Column(DateTime, default=datetime.utcnow, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = Column(DateTime)
    
    events = relationship("SecurityEvent", back_populates="incident", cascade="all, delete-orphan")

class ThreatIntel(Base):
    __tablename__ = "threat_intel"
    
    id = Column(Integer, primary_key=True)
    title = Column(String(512), nullable=False)
    content = Column(Text, nullable=False)
    content_type = Column(String(32))
    mitre_id = Column(String(32), index=True)
    cve_id = Column(String(32), index=True)
    source = Column(String(255))
    url = Column(String(1024))
    created_at = Column(DateTime, default=datetime.utcnow)

class AnalystAction(Base):
    __tablename__ = "analyst_actions"
    
    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False, index=True)
    action_type = Column(String(64), nullable=False)
    action_description = Column(Text, nullable=False)
    target = Column(String(512))
    status = Column(String(32), default="pending")
    requires_approval = Column(Boolean, default=True)
    executed_by = Column(String(128))
    executed_at = Column(DateTime)
    result = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)