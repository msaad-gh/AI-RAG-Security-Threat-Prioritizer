from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta
import uuid
import os

from utils.database import get_db, init_db, SessionLocal
from models import SecurityEvent, Incident, ThreatIntel, AnalystAction, EventType, RiskLevel, IncidentStatus
from api.schemas import *

app = FastAPI(title="ThreatIQ", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


@app.on_event("startup")
def startup():
    init_db()
    print("ThreatIQ started")


@app.get("/api/health", response_model=HealthResponse)
def health():
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        database="sqlite",
        llm_configured=True,
        rag_configured=True,
        demo_mode=True
    )


@app.get("/api/config", response_model=ConfigResponse)
def config():
    return ConfigResponse(
        demo_mode=True,
        llm_provider="template",
        llm_model="template",
        rag_enabled=True,
        anomaly_detection_enabled=True,
        max_events_per_incident=100
    )


@app.post("/api/events", response_model=SecurityEventResponse)
def create_event(event: SecurityEventCreate, db: Session = Depends(get_db)):
    eid = event.event_id or f"evt_{uuid.uuid4().hex[:16]}"
    db_event = SecurityEvent(
        event_id=eid,
        event_type=event.event_type.value,
        timestamp=event.timestamp or datetime.utcnow(),
        source_ip=event.source_ip,
        dest_ip=event.dest_ip,
        source_port=event.source_port,
        dest_port=event.dest_port,
        protocol=event.protocol,
        hostname=event.hostname,
        username=event.username,
        process_name=event.process_name,
        file_hash=event.file_hash,
        mitre_tactic=event.mitre_tactic,
        mitre_technique=event.mitre_technique,
        description=event.description,
        raw_event=event.raw_event,
        base_severity=event.base_severity
    )
    db.add(db_event)
    db.commit()
    db.refresh(db_event)
    return db_event


@app.get("/api/events", response_model=List[SecurityEventResponse])
def list_events(limit: int = 100, offset: int = 0, db: Session = Depends(get_db)):
    return db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).offset(offset).limit(limit).all()


@app.post("/api/events/score-anomaly", response_model=AnomalyScoreResponse)
def score_anomaly(req: AnomalyScoreRequest):
    from services.anomaly_detection import anomaly_detector
    events = [e.model_dump() for e in req.events]
    scores, anomalies = anomaly_detector.detect(events)
    return AnomalyScoreResponse(scores=scores, threshold=0.9, anomalies=anomalies)


@app.post("/api/incidents/correlate", response_model=List[IncidentResponse])
async def correlate_incidents(event_ids: Optional[List[int]] = None, db: Session = Depends(get_db)):
    from services.anomaly_detection import anomaly_detector
    from services.risk_scoring import risk_scorer
    from services.llm_service import llm_service
    from services.rag_service import rag_service
    
    events = db.query(SecurityEvent).filter(SecurityEvent.incident_id.is_(None)).all() if not event_ids else db.query(SecurityEvent).filter(SecurityEvent.id.in_(event_ids)).all()
    if not events:
        return []
    
    events_dict = [{
        "id": e.id, "event_type": e.event_type, "timestamp": e.timestamp,
        "source_ip": e.source_ip, "dest_ip": e.dest_ip, "hostname": e.hostname,
        "username": e.username, "mitre_tactic": e.mitre_tactic,
        "mitre_technique": e.mitre_technique, "base_severity": e.base_severity
    } for e in events]
    
    scores = anomaly_detector.score_events(events_dict)
    for i, s in enumerate(scores):
        events[i].anomaly_score = s
    db.commit()
    
    risk = risk_scorer.calculate_risk_scores(events_dict)
    mitre_info = [{"mitre_id": t, "title": t} for t in set(e.mitre_technique for e in events if e.mitre_technique)][:5]
    llm = await llm_service.generate(events_dict, risk, mitre_info)
    
    inc = Incident(
        incident_id=f"inc_{uuid.uuid4().hex[:16]}",
        title=f"Security Incident - {risk['risk_level'].upper()} Risk",
        description=llm["summary"],
        status=IncidentStatus.NEW,
        threat_severity_score=risk["threat_severity_score"],
        asset_criticality_score=risk["asset_criticality_score"],
        attack_sophistication_score=risk["attack_sophistication_score"],
        confidence_score=risk["confidence_score"],
        exposure_score=risk["exposure_score"],
        temporal_score=risk["temporal_score"],
        mitigation_score=risk["mitigation_score"],
        overall_risk_score=risk["overall_risk_score"],
        risk_level=RiskLevel(risk["risk_level"]),
        mitre_tactics=list(set(e.mitre_tactic for e in events if e.mitre_tactic)),
        mitre_techniques=list(set(e.mitre_technique for e in events if e.mitre_technique)),
        llm_explanation=llm["explanation"],
        llm_summary=llm["summary"],
        llm_recommendations=llm["recommendations"]
    )
    
    db.add(inc)
    db.commit()
    db.refresh(inc)
    
    for e in events:
        e.incident_id = inc.id
    db.commit()
    
    return [IncidentResponse(
        id=inc.id,
        incident_id=inc.incident_id,
        title=inc.title,
        description=inc.description,
        status=IncidentStatusEnum(inc.status.value),
        risk_factors=RiskScoreFactors(
            threat_severity_score=inc.threat_severity_score,
            asset_criticality_score=inc.asset_criticality_score,
            attack_sophistication_score=inc.attack_sophistication_score,
            confidence_score=inc.confidence_score,
            exposure_score=inc.exposure_score,
            temporal_score=inc.temporal_score,
            mitigation_score=inc.mitigation_score
        ),
        overall_risk_score=inc.overall_risk_score,
        risk_level=RiskLevelEnum(inc.risk_level.value),
        mitre_tactics=inc.mitre_tactics,
        mitre_techniques=inc.mitre_techniques,
        llm_explanation=inc.llm_explanation,
        llm_summary=inc.llm_summary,
        llm_recommendations=inc.llm_recommendations,
        detected_at=inc.detected_at,
        created_at=inc.created_at,
        updated_at=inc.updated_at,
        resolved_at=inc.resolved_at,
        human_reviewed=inc.human_reviewed,
        detected_at=inc.detected_at,
        created_at=inc.created_at,
        event_count=len(events),
        actions=[]
    )]


@app.get("/api/incidents", response_model=IncidentListResponse)
def list_incidents(page: int = 1, page_size: int = 20, status: Optional[str] = None, risk_level: Optional[str] = None, db: Session = Depends(get_db)):
    q = db.query(Incident)
    if status:
        q = q.filter(Incident.status == status)
    if risk_level:
        q = q.filter(Incident.risk_level == risk_level)
    total = q.count()
    incs = q.order_by(Incident.overall_risk_score.desc()).offset((page - 1) * page_size).limit(page_size).all()
    
    return IncidentListResponse(
        incidents=[IncidentListItem(
            id=i.id,
            incident_id=i.incident_id,
            title=i.title,
            risk_level=RiskLevelEnum(i.risk_level.value),
            overall_risk_score=i.overall_risk_score,
            status=IncidentStatusEnum(i.status.value),
            event_count=len(i.events),
            detected_at=i.detected_at,
            mitre_tactics=i.mitre_tactics
        ) for i in incs],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size
    )


@app.get("/api/incidents/{inc_id}", response_model=IncidentResponse)
def get_incident(inc_id: int, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.id == inc_id).first()
    if not inc:
        raise HTTPException(404, "Not found")
    
    return IncidentResponse(
        id=inc.id,
        incident_id=inc.incident_id,
        title=inc.title,
        description=inc.description,
        status=IncidentStatusEnum(inc.status.value),
        risk_factors=RiskScoreFactors(
            threat_severity_score=inc.threat_severity_score,
            asset_criticality_score=inc.asset_criticality_score,
            attack_sophistication_score=inc.attack_sophistication_score,
            confidence_score=inc.confidence_score,
            exposure_score=inc.exposure_score,
            temporal_score=inc.temporal_score,
            mitigation_score=inc.mitigation_score
        ),
        overall_risk_score=inc.overall_risk_score,
        risk_level=RiskLevelEnum(inc.risk_level.value),
        mitre_tactics=inc.mitre_tactics,
        mitre_techniques=inc.mitre_techniques,
        llm_explanation=inc.llm_explanation,
        llm_summary=inc.llm_summary,
        llm_recommendations=inc.llm_recommendations,
        human_reviewed=inc.human_reviewed,
        human_review_notes=inc.human_review_notes,
        detected_at=inc.detected_at,
        created_at=inc.created_at,
        updated_at=inc.updated_at,
        event_count=len(inc.events),
        actions=[]
    )


@app.put("/api/incidents/{inc_id}", response_model=IncidentResponse)
def update_incident(inc_id: int, upd: IncidentUpdate, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.id == inc_id).first()
    if not inc:
        raise HTTPException(404, "Not found")
    
    if upd.title:
        inc.title = upd.title
    if upd.description:
        inc.description = upd.description
    if upd.status:
        inc.status = IncidentStatus(upd.status.value)
        inc.resolved_at = datetime.utcnow() if upd.status == IncidentStatusEnum.RESOLVED else None
    if upd.human_review_notes:
        inc.human_reviewed = True
        inc.human_review_notes = upd.human_review_notes
    
    db.commit()
    db.refresh(inc)
    
    return IncidentResponse(
        id=inc.id,
        incident_id=inc.incident_id,
        title=inc.title,
        status=IncidentStatusEnum(inc.status.value),
        risk_factors=RiskScoreFactors(
            threat_severity_score=inc.threat_severity_score,
            asset_criticality_score=inc.asset_criticality_score,
            attack_sophistication_score=inc.attack_sophistication_score,
            confidence_score=inc.confidence_score,
            exposure_score=inc.exposure_score,
            temporal_score=inc.temporal_score,
            mitigation_score=inc.mitigation_score
        ),
        overall_risk_score=inc.overall_risk_score,
        risk_level=RiskLevelEnum(inc.risk_level.value),
        llm_explanation=inc.llm_explanation,
        human_reviewed=inc.human_reviewed,
        human_review_notes=inc.human_review_notes,
        detected_at=inc.detected_at,
        event_count=len(inc.events),
        actions=[]
    )


@app.post("/api/incidents/{inc_id}/actions", response_model=AnalystActionResponse)
def create_action(inc_id: int, action: AnalystActionRequest, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.id == inc_id).first()
    if not inc:
        raise HTTPException(404, "Not found")
    
    a = AnalystAction(
        incident_id=inc_id,
        action_type=action.action_type,
        action_description=action.action_description,
        target=action.target,
        requires_approval=action.requires_approval,
        status="pending"
    )
    db.add(a)
    db.commit()
    db.refresh(a)
    
    return AnalystActionResponse(
        id=a.id,
        incident_id=a.incident_id,
        action_type=a.action_type,
        action_description=a.action_description,
        target=a.target,
        status=a.status,
        requires_approval=a.requires_approval,
        created_at=a.created_at,
        updated_at=a.updated_at
    )


@app.get("/api/dashboard/stats", response_model=DashboardStats)
def dashboard_stats(db: Session = Depends(get_db)):
    now = datetime.utcnow()
    day_ago = now - timedelta(days=1)
    
    return DashboardStats(
        total_incidents=db.query(Incident).count(),
        critical_incidents=db.query(Incident).filter(Incident.risk_level == RiskLevel.CRITICAL).count(),
        high_incidents=db.query(Incident).filter(Incident.risk_level == RiskLevel.HIGH).count(),
        medium_incidents=db.query(Incident).filter(Incident.risk_level == RiskLevel.MEDIUM).count(),
        low_incidents=db.query(Incident).filter(Incident.risk_level.in_([RiskLevel.LOW, RiskLevel.INFO])).count(),
        new_incidents_24h=db.query(Incident).filter(Incident.detected_at >= day_ago).count(),
        resolved_incidents_24h=db.query(Incident).filter(Incident.status == IncidentStatus.RESOLVED, Incident.resolved_at >= day_ago).count(),
        total_events_24h=db.query(SecurityEvent).filter(SecurityEvent.timestamp >= day_ago).count(),
        unique_attackers_24h=db.query(SecurityEvent.source_ip).filter(SecurityEvent.timestamp >= day_ago, SecurityEvent.source_ip.isnot(None)).distinct().count()
    )


@app.post("/api/rag/query", response_model=RAGQueryResponse)
def rag_query(req: RAGQueryRequest):
    from services.rag_service import rag_service
    import time
    start = time.time()
    results = rag_service.query(req.query, req.top_k)
    return RAGQueryResponse(
        query=req.query,
        results=[RAGResult(**r) for r in results],
        total_results=len(results),
        query_time_ms=(time.time() - start) * 1000
    )


@app.post("/api/demo/seed")
def seed_demo(db: Session = Depends(get_db)):
    from scripts.seed_demo_data import seed_all_demo_data
    result = seed_all_demo_data(db)
    return {"status": "success", "details": result}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.getenv("HOST", "0.0.0.0"), port=int(os.getenv("PORT", "8000")))