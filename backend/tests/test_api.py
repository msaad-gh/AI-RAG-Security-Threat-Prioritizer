"""
ThreatIQ Backend Tests
Comprehensive test suite for API endpoints and services
"""
import pytest
from fastapi.testclient import TestClient
from datetime import datetime, timedelta
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app
from utils.database import get_db, init_db, SessionLocal
from models import Base, SecurityEvent, Incident, EventType, RiskLevel, IncidentStatus

client = TestClient(app)


@pytest.fixture(scope="function")
def db_session():
    """Create a fresh database for each test"""
    init_db()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="function")
def test_event(db_session):
    """Create a test event"""
    event = SecurityEvent(
        event_id="evt_test_001",
        event_type=EventType.NETWORK_SCAN,
        timestamp=datetime.utcnow(),
        source_ip="192.168.1.100",
        dest_ip="192.168.1.10",
        dest_port=22,
        hostname="TEST01",
        mitre_tactic="discovery",
        mitre_technique="T1046",
        description="Test network scan event",
        base_severity=5.0,
    )
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)
    return event


def test_health_check():
    """Test health endpoint"""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data
    assert "database" in data


def test_config_endpoint():
    """Test config endpoint"""
    response = client.get("/api/config")
    assert response.status_code == 200
    data = response.json()
    assert "demo_mode" in data


def test_create_event(test_event):
    """Test event creation"""
    event_data = {
        "event_type": "malware_detected",
        "source_ip": "192.168.1.105",
        "dest_ip": "192.168.1.20",
        "dest_port": 443,
        "hostname": "WORKSTATION01",
        "username": "jsmith",
        "mitre_tactic": "execution",
        "mitre_technique": "T1059",
        "description": "Malware detected",
        "base_severity": 7.5,
    }
    
    response = client.post("/api/events", json=event_data)
    assert response.status_code == 200
    data = response.json()
    assert data["event_type"] == "malware_detected"
    assert data["source_ip"] == "192.168.1.105"
    assert "event_id" in data


def test_list_events(test_event):
    """Test listing events"""
    response = client.get("/api/events?limit=10&offset=0")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1


def test_anomaly_scoring():
    """Test anomaly detection scoring"""
    events = [
        {"event_type": "network_scan", "source_ip": "192.168.1.100", "base_severity": 3.0},
        {"event_type": "malware_detected", "source_ip": "192.168.1.105", "base_severity": 9.0},
        {"event_type": "data_exfiltration", "source_ip": "192.168.1.110", "dest_ip": "8.8.8.8", "base_severity": 9.5},
    ]
    
    response = client.post("/api/events/score-anomaly", json={"events": events})
    assert response.status_code == 200
    data = response.json()
    assert "scores" in data
    assert "threshold" in data
    assert len(data["scores"]) == 3


def test_dashboard_stats():
    """Test dashboard statistics"""
    response = client.get("/api/dashboard/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_incidents" in data
    assert "critical_incidents" in data


def test_rag_query():
    """Test RAG threat intelligence query"""
    response = client.post("/api/rag/query", json={
        "query": "T1059",
        "top_k": 5,
        "include_mitre": True,
        "include_cve": True,
    })
    assert response.status_code == 200
    data = response.json()
    assert "query" in data
    assert "results" in data


def test_risk_scoring_formula():
    """Test 7-factor risk scoring calculation"""
    from services.risk_scoring import risk_scorer
    
    events = [
        {"event_type": "malware_detected", "mitre_tactic": "execution", "mitre_technique": "T1059", "base_severity": 8.0, "anomaly_score": 0.8},
        {"event_type": "lateral_movement", "mitre_tactic": "lateral_movement", "mitre_technique": "T1021", "base_severity": 8.5, "anomaly_score": 0.9},
        {"event_type": "data_exfiltration", "mitre_tactic": "data_exfiltration", "mitre_technique": "T1041", "base_severity": 9.5, "anomaly_score": 0.95},
    ]
    
    scores = risk_scorer.calculate_risk_scores(events)
    
    assert "overall_risk_score" in scores
    assert "risk_level" in scores
    assert 0 <= scores["overall_risk_score"] <= 100
    assert scores["risk_level"] in ["critical", "high", "medium", "low", "info"]
    assert "threat_severity_score" in scores
    assert "asset_criticality_score" in scores


def test_isolation_forest_anomaly_detection():
    """Test isolation forest anomaly detection"""
    from services.anomaly_detection import anomaly_detector
    
    normal_events = [{"event_type": "network_scan", "base_severity": 3.0, "dest_port": 80}] * 10
    anomalous_events = [
        {"event_type": "data_exfiltration", "base_severity": 9.5, "dest_port": 443},
        {"event_type": "malware_detected", "base_severity": 9.0, "dest_port": 4444},
    ]
    
    all_events = normal_events + anomalous_events
    scores = anomaly_detector.score_events(all_events)
    
    normal_scores = scores[:len(normal_events)]
    anomaly_scores = scores[len(normal_events):]
    
    avg_normal = sum(normal_scores) / len(normal_scores)
    avg_anomaly = sum(anomaly_scores) / len(anomaly_scores)
    
    assert avg_anomaly > avg_normal


def test_full_incident_workflow():
    """Test complete incident creation workflow"""
    events_data = [
        {"event_type": "network_scan", "source_ip": "192.168.1.100", "mitre_tactic": "discovery", "mitre_technique": "T1046", "base_severity": 4.0},
        {"event_type": "initial_access", "source_ip": "192.168.1.100", "dest_ip": "192.168.1.10", "dest_port": 443, "mitre_tactic": "initial_access", "mitre_technique": "T1190", "base_severity": 7.0},
        {"event_type": "execution", "hostname": "WEB01", "mitre_tactic": "execution", "mitre_technique": "T1059", "base_severity": 8.0},
    ]
    
    created_events = []
    for event_data in events_data:
        response = client.post("/api/events", json=event_data)
        assert response.status_code == 200
        created_events.append(response.json())
    
    event_ids = [e["id"] for e in created_events]
    response = client.post("/api/incidents/correlate", params={"event_ids": event_ids})
    assert response.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v"])