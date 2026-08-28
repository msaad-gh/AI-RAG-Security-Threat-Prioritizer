from typing import List, Dict, Any
from datetime import datetime


class RiskScoringService:
    """
    Implements the 7-factor risk scoring formula:
    
    Overall Risk = (
        threat_severity      × 0.20 +
        asset_criticality    × 0.15 +
        attack_sophistication × 0.15 +
        confidence           × 0.15 +
        exposure             × 0.15 +
        temporal             × 0.10 +
        mitigation_gap       × 0.10
    ) × 10
    
    Each factor is scored 0-10, overall risk is 0-100.
    """
    
    EVENT_SEVERITY = {
        "network_scan": 3.0, "malware_detected": 7.0, "phishing_attempt": 5.0,
        "data_exfiltration": 9.0, "privilege_escalation": 8.0, "lateral_movement": 8.5,
        "command_control": 8.0, "initial_access": 7.0, "persistence": 7.5,
        "defense_evasion": 6.5, "credential_access": 8.0, "discovery": 4.0,
        "collection": 6.0, "impact": 9.5, "unknown": 3.0,
    }
    
    TACTIC_SEVERITY = {
        "initial_access": 6.0, "execution": 6.5, "persistence": 7.0,
        "privilege_escalation": 7.5, "defense_evasion": 7.0, "credential_access": 8.0,
        "discovery": 5.0, "lateral_movement": 8.5, "collection": 7.0,
        "command_control": 8.0, "data_exfiltration": 9.0, "impact": 9.5,
    }
    
    def _calculate_threat_severity(self, events: List[Dict[str, Any]]) -> float:
        """Factor 1: Threat Severity (weight: 0.20)"""
        if not events:
            return 0.0
        
        severities = []
        for e in events:
            event_type = e.get("event_type", "unknown")
            if hasattr(event_type, 'value'):
                event_type = event_type.value
            severity = self.EVENT_SEVERITY.get(str(event_type), 3.0)
            base_sev = e.get("base_severity", 0.0)
            severity = severity * (1 + base_sev / 20.0)
            severities.append(severity)
        
        avg_severity = sum(severities) / len(severities)
        chain_multiplier = min(1.0 + (len(events) - 1) * 0.1, 1.5)
        
        return min(avg_severity * chain_multiplier, 10.0)
    
    def _calculate_asset_criticality(self, events: List[Dict[str, Any]]) -> float:
        """Factor 2: Asset Criticality (weight: 0.15)"""
        if not events:
            return 0.0
        
        max_score = 5.0
        
        for e in events:
            score = 5.0
            
            dest_port = e.get("dest_port")
            if dest_port in [445, 1433, 3306, 5432, 3389]:
                score = 9.0
            elif dest_port in [22, 389, 6379, 27017]:
                score = 8.5
            
            username = str(e.get("username", "")).lower()
            if any(x in username for x in ["admin", "root", "system"]):
                score = max(score, 9.0)
            
            hostname = str(e.get("hostname", "")).lower()
            if any(x in hostname for x in ["dc", "domain", "controller"]):
                score = max(score, 9.5)
            
            max_score = max(max_score, score)
        
        return max_score
    
    def _calculate_attack_sophistication(self, events: List[Dict[str, Any]]) -> float:
        """Factor 3: Attack Sophistication (weight: 0.15)"""
        if not events:
            return 0.0
        
        techniques = set()
        tactics = set()
        
        for e in events:
            tech = e.get("mitre_technique")
            if tech:
                techniques.add(tech)
            tactic = str(e.get("mitre_tactic", "")).lower()
            if tactic:
                tactics.add(tactic)
        
        technique_score = min(len(techniques) * 1.5, 6.0)
        tactic_score = min(len(tactics) * 1.0, 4.0)
        
        sophistication = technique_score + tactic_score
        
        if "defense_evasion" in tactics:
            sophistication += 2.0
        
        return min(sophistication, 10.0)
    
    def _calculate_confidence(self, events: List[Dict[str, Any]]) -> float:
        """Factor 4: Confidence (weight: 0.15)"""
        if not events:
            return 0.0
        
        scores = []
        
        for e in events:
            score = 5.0
            
            if e.get("mitre_technique"):
                score += 1.5
            if e.get("source_ip"):
                score += 0.5
            if e.get("hostname"):
                score += 0.5
            if e.get("file_hash"):
                score += 1.0
            
            anomaly = e.get("anomaly_score", 0.0)
            score += anomaly * 1.5
            
            scores.append(min(score, 10.0))
        
        return sum(scores) / len(scores)
    
    def _calculate_exposure(self, events: List[Dict[str, Any]]) -> float:
        """Factor 5: Exposure (weight: 0.15)"""
        if not events:
            return 0.0
        
        ips = set()
        hosts = set()
        users = set()
        
        for e in events:
            if e.get("source_ip"):
                ips.add(e["source_ip"])
            if e.get("dest_ip"):
                ips.add(e["dest_ip"])
            if e.get("hostname"):
                hosts.add(e["hostname"])
            if e.get("username"):
                users.add(e["username"])
        
        ip_score = min(len(ips) * 1.5, 6.0)
        host_score = min(len(hosts) * 2.0, 6.0)
        user_score = min(len(users) * 2.0, 6.0)
        
        exposure = (ip_score + host_score + user_score) / 3.0
        
        return min(exposure, 10.0)
    
    def _calculate_temporal(self, events: List[Dict[str, Any]]) -> float:
        """Factor 6: Temporal (weight: 0.10)"""
        if not events:
            return 5.0
        
        return 7.0
    
    def _calculate_mitigation(self, events: List[Dict[str, Any]]) -> float:
        """Factor 7: Mitigation Gap (weight: 0.10)"""
        if not events:
            return 0.0
        
        gap = 5.0
        
        tactics = set()
        for e in events:
            tactic = str(e.get("mitre_tactic", "")).lower()
            if tactic:
                tactics.add(tactic)
        
        if "defense_evasion" in tactics:
            gap += 1.0
        if "persistence" in tactics:
            gap += 0.5
        
        event_types = set()
        for e in events:
            et = e.get("event_type", "unknown")
            if hasattr(et, 'value'):
                et = et.value
            event_types.add(str(et))
        
        if len(event_types) > 3:
            gap += min(len(event_types) - 3, 3.0)
        
        return min(gap, 10.0)
    
    def calculate_risk_scores(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate all 7 risk factors and overall score."""
        
        threat_severity = self._calculate_threat_severity(events)
        asset_criticality = self._calculate_asset_criticality(events)
        attack_sophistication = self._calculate_attack_sophistication(events)
        confidence = self._calculate_confidence(events)
        exposure = self._calculate_exposure(events)
        temporal = self._calculate_temporal(events)
        mitigation = self._calculate_mitigation(events)
        
        overall = (
            threat_severity * 0.20 +
            asset_criticality * 0.15 +
            attack_sophistication * 0.15 +
            confidence * 0.15 +
            exposure * 0.15 +
            temporal * 0.10 +
            mitigation * 0.10
        ) * 10
        
        if overall >= 80:
            risk_level = "critical"
        elif overall >= 60:
            risk_level = "high"
        elif overall >= 40:
            risk_level = "medium"
        elif overall >= 20:
            risk_level = "low"
        else:
            risk_level = "info"
        
        return {
            "threat_severity_score": round(threat_severity, 2),
            "asset_criticality_score": round(asset_criticality, 2),
            "attack_sophistication_score": round(attack_sophistication, 2),
            "confidence_score": round(confidence, 2),
            "exposure_score": round(exposure, 2),
            "temporal_score": round(temporal, 2),
            "mitigation_score": round(mitigation, 2),
            "overall_risk_score": round(overall, 2),
            "risk_level": risk_level,
        }


risk_scorer = RiskScoringService()