from typing import List, Dict
from datetime import datetime


class LLMService:
    """
    LLM service for generating incident explanations.
    Uses template-based generation for demo (deterministic, no API key needed).
    """
    
    def __init__(self):
        self.demo_mode = True
    
    async def generate(
        self,
        events: List[Dict],
        scores: Dict,
        mitre: List[Dict]
    ) -> Dict:
        """Generate structured explanation for an incident."""
        
        # Determine incident pattern from events
        event_types = set(str(e.get("event_type", "")) for e in events)
        tactics = set(str(e.get("mitre_tactic", "")).lower() for e in events if e.get("mitre_tactic"))
        
        # Pattern matching for demo scenarios
        if "malware_detected" in event_types or "impact" in tactics:
            # Ransomware pattern
            summary = "Ransomware attack detected with multi-stage kill chain"
            explanation = f"""This incident shows a ransomware attack pattern:

1. **Initial Access**: Attack likely began with phishing or exploit
2. **Execution**: Malware deployed and executed on victim systems
3. **Persistence**: Attacker established foothold with scheduled tasks
4. **Credential Access**: Credentials dumped from LSASS
5. **Lateral Movement**: Attacker moved through network using SMB/RDP
6. **Collection**: Sensitive data gathered from file servers
7. **Exfiltration**: Data stolen before encryption
8. **Impact**: Ransomware deployed, files encrypted

**MITRE Techniques Identified:**
{", ".join(str(e.get("mitre_technique", "")) for e in events if e.get("mitre_technique"))}

**Risk Assessment:**
Overall Risk Score: {scores.get("overall_risk_score", 0)}/100 ({scores.get("risk_level", "unknown").upper()})

This attack follows a sophisticated pattern consistent with modern ransomware groups, utilizing living-off-the-land techniques to evade detection."""
            
            recommendations = [
                "Immediately isolate affected systems from the network",
                "Activate incident response team and notify leadership",
                "Preserve evidence by creating forensic images",
                "Identify and block C2 infrastructure at firewall",
                "Reset credentials for all potentially compromised accounts",
                "Assess backup integrity and prepare for recovery",
                "Consider engaging law enforcement and cyber insurance"
            ]
            
        elif "data_exfiltration" in event_types and "lateral_movement" in tactics:
            # APT pattern
            summary = "Advanced Persistent Threat (APT) intrusion detected"
            explanation = f"""This incident demonstrates characteristics of an APT operation:

1. **Reconnaissance**: Extended network discovery and enumeration
2. **Initial Compromise**: Spear-phishing or exploit provided access
3. **Establishment**: Multiple persistence mechanisms installed
4. **Privilege Escalation**: Credential dumping achieved admin access
5. **Lateral Movement**: Systematic movement through network
6. **Data Collection**: Targeted collection from high-value systems
7. **Exfiltration Preparation**: Data staging for theft

The attacker demonstrates sophisticated tradecraft, using legitimate tools to blend with normal activity."""
            
            recommendations = [
                "Engage threat intelligence team to identify threat actor",
                "Conduct enterprise-wide threat hunt for additional compromised systems",
                "Implement emergency credential rotation for privileged accounts",
                "Deploy enhanced monitoring on identified TTPs",
                "Review and enhance email security controls"
            ]
            
        elif "data_exfiltration" in event_types and "insider" in str(events):
            # Insider threat pattern
            summary = "Potential insider threat activity detected"
            explanation = """This incident shows indicators consistent with insider threat:

1. **Unusual Access**: After-hours system access beyond normal duties
2. **Elevated Data Access**: Significantly higher data volume than peers
3. **Privilege Misuse**: Administrative privileges used for non-admin tasks
4. **Data Transfer**: Large volumes to personal cloud storage
5. **Policy Evasion**: Attempts to disable logging

Pattern suggests either malicious insider or compromised credentials."""
            
            recommendations = [
                "Immediately disable user account and all access",
                "Preserve all logs for forensic analysis",
                "Coordinate with HR and Legal before action",
                "Review all data accessed in past 90 days",
                "Assess potential data breach notification requirements"
            ]
            
        elif "initial_access" in tactics and "T1190" in str(events):
            # Web app attack pattern
            summary = "Web application attack with SQL injection detected"
            explanation = f"""This incident indicates a web application attack:

1. **Reconnaissance**: Automated scanning for vulnerabilities
2. **SQL Injection**: Multiple injection attempts in web parameters
3. **Successful Exploitation**: Database access achieved
4. **Data Access**: Customer PII and financial records queried
5. **Web Shell**: Suspicious file upload for persistence
6. **Command Execution**: OS commands executed via web shell
7. **Exfiltration**: Database dump transferred to attacker

Attack demonstrates knowledge of web application vulnerabilities."""
            
            recommendations = [
                "Immediately take affected web application offline",
                "Block attacking IP addresses at WAF/firewall",
                "Conduct code review for SQL injection vulnerabilities",
                "Assess scope of data breach and prepare notification",
                "Deploy Web Application Firewall (WAF) rules",
                "Implement parameterized queries across application"
            ]
            
        else:
            # Generic pattern
            summary = f"Security incident detected - {scores.get('risk_level', 'unknown').upper()} risk"
            explanation = f"""This security incident has been detected and requires investigation:

**Event Analysis:**
Multiple security events correlated indicating potential malicious activity.

**Attack Indicators:**
MITRE ATT&CK techniques identified suggest structured attack methodology.

**Affected Systems:**
Multiple systems and/or users potentially impacted.

**Risk Assessment:**
Based on 7-factor scoring model, this incident presents elevated risk.

**Recommended Actions:**
Immediate investigation and containment recommended."""
            
            recommendations = [
                "Review all correlated events in detail",
                "Identify and isolate affected systems",
                "Preserve evidence for forensic analysis",
                "Assess potential data impact",
                "Update detection rules based on findings"
            ]
        
        # Add MITRE details to explanation
        if mitre:
            mitre_text = "\n\n**Identified MITRE ATT&CK Techniques:**\n"
            for intel in mitre[:5]:
                mitre_text += f"- {intel.get('mitre_id', 'N/A')}: {intel.get('title', 'Unknown')}\n"
            explanation += mitre_text
        
        # Add risk breakdown
        risk_text = f"""

**Risk Score Breakdown:**
- Threat Severity: {scores.get('threat_severity_score', 0)}/10
- Asset Criticality: {scores.get('asset_criticality_score', 0)}/10
- Attack Sophistication: {scores.get('attack_sophistication_score', 0)}/10
- Confidence: {scores.get('confidence_score', 0)}/10
- Exposure: {scores.get('exposure_score', 0)}/10
- Temporal: {scores.get('temporal_score', 0)}/10
- Mitigation Gap: {scores.get('mitigation_score', 0)}/10

**Overall Risk Score: {scores.get('overall_risk_score', 0)}/100 ({scores.get('risk_level', 'unknown').upper()})"""
        
        explanation += risk_text
        
        return {
            "summary": summary,
            "explanation": explanation,
            "recommendations": recommendations,
            "confidence": 0.85,
            "model_used": "template",
            "generated_at": datetime.utcnow().isoformat()
        }


llm_service = LLMService()