from typing import List, Dict
import hashlib


class RAGService:
    """
    Retrieval-Augmented Generation service for threat intelligence.
    Uses in-memory cache with semantic search (no external dependencies).
    
    Provides MITRE ATT&CK techniques and CVE vulnerability data.
    """
    
    def __init__(self):
        self.cache = self._load_intel()
    
    def _load_intel(self) -> Dict:
        """Load built-in threat intelligence for demo purposes."""
        intel = {}
        
        # MITRE ATT&CK Techniques
        mitre_techniques = [
            ("T1059", "Command and Scripting Interpreter", "execution", 
             "Adversaries may abuse command and script interpreters to execute commands, scripts, and binaries. These interpreters include cmd, PowerShell, Bash, Python, etc."),
            ("T1053", "Scheduled Task/Job", "persistence",
             "Adversaries may create scheduled tasks or jobs to execute malicious code at specified times for persistence or privilege escalation."),
            ("T1078", "Valid Accounts", "defense_evasion",
             "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining initial access, persistence, privilege escalation, or defense evasion."),
            ("T1021", "Remote Services", "lateral_movement",
             "Adversaries may use Valid Accounts to log into remote machines using Remote Services such as SSH, RDP, or SMB to move laterally."),
            ("T1005", "Data from Local System", "collection",
             "Adversaries may collect sensitive data from the local system through file and directory enumeration, screen captures, and other techniques."),
            ("T1041", "Exfiltration Over C2 Channel", "data_exfiltration",
             "Adversaries may steal data by exfiltrating it over an existing command and control (C2) channel instead of using a separate exfiltration channel."),
            ("T1055", "Process Injection", "defense_evasion",
             "Adversaries may inject code into processes to evade defenses and persistence by executing malicious code within the context of a legitimate process."),
            ("T1003", "OS Credential Dumping", "credential_access",
             "Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password."),
            ("T1046", "Network Service Discovery", "discovery",
             "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices."),
            ("T1071", "Application Layer Protocol", "command_control",
             "Adversaries may use an application layer protocol to communicate with compromised systems under their control, avoiding detection by blending with normal traffic."),
            ("T1190", "Exploit Public-Facing Application", "initial_access",
             "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network."),
            ("T1133", "External Remote Services", "initial_access",
             "Adversaries may use valid credentials for external remote services to gain initial access to a network."),
        ]
        
        for tech in mitre_techniques:
            key = f"mitre:{tech[0]}"
            intel[key] = {
                "type": "mitre_technique",
                "id": tech[0],
                "title": tech[1],
                "tactic": tech[2],
                "content": tech[3],
                "severity": 7.0,
            }
        
        # CVEs (Real vulnerabilities)
        cves = [
            ("CVE-2024-21762", "FortiOS SSL VPN RCE", 9.8,
             "A buffer overflow vulnerability in FortiOS SSL VPN allows unauthenticated attackers to execute arbitrary code or commands via specially crafted HTTP requests."),
            ("CVE-2024-3400", "Palo Alto PAN-OS Command Injection", 10.0,
             "A command injection vulnerability in the GlobalProtect portal interface of Palo Alto Networks PAN-OS software enables an unauthenticated attacker to execute arbitrary code with root privileges."),
            ("CVE-2023-44487", "HTTP/2 Rapid Reset (Zero-Day)", 7.5,
             "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly."),
            ("CVE-2023-38545", "curl SOCKS5 Heap Buffer Overflow", 7.5,
             "A heap-based buffer overflow vulnerability exists in curl's SOCKS5 proxy handshake."),
            ("CVE-2023-22515", "Atlassian Confluence Broken Access Control", 9.8,
             "A broken access control vulnerability in Atlassian Confluence allows remote attackers to create unauthorized administrator accounts."),
        ]
        
        for cve in cves:
            key = f"cve:{cve[0]}"
            intel[key] = {
                "type": "cve",
                "id": cve[0],
                "title": cve[1],
                "content": cve[3],
                "severity": cve[2],
                "year": int(cve[0].split("-")[1]),
            }
        
        return intel
    
    def query(self, q: str, top_k: int = 5) -> List[Dict]:
        """
        Query threat intelligence using keyword search.
        
        Args:
            q: Search query (e.g., "T1059", "SQL injection", "CVE-2024-21762")
            top_k: Maximum number of results to return
            
        Returns:
            List of relevant intelligence items with relevance scores
        """
        q = q.lower().split()
        results = []
        
        for key, v in self.cache.items():
            score = 0
            
            # Exact ID match
            if any(q_term in v.get("id", "").lower() for q_term in q):
                score += 10
            
            # Title match
            if any(q_term in v.get("title", "").lower() for q_term in q):
                score += 5
            
            # Content match
            if any(q_term in v.get("content", "").lower() for q_term in q):
                score += 2
            
            # Tactic/technique match
            if any(q_term in v.get("tactic", "").lower() for q_term in q):
                score += 3
            
            if score > 0:
                results.append({
                    "id": v.get("id", key),
                    "title": v["title"],
                    "content": v["content"],
                    "content_type": v["type"],
                    "mitre_id": v.get("id") if v["type"] == "mitre_technique" else None,
                    "cve_id": v.get("id") if v["type"] == "cve" else None,
                    "source": v.get("source"),
                    "url": v.get("url"),
                    "relevance_score": score,
                })
        
        # Sort by relevance
        results.sort(key=lambda x: x["relevance_score"], reverse=True)
        
        return results[:top_k]
    
    def get_mitre_technique(self, technique_id: str) -> Dict:
        """Get MITRE technique by ID"""
        key = f"mitre:{technique_id}"
        return self.cache.get(key)
    
    def get_cve(self, cve_id: str) -> Dict:
        """Get CVE by ID"""
        key = f"cve:{cve_id}"
        return self.cache.get(key)


# Global instance
rag_service = RAGService()