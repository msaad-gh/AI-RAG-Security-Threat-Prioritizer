from datetime import datetime, timedelta
import uuid
from models import SecurityEvent, EventType


SAMPLE_DATA = {
    "ips": ["192.168.1.105", "192.168.1.110", "10.0.0.50", "192.168.1.10", "192.168.1.20"],
    "hosts": ["DC01.corp.local", "WEB01.corp.local", "DB01.corp.local", "FILE01.corp.local", "WORKSTATION042"],
    "users": ["admin", "jsmith", "svc_backup", "system", "dbadmin"],
    "hashes": ["a1b2c3d4e5f6789012345678901234567890abcd", "deadbeef12345678901234567890123456789012"],
}


def generate_event_id() -> str:
    return f"evt_{uuid.uuid4().hex[:16]}"


def create_ransomware_scenario(base_time: datetime, db):
    """Create a ransomware attack scenario (10 events)"""
    events = [
        SecurityEvent(
            event_id=generate_event_id(),
            timestamp=base_time,
            event_type=EventType.PHISHING_ATTEMPT,
            source_ip=SAMPLE_DATA["ips"][0],
            dest_ip=SAMPLE_DATA["ips"][3],
            hostname=SAMPLE_DATA["hosts"][4],
            username=SAMPLE_DATA["users"][1],
            mitre_tactic="initial_access",
            mitre_technique="T1190",
            description="Phishing email with malicious attachment detected",
            base_severity=6.0,
        ),
        SecurityEvent(
            event_id=generate_event_id(),
            timestamp=base_time + timedelta(minutes=15),
            event_type=EventType.MALWARE_DETECTED,
            source_ip=SAMPLE_DATA["ips"][0],
            hostname=SAMPLE_DATA["hosts"][4],
            username=SAMPLE_DATA["users"][1],
            process_name="powershell.exe",
            file_hash=SAMPLE_DATA["hashes"][0],
            mitre_tactic="execution",
            mitre_technique="T1059",
            description="Malicious PowerShell script execution detected",
            base_severity=8.0,
        ),
        SecurityEvent(
            event_id=generate_event_id(),
            timestamp=base_time + timedelta(minutes=30),
            event_type=EventType.CREDENTIAL_ACCESS,
            hostname=SAMPLE_DATA["hosts"][0],
            username=SAMPLE_DATA["users"][0],
            process_name="lsass.exe",
            mitre_tactic="credential_access",
            mitre_technique="T1003",
            description="LSASS memory access detected - credential dumping",
            base_severity=9.0,
        ),
        SecurityEvent(
            event_id=generate_event_id(),
            timestamp=base_time + timedelta(minutes=45),
            event_type=EventType.LATERAL_MOVEMENT,
            source_ip=SAMPLE_DATA["ips"][0],
            dest_ip=SAMPLE_DATA["ips"][4],
            dest_port=445,
            hostname=SAMPLE_DATA["hosts"][3],
            username=SAMPLE_DATA["users"][0],
            mitre_tactic="lateral_movement",
            mitre_technique="T1021",
            description="SMB lateral movement to file server",
            base_severity=8.5,
        ),
        SecurityEvent(
            event_id=generate_event_id(),
            timestamp=base_time + timedelta(hours=1),
            event_type=EventType.NETWORK_SCAN,
            source_ip=SAMPLE_DATA["ips"][0],
            hostname=SAMPLE_DATA["hosts"][3],
            mitre_tactic="discovery",
            mitre_technique="T1046",
            description="Network scanning activity from compromised host",
            base_severity=5.0,
        ),
        SecurityEvent(
            event_id=generate_event_id(),
            timestamp=base_time + timedelta(hours=1, minutes=15),
            event_type=EventType.PERSISTENCE,
            hostname=SAMPLE_DATA["hosts"][3],
            process_name="schtasks.exe",
            mitre_tactic="persistence",
            mitre_technique="T1053",
            description="Suspicious scheduled task creation",
            base_severity=7.0,
        ),
        SecurityEvent(
            event_id=generate_event_id(),
            timestamp=base_time + timedelta(hours=2),
            event_type=EventType.COLLECTION,
            hostname=SAMPLE_DATA["hosts"][3],
            username=SAMPLE_DATA["users"][0],
            mitre_tactic="collection",
            mitre_technique="T1005",
            description="Bulk file access on sensitive shares",
            base_severity=7.5,
        ),
        SecurityEvent(
            event_id=generate_event_id(),
            timestamp=base_time + timedelta(hours=2, minutes=30),
            event_type=EventType.COMMAND_CONTROL,
            source_ip=SAMPLE_DATA["ips"][0],
            dest_ip="8.8.8.8",
            dest_port=443,
            hostname=SAMPLE_DATA["hosts"][3],
            mitre_tactic="command_control",
            mitre_technique="T1071",
            description="Encrypted C2 communication to external IP",
            base_severity=8.0,
        ),
        SecurityEvent(
            event_id=generate_event_id(),
            timestamp=base_time + timedelta(hours=3),
            event_type=EventType.DATA_EXFILTRATION,
            source_ip=SAMPLE_DATA["ips"][0],
            dest_ip="8.8.8.8",
            dest_port=443,
            mitre_tactic="data_exfiltration",
            mitre_technique="T1041",
            description="Large data transfer to external destination",
            base_severity=9.5,
        ),
        SecurityEvent(
            event_id=generate_event_id(),
            timestamp=base_time + timedelta(hours=4),
            event_type=EventType.IMPACT,
            hostname=SAMPLE_DATA["hosts"][3],
            process_name="encryptor.exe",
            file_hash=SAMPLE_DATA["hashes"][1],
            mitre_tactic="impact",
            description="Ransomware encryption activity detected",
            base_severity=10.0,
        ),
    ]
    db.add_all(events)
    return events


def create_apt_scenario(base_time: datetime, db):
    """Create an APT intrusion scenario (12 events over 3 days)"""
    events = []
    
    for day in range(3):
        day_offset = timedelta(days=day)
        
        events.extend([
            SecurityEvent(
                event_id=generate_event_id(),
                timestamp=base_time + day_offset + timedelta(hours=2),
                event_type=EventType.NETWORK_SCAN,
                source_ip=SAMPLE_DATA["ips"][2],
                mitre_tactic="discovery",
                mitre_technique="T1046",
                description=f"Network reconnaissance - Day {day+1}",
                base_severity=4.0 + day * 0.5,
            ),
            SecurityEvent(
                event_id=generate_event_id(),
                timestamp=base_time + day_offset + timedelta(hours=8),
                event_type=EventType.CREDENTIAL_ACCESS,
                hostname=SAMPLE_DATA["hosts"][0],
                username=SAMPLE_DATA["users"][2],
                mitre_tactic="credential_access",
                mitre_technique="T1003",
                description="Credential dumping attempt on DC",
                base_severity=8.0,
            ),
            SecurityEvent(
                event_id=generate_event_id(),
                timestamp=base_time + day_offset + timedelta(hours=14),
                event_type=EventType.LATERAL_MOVEMENT,
                source_ip=SAMPLE_DATA["ips"][2],
                dest_ip=SAMPLE_DATA["ips"][3],
                dest_port=3389,
                hostname=SAMPLE_DATA["hosts"][1],
                username=SAMPLE_DATA["users"][0],
                mitre_tactic="lateral_movement",
                mitre_technique="T1021",
                description="RDP lateral movement",
                base_severity=7.5,
            ),
            SecurityEvent(
                event_id=generate_event_id(),
                timestamp=base_time + day_offset + timedelta(hours=20),
                event_type=EventType.PERSISTENCE,
                hostname=SAMPLE_DATA["hosts"][1],
                process_name="reg.exe",
                mitre_tactic="persistence",
                mitre_technique="T1053",
                description="Registry persistence mechanism",
                base_severity=7.0,
            ),
        ])
    
    db.add_all(events)
    return events


def create_insider_threat_scenario(base_time: datetime, db):
    """Create an insider threat scenario (10 events)"""
    events = []
    user = SAMPLE_DATA["users"][1]
    workstation = SAMPLE_DATA["hosts"][4]
    
    for hour in [22, 23, 0, 1, 2]:
        events.append(SecurityEvent(
            event_id=generate_event_id(),
            timestamp=base_time + timedelta(hours=hour - 22),
            event_type=EventType.DISCOVERY,
            hostname=workstation,
            username=user,
            mitre_tactic="discovery",
            mitre_technique="T1046",
            description=f"After-hours system access - {hour}:00",
            base_severity=5.0,
        ))
    
    events.extend([
        SecurityEvent(
            event_id=generate_event_id(),
            timestamp=base_time + timedelta(hours=1),
            event_type=EventType.COLLECTION,
            hostname=SAMPLE_DATA["hosts"][3],
            username=user,
            mitre_tactic="collection",
            mitre_technique="T1005",
            description="Access to sensitive HR files",
            base_severity=7.0,
        ),
        SecurityEvent(
            event_id=generate_event_id(),
            timestamp=base_time + timedelta(hours=2),
            event_type=EventType.DATA_EXFILTRATION,
            source_ip=SAMPLE_DATA["ips"][1],
            dest_ip="8.8.8.8",
            dest_port=443,
            hostname=workstation,
            username=user,
            mitre_tactic="data_exfiltration",
            mitre_technique="T1041",
            description="Large upload to cloud storage",
            base_severity=8.5,
        ),
        SecurityEvent(
            event_id=generate_event_id(),
            timestamp=base_time + timedelta(hours=2, minutes=30),
            event_type=EventType.COLLECTION,
            hostname=workstation,
            username=user,
            mitre_tactic="collection",
            mitre_technique="T1005",
            description="USB storage device connected",
            base_severity=6.5,
        ),
        SecurityEvent(
            event_id=generate_event_id(),
            timestamp=base_time + timedelta(hours=3),
            event_type=EventType.DEFENSE_EVASION,
            hostname=workstation,
            username=user,
            process_name="wevtutil.exe",
            mitre_tactic="defense_evasion",
            mitre_technique="T1055",
            description="Event log clearing attempt",
            base_severity=8.0,
        ),
        SecurityEvent(
            event_id=generate_event_id(),
            timestamp=base_time + timedelta(hours=1, minutes=30),
            event_type=EventType.PRIVILEGE_ESCALATION,
            hostname=workstation,
            username=user,
            process_name="cmd.exe",
            mitre_tactic="privilege_escalation",
            mitre_technique="T1078",
            description="Privilege escalation attempt",
            base_severity=7.5,
        ),
    ])
    
    db.add_all(events)
    return events


def create_web_attack_scenario(base_time: datetime, db):
    """Create a web application attack scenario (10 events)"""
    events = []
    attacker_ip = "203.0.113.50"
    web_server = SAMPLE_DATA["hosts"][1]
    
    for i in range(5):
        events.append(SecurityEvent(
            event_id=generate_event_id(),
            timestamp=base_time + timedelta(minutes=i * 2),
            event_type=EventType.INITIAL_ACCESS,
            source_ip=attacker_ip,
            dest_ip=SAMPLE_DATA["ips"][4],
            dest_port=443,
            hostname=web_server,
            mitre_tactic="initial_access",
            mitre_technique="T1190",
            description=f"SQL injection attempt #{i+1}",
            base_severity=6.0 + i * 0.5,
        ))
    
    events.extend([
        SecurityEvent(
            event_id=generate_event_id(),
            timestamp=base_time + timedelta(minutes=15),
            event_type=EventType.INITIAL_ACCESS,
            source_ip=attacker_ip,
            dest_ip=SAMPLE_DATA["ips"][4],
            dest_port=443,
            hostname=web_server,
            mitre_tactic="initial_access",
            mitre_technique="T1190",
            description="Successful SQL injection - DB access",
            base_severity=9.0,
        ),
        SecurityEvent(
            event_id=generate_event_id(),
            timestamp=base_time + timedelta(minutes=20),
            event_type=EventType.COLLECTION,
            hostname=web_server,
            mitre_tactic="collection",
            mitre_technique="T1005",
            description="Database query - customer PII access",
            base_severity=8.5,
        ),
        SecurityEvent(
            event_id=generate_event_id(),
            timestamp=base_time + timedelta(minutes=30),
            event_type=EventType.PERSISTENCE,
            source_ip=attacker_ip,
            hostname=web_server,
            file_hash=SAMPLE_DATA["hashes"][0],
            mitre_tactic="persistence",
            mitre_technique="T1053",
            description="Web shell upload",
            base_severity=9.0,
        ),
        SecurityEvent(
            event_id=generate_event_id(),
            timestamp=base_time + timedelta(minutes=35),
            event_type=EventType.INITIAL_ACCESS,
            hostname=web_server,
            process_name="cmd.exe",
            mitre_tactic="execution",
            mitre_technique="T1059",
            description="OS command execution via web shell",
            base_severity=8.5,
        ),
        SecurityEvent(
            event_id=generate_event_id(),
            timestamp=base_time + timedelta(minutes=45),
            event_type=EventType.DATA_EXFILTRATION,
            source_ip=SAMPLE_DATA["ips"][4],
            dest_ip=attacker_ip,
            dest_port=443,
            mitre_tactic="data_exfiltration",
            mitre_technique="T1041",
            description="Database dump exfiltration",
            base_severity=9.5,
        ),
    ])
    
    db.add_all(events)
    return events


def create_malware_outbreak_scenario(base_time: datetime, db):
    """Create a malware outbreak scenario (8 events)"""
    events = []
    
    hosts = SAMPLE_DATA["hosts"][:8]
    for i, host in enumerate(hosts):
        events.append(SecurityEvent(
            event_id=generate_event_id(),
            timestamp=base_time + timedelta(minutes=i * 10),
            event_type=EventType.MALWARE_DETECTED,
            source_ip=f"192.168.1.{100+i}",
            hostname=host,
            process_name="svchost.exe",
            file_hash=SAMPLE_DATA["hashes"][i % 2],
            mitre_tactic="execution",
            mitre_technique="T1059",
            description=f"Malware detected on {host}",
            base_severity=7.0 + (i * 0.3),
        ))
    
    db.add_all(events)
    return events


def seed_all_demo_data(db):
    """Seed all demo data - 50 events across 5 scenarios"""
    base_time = datetime.utcnow() - timedelta(hours=24)
    
    db.query(SecurityEvent).delete()
    
    scenarios = {
        "ransomware": create_ransomware_scenario(base_time, db),
        "apt": create_apt_scenario(base_time - timedelta(days=2), db),
        "insider_threat": create_insider_threat_scenario(base_time - timedelta(hours=12), db),
        "web_attack": create_web_attack_scenario(base_time - timedelta(hours=6), db),
        "malware_outbreak": create_malware_outbreak_scenario(base_time - timedelta(hours=3), db),
    }
    
    db.commit()
    
    total = sum(len(events) for events in scenarios.values())
    
    return {
        "total_events": total,
        "scenarios": {name: len(events) for name, events in scenarios.items()},
    }


if __name__ == "__main__":
    from utils.database import init_db, SessionLocal
    
    init_db()
    db = SessionLocal()
    
    result = seed_all_demo_data(db)
    print(f"✓ Demo data seeded: {result}")
    
    db.close()