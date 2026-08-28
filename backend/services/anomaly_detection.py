import numpy as np
from sklearn.ensemble import IsolationForest
from typing import List, Dict, Any, Optional

class AnomalyDetectionService:
    """
    Isolation Forest-based anomaly detection for security events.
    
    Features used:
    - Base severity score
    - Event type encoding
    - Port numbers
    - MITRE technique presence
    - File hash presence
    - Username presence
    """
    
    EVENT_TYPE_ENCODING = {
        "network_scan": 0, "malware_detected": 1, "phishing_attempt": 2,
        "data_exfiltration": 3, "privilege_escalation": 4, "lateral_movement": 5,
        "command_control": 6, "initial_access": 7, "persistence": 8,
        "defense_evasion": 9, "credential_access": 10, "discovery": 11,
        "collection": 12, "impact": 13, "unknown": 14,
    }
    
    def __init__(self, contamination: float = 0.1, n_estimators: int = 100):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.model: Optional[IsolationForest] = None
        self.is_fitted = False
    
    def _extract_features(self, event: Dict[str, Any]) -> np.ndarray:
        """Extract numeric features from an event for anomaly detection."""
        features = []
        
        # 1. Base severity (0-10)
        features.append(event.get("base_severity", 0.0) / 10.0)
        
        # 2. Event type encoding (0-14)
        event_type = event.get("event_type", "unknown")
        if hasattr(event_type, 'value'):
            event_type = event_type.value
        type_encoded = self.EVENT_TYPE_ENCODING.get(str(event_type), 14) / 14.0
        features.append(type_encoded)
        
        # 3. Destination port (normalized)
        dest_port = event.get("dest_port") or 0
        features.append(min(dest_port / 65535.0, 1.0))
        
        # 4. Is well-known port (0-1023)?
        is_well_known = 1.0 if dest_port and dest_port < 1024 else 0.0
        features.append(is_well_known)
        
        # 5. Has MITRE technique?
        has_mitre = 1.0 if event.get("mitre_technique") else 0.0
        features.append(has_mitre)
        
        # 6. Has file hash?
        has_hash = 1.0 if event.get("file_hash") else 0.0
        features.append(has_hash)
        
        # 7. Has username?
        has_user = 1.0 if event.get("username") else 0.0
        features.append(has_user)
        
        return np.array(features)
    
    def score_events(self, events: List[Dict[str, Any]]) -> List[float]:
        """
        Score events for anomaly detection.
        
        Returns:
            List of anomaly scores (0-1, higher = more anomalous)
        """
        if len(events) < 3:
            return [0.5] * len(events)
        
        # Extract features
        X = np.array([self._extract_features(e) for e in events])
        
        # Fit model
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1
        )
        self.model.fit(X)
        self.is_fitted = True
        
        # Get anomaly scores (negative = more anomalous in sklearn)
        raw_scores = self.model.score_samples(X)
        
        # Convert to 0-1 scale (higher = more anomalous)
        min_score = raw_scores.min()
        max_score = raw_scores.max()
        
        if max_score - min_score > 1e-8:
            normalized_scores = 1.0 - (raw_scores - min_score) / (max_score - min_score)
        else:
            normalized_scores = np.zeros_like(raw_scores)
        
        return normalized_scores.tolist()
    
    def detect_anomalies(
        self, 
        events: List[Dict[str, Any]], 
        threshold: Optional[float] = None
    ) -> tuple[List[float], List[int]]:
        """
        Detect anomalous events.
        
        Returns:
            Tuple of (scores, anomaly_indices)
        """
        scores = self.score_events(events)
        
        if threshold is None:
            threshold = 1.0 - self.contamination
        
        anomaly_indices = [i for i, s in enumerate(scores) if s >= threshold]
        
        return scores, anomaly_indices
    
    def get_threshold(self) -> float:
        """Get the current anomaly threshold"""
        return 1.0 - self.contamination


# Global instance
anomaly_detector = AnomalyDetectionService(contamination=0.15, n_estimators=100)