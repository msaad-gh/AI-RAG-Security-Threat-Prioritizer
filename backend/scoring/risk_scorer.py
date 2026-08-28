"""Composite risk scoring engine for ThreatIQ incidents.

Combines seven weighted factors (base severity, anomaly score, asset
criticality, exploitability, evidence count, recency, and threat-intel
relevance) into a single explainable 0-100 composite risk score.
"""

from datetime import datetime, timezone
from typing import Any, ClassVar, Dict, Optional

from backend.scoring.score_factors import ScoreFactors


class RiskScorer:
    """Computes composite risk scores for correlated incidents."""

    SEVERITY_POINTS: ClassVar[Dict[str, int]] = {
        "low": 5,
        "medium": 10,
        "high": 15,
        "critical": 20,
    }
    ASSET_CRITICALITY_POINTS: ClassVar[Dict[str, int]] = {
        "low": 4,
        "medium": 8,
        "high": 14,
        "critical": 20,
    }

    def calculate(
        self,
        incident_dict: Dict[str, Any],
        anomaly_score_float: float,
    ) -> ScoreFactors:
        """Compute the composite risk score for an incident.

        Args:
            incident_dict: incident payload with keys ``severity``,
                ``asset_criticality``, ``has_known_exploit``,
                ``has_active_exploit``, ``events``, ``latest_event_time``,
                ``mitre_technique_matched``, and ``high_relevance_ti``.
            anomaly_score_float: Isolation Forest anomaly score in [0.0, 1.0].

        Returns:
            A fully populated ScoreFactors object (total 0-100).
        """
        base_severity, severity_reason = self._score_base_severity(
            incident_dict.get("severity")
        )
        anomaly_pts, anomaly_reason = self._score_anomaly(anomaly_score_float)
        criticality_pts, criticality_reason = self._score_asset_criticality(
            incident_dict.get("asset_criticality")
        )
        exploitability_pts, exploitability_reason = self._score_exploitability(
            incident_dict
        )
        evidence_pts, evidence_reason = self._score_evidence_count(
            incident_dict.get("events") or []
        )
        recency_pts, recency_reason = self._score_recency(
            incident_dict.get("latest_event_time")
        )
        ti_pts, ti_reason = self._score_ti_relevance(incident_dict)

        total_score = (
            base_severity
            + anomaly_pts
            + criticality_pts
            + exploitability_pts
            + evidence_pts
            + recency_pts
            + ti_pts
        )

        return ScoreFactors(
            base_severity=base_severity,
            anomaly_score_pts=anomaly_pts,
            asset_criticality_pts=criticality_pts,
            exploitability_pts=exploitability_pts,
            evidence_count_pts=evidence_pts,
            recency_pts=recency_pts,
            ti_relevance_pts=ti_pts,
            total_score=total_score,
            reasons={
                "base_severity": severity_reason,
                "anomaly_score_pts": anomaly_reason,
                "asset_criticality_pts": criticality_reason,
                "exploitability_pts": exploitability_reason,
                "evidence_count_pts": evidence_reason,
                "recency_pts": recency_reason,
                "ti_relevance_pts": ti_reason,
            },
        )

    # ------------------------------------------------------------------ #
    # Factor scoring helpers (each returns (points, reason))
    # ------------------------------------------------------------------ #

    def _score_base_severity(self, severity: Optional[str]) -> tuple[int, str]:
        """Low=5, Medium=10, High=15, Critical=20."""
        label = str(severity or "low").lower()
        points = self.SEVERITY_POINTS.get(label, self.SEVERITY_POINTS["low"])
        return points, f"Primary event severity is {label.upper()}"

    def _score_anomaly(self, anomaly_score_float: float) -> tuple[int, str]:
        """anomaly_score x 20, rounded to int."""
        clipped = max(0.0, min(1.0, float(anomaly_score_float)))
        points = round(clipped * 20)
        return points, f"Isolation Forest anomaly score is {clipped:.2f}"

    def _score_asset_criticality(self, criticality: Optional[str]) -> tuple[int, str]:
        """Low=4, Medium=8, High=14, Critical=20."""
        label = str(criticality or "low").lower()
        points = self.ASSET_CRITICALITY_POINTS.get(
            label, self.ASSET_CRITICALITY_POINTS["low"]
        )
        return points, f"Targeted asset criticality is {label.upper()}"

    def _score_exploitability(
        self, incident_dict: Dict[str, Any]
    ) -> tuple[int, str]:
        """Active exploit=15, known PoC=8, none=0."""
        if incident_dict.get("has_active_exploit"):
            return 15, "An active exploit is being used in the wild"
        if incident_dict.get("has_known_exploit"):
            return 8, "A known proof-of-concept exploit exists"
        return 0, "No known exploit for this technique"

    def _score_evidence_count(self, events: list) -> tuple[int, str]:
        """1 event=2, 2-3 events=5, 4+ events=10."""
        count = len(events)
        if count >= 4:
            points = 10
        elif count >= 2:
            points = 5
        elif count == 1:
            points = 2
        else:
            points = 0
        return points, f"{count} correlated event(s) support this incident"

    def _score_recency(self, latest_event_time: Any) -> tuple[int, str]:
        """>1440min=2, 60-1440min=5, 10-60min=8, <10min=10."""
        minutes_ago = self._minutes_since(latest_event_time)
        if minutes_ago is None:
            return 0, "No event timestamp available"
        if minutes_ago > 1440:
            points = 2
        elif minutes_ago >= 60:
            points = 5
        elif minutes_ago >= 10:
            points = 8
        else:
            points = 10
        return points, f"Most recent event was {minutes_ago:.0f} minutes ago"

    def _score_ti_relevance(self, incident_dict: Dict[str, Any]) -> tuple[int, str]:
        """High-relevance TI=5, MITRE technique matched=3, none=0."""
        if incident_dict.get("high_relevance_ti"):
            return 5, "Technique appears in high-relevance threat intelligence"
        if incident_dict.get("mitre_technique_matched"):
            return 3, "MITRE ATT&CK technique matched in threat intelligence"
        return 0, "No matching threat intelligence"

    # ------------------------------------------------------------------ #
    # Timestamp parsing
    # ------------------------------------------------------------------ #

    def _minutes_since(self, latest_event_time: Any) -> Optional[float]:
        """Return minutes elapsed since the latest event, or None if unknown."""
        if latest_event_time is None:
            return None
        if isinstance(latest_event_time, str):
            try:
                latest_event_time = datetime.fromisoformat(
                    latest_event_time.replace("Z", "+00:00")
                )
            except ValueError:
                return None
        if not isinstance(latest_event_time, datetime):
            return None
        if latest_event_time.tzinfo is None:
            latest_event_time = latest_event_time.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - latest_event_time
        return max(0.0, delta.total_seconds() / 60)
