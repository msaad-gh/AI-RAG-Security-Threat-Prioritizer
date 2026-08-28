"""Pydantic model for composite risk score factor storage."""

from typing import Any, ClassVar, Dict, List

from pydantic import BaseModel, Field


class ScoreFactors(BaseModel):
    """Point breakdown for a composite risk score (0-100).

    Each field holds the points earned for one scoring factor, capped at
    the factor's maximum. ``total_score`` is the sum of all factors.
    """

    # Display names and max points per factor, in reporting order.
    FACTOR_META: ClassVar[List[Dict[str, Any]]] = [
        {"key": "base_severity", "name": "Base Severity", "max_points": 20},
        {"key": "anomaly_score_pts", "name": "Anomaly Score", "max_points": 20},
        {"key": "asset_criticality_pts", "name": "Asset Criticality", "max_points": 20},
        {"key": "exploitability_pts", "name": "Exploitability", "max_points": 15},
        {"key": "evidence_count_pts", "name": "Evidence Count", "max_points": 10},
        {"key": "recency_pts", "name": "Recency", "max_points": 10},
        {"key": "ti_relevance_pts", "name": "TI Relevance", "max_points": 5},
    ]

    base_severity: int = Field(ge=0, le=20)
    anomaly_score_pts: int = Field(ge=0, le=20)
    asset_criticality_pts: int = Field(ge=0, le=20)
    exploitability_pts: int = Field(ge=0, le=15)
    evidence_count_pts: int = Field(ge=0, le=10)
    recency_pts: int = Field(ge=0, le=10)
    ti_relevance_pts: int = Field(ge=0, le=5)
    total_score: int = Field(ge=0, le=100)

    # Human-readable justification per factor key, populated by the scorer.
    reasons: Dict[str, str] = Field(default_factory=dict)

    def to_breakdown_dict(self) -> Dict[str, Any]:
        """Return a per-factor breakdown with points, max points, and reason."""
        factors = [
            {
                "factor": meta["name"],
                "points": getattr(self, meta["key"]),
                "max_points": meta["max_points"],
                "reason": self.reasons.get(meta["key"], ""),
            }
            for meta in self.FACTOR_META
        ]
        return {
            "factors": factors,
            "total_score": self.total_score,
            "max_total": sum(meta["max_points"] for meta in self.FACTOR_META),
        }
