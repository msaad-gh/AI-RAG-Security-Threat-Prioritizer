"""Core event schemas for ThreatIQ ingestion and normalization."""

import ipaddress
from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field, model_validator


class AssetCriticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventSeverity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Numeric mapping used for ML features and scoring.
ASSET_CRITICALITY_SCORES: dict[AssetCriticality, int] = {
    AssetCriticality.LOW: 1,
    AssetCriticality.MEDIUM: 2,
    AssetCriticality.HIGH: 4,
    AssetCriticality.CRITICAL: 5,
}

# Private/known networks treated as internal assets.
KNOWN_IP_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("192.168.0.0/16"),
]


class EventInput(BaseModel):
    """Raw security event as received from an ingestion source."""

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime | str
    source_ip: str
    dest_ip: Optional[str] = None
    event_type: str
    username: Optional[str] = None
    attempts: int = 1
    bytes_transferred: int = 0
    port: int = 0
    asset: str = "unknown"
    asset_criticality: AssetCriticality = AssetCriticality.LOW
    protocol: Optional[str] = "TCP"
    raw_payload: Optional[dict] = None

    @model_validator(mode="after")
    def coerce_timestamp(self) -> "EventInput":
        """Accept ISO-8601 strings for timestamp and store a datetime."""
        if isinstance(self.timestamp, str):
            self.timestamp = datetime.fromisoformat(self.timestamp)
        return self


class NormalizedEvent(EventInput):
    """Event enriched with numeric features for detection and scoring."""

    hour_of_day: int = Field(ge=0, le=23)
    is_known_ip: int = Field(ge=0, le=1)
    asset_criticality_score: int = Field(ge=1, le=5)
    anomaly_score: float = 0.0
    is_anomaly: bool = False


def _is_known_ip(ip: Optional[str]) -> int:
    """Return 1 if the IP belongs to a private/known network, else 0."""
    if not ip:
        return 0
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return 0
    return int(any(address in network for network in KNOWN_IP_NETWORKS))


def normalize_event(event: EventInput) -> NormalizedEvent:
    """Convert an EventInput into a feature-rich NormalizedEvent.

    - Parses ISO timestamps (already coerced by the model validator).
    - Extracts hour_of_day (0-23) from the event timestamp.
    - Maps asset criticality to a 1-5 numeric score.
    - Flags whether the source IP is within known private networks.
    """
    timestamp = event.timestamp
    if isinstance(timestamp, str):
        timestamp = datetime.fromisoformat(timestamp)

    return NormalizedEvent(
        **event.model_dump(),
        hour_of_day=timestamp.hour,
        is_known_ip=_is_known_ip(event.source_ip),
        asset_criticality_score=ASSET_CRITICALITY_SCORES[event.asset_criticality],
    )
