"""Analyst action schemas for incident lifecycle management."""

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel


class AnalystActionCreate(BaseModel):
    """Payload for recording an analyst action on an incident."""

    action: Literal["acknowledge", "escalate", "resolve"]
    analyst_note: Optional[str] = None


class AnalystActionResponse(BaseModel):
    """Recorded analyst action as returned by the API."""

    id: str
    incident_id: str
    action: str
    created_at: datetime
    analyst_note: Optional[str] = None
