from datetime import datetime, timezone
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator

_VALID_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


def as_utc(value: datetime) -> datetime:
    """Every time is UTC inside detection-engine. SQLite drops the offset
    on storage, so an un-normalized "+03:00" would be stored as wall-clock
    time three hours off -- and correlation windows compare these values.
    A naive value is taken to already be UTC, which is what's stored.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


UtcDatetime = Annotated[datetime, AfterValidator(as_utc)]


class EventIn(BaseModel):

    timestamp: UtcDatetime
    level: str = Field(min_length=1)
    logger: str = Field(min_length=1)
    source: str = Field(min_length=1)
    event_type: str = Field(min_length=1)
    event_id: str = Field(min_length=1)
    message: str
    details: dict = {}

    @field_validator("level")
    @classmethod
    def _level_is_a_known_log_level(cls, value: str) -> str:
        if value.upper() not in _VALID_LEVELS:
            raise ValueError(f"level must be one of {sorted(_VALID_LEVELS)}, got {value!r}")
        return value


class EventOut(EventIn):
    received_at: UtcDatetime

    model_config = ConfigDict(from_attributes=True)


class IncidentOut(BaseModel):

    incident_id: str
    created_at: UtcDatetime
    pattern: str
    window_seconds: int
    correlated_event_ids: list[str]
    mitre_techniques: list[str]
    severity: str
    confidence: float
    summary: str

    model_config = ConfigDict(from_attributes=True)


class IncidentListOut(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[IncidentOut]