from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

_VALID_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


class EventIn(BaseModel):

    timestamp: datetime
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
    received_at: datetime

    model_config = ConfigDict(from_attributes=True)