from datetime import datetime

from pydantic import BaseModel, ConfigDict


class EventIn(BaseModel):

    timestamp: datetime
    level: str
    logger: str
    source: str
    event_type: str
    event_id: str
    message: str
    details: dict = {}


class EventOut(EventIn):
    received_at: datetime

    model_config = ConfigDict(from_attributes=True)