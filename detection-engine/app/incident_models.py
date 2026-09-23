from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class IncidentORM(Base):

    __tablename__ = "incidents"

    incident_id: Mapped[str] = mapped_column(String, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    pattern: Mapped[str] = mapped_column(String, index=True)
    window_seconds: Mapped[int] = mapped_column(Integer)
    correlated_event_ids: Mapped[list] = mapped_column(JSON)
    mitre_techniques: Mapped[list] = mapped_column(JSON)
    severity: Mapped[str] = mapped_column(String, index=True)
    confidence: Mapped[float] = mapped_column(Float)
    summary: Mapped[str] = mapped_column(String)