from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.orm import Session

from app.db import get_session
from app.event_models import EventORM
from app.models import EventIn, EventOut

router = APIRouter(prefix="/events", tags=["events"])


@router.post("", response_model=EventOut)
def ingest_event(
    event: EventIn, response: Response, session: Session = Depends(get_session)
) -> EventORM:
    existing = session.get(EventORM, event.event_id)
    if existing is not None:
        response.status_code = status.HTTP_200_OK
        return existing

    row = EventORM(**event.model_dump())
    session.add(row)
    session.commit()
    session.refresh(row)
    response.status_code = status.HTTP_201_CREATED
    return row