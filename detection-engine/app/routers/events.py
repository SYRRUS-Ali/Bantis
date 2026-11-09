from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db import get_session
from app.event_models import EventORM
from app.models import EventIn, EventOut, LiveEventListOut

router = APIRouter(prefix="/events", tags=["events"])


@router.get("", response_model=LiveEventListOut)
def recent_events(
    limit: int = Query(default=500, ge=1, le=500),
    session: Session = Depends(get_session),
) -> LiveEventListOut:
    query = session.query(EventORM)
    total = query.count()
    items = (
        query.order_by(EventORM.received_at.desc(), EventORM.event_id.desc())
        .limit(limit)
        .all()
    )
    return LiveEventListOut(total=total, limit=limit, items=items)


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
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        response.status_code = status.HTTP_200_OK
        return session.get(EventORM, event.event_id)

    session.refresh(row)
    response.status_code = status.HTTP_201_CREATED
    return row