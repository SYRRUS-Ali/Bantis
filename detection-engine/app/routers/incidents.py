from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db import get_session
from app.incident_models import IncidentORM
from app.models import IncidentListOut, IncidentOut

router = APIRouter(prefix="/incidents", tags=["incidents"])

_VALID_SEVERITIES = {"low", "medium", "high", "critical"}


@router.get("", response_model=IncidentListOut)
def list_incidents(
    severity: str | None = Query(default=None, description="Exact match, e.g. 'high'."),
    pattern: str | None = Query(default=None, description="Exact match, e.g. 'same-source-burst'."),
    since: datetime | None = Query(default=None, description="Only incidents created at or after this time."),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
) -> IncidentListOut:
    if severity is not None and severity not in _VALID_SEVERITIES:
        raise HTTPException(
            status_code=422, detail=f"severity must be one of {sorted(_VALID_SEVERITIES)}, got {severity!r}"
        )

    query = session.query(IncidentORM)
    if severity is not None:
        query = query.filter(IncidentORM.severity == severity)
    if pattern is not None:
        query = query.filter(IncidentORM.pattern == pattern)
    if since is not None:
        query = query.filter(IncidentORM.created_at >= since)

    total = query.count()
    items = query.order_by(IncidentORM.created_at.desc()).offset(offset).limit(limit).all()

    return IncidentListOut(total=total, limit=limit, offset=offset, items=items)


@router.get("/{incident_id}", response_model=IncidentOut)
def get_incident(incident_id: str, session: Session = Depends(get_session)) -> IncidentORM:
    incident = session.get(IncidentORM, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"no incident with incident_id {incident_id!r}")
    return incident