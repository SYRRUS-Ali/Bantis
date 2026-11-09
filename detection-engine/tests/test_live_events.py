from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from app.db import Base, engine
    from app.main import app

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as client:
        yield client


def seed(event_id, received_at, *, timestamp=None, level="info", details=None):
    from app.db import SessionLocal
    from app.event_models import EventORM

    with SessionLocal() as session:
        session.add(
            EventORM(
                event_id=event_id,
                timestamp=timestamp or received_at,
                received_at=received_at,
                level=level,
                logger="fixture",
                source="pipeline",
                event_type="fixture_event",
                message="private-message",
                details=details or {},
            )
        )
        session.commit()


def test_recent_events_empty_and_validation(client):
    assert client.get("/events").json() == {"total": 0, "limit": 500, "items": []}
    assert client.get("/events?limit=0").status_code == 422
    assert client.get("/events?limit=501").status_code == 422


def test_received_order_includes_late_event_times_and_deterministic_ties(client):
    now = datetime(2026, 11, 9, 12, tzinfo=timezone.utc)
    seed("a", now)
    seed("b", now)
    seed("late", now + timedelta(seconds=1), timestamp=now - timedelta(days=1))
    page = client.get("/events?limit=2").json()
    assert page["total"] == 3
    assert [event["event_id"] for event in page["items"]] == ["late", "b"]
    assert page["items"][0]["timestamp"] == "2026-11-08T12:00:00Z"
    assert page["items"][0]["received_at"] == "2026-11-09T12:00:01Z"
    assert page["items"][0]["level"] == "INFO"


def test_feed_selects_scalar_details_and_never_returns_messages(client):
    seed(
        "secret",
        datetime.now(timezone.utc),
        details={
            "scenario": "malicious-dependency",
            "artifact": "package==1.0",
            "tool_returncode": 1,
            "tool_output_tail": "private-tool-output",
            "token": "private-token",
            "image": {"unexpected": "private-nested-content"},
        },
    )
    response = client.get("/events")
    assert response.json()["items"][0]["details"] == {
        "scenario": "malicious-dependency",
        "artifact": "package==1.0",
        "tool_returncode": 1,
    }
    for secret in [
        "private-message",
        "private-tool-output",
        "private-token",
        "private-nested-content",
    ]:
        assert secret not in response.text


def test_recent_query_does_not_change_ingestion_idempotency(client):
    event = {
        "event_id": "same",
        "timestamp": "2026-11-09T12:00:00Z",
        "level": "INFO",
        "logger": "fixture",
        "source": "pipeline",
        "event_type": "fixture",
        "message": "private",
        "details": {},
    }
    assert client.post("/events", json=event).status_code == 201
    assert client.post("/events", json=event).status_code == 200
    assert client.get("/events").json()["total"] == 1