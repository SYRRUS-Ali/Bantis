import pytest

_VALID_EVENT = {
    "timestamp": "2026-09-24T12:00:00Z",
    "level": "INFO",
    "logger": "attack_sim",
    "source": "attack-sim",
    "event_type": "attack_scenario_run",
    "event_id": "11111111-1111-1111-1111-111111111111",
    "message": "no-op scenario executed",
    "details": {"scenario": "noop", "mitre_technique": "N/A", "status": "success"},
}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")

    from fastapi.testclient import TestClient

    from app.db import Base, engine
    from app.main import app

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    with TestClient(app) as test_client:
        yield test_client


def test_ingest_event_stores_it_and_returns_201(client):
    response = client.post("/events", json=_VALID_EVENT)

    assert response.status_code == 201
    body = response.json()
    assert body["event_id"] == _VALID_EVENT["event_id"]
    assert body["source"] == "attack-sim"
    assert body["details"] == _VALID_EVENT["details"]
    assert "received_at" in body


def test_ingest_duplicate_event_id_returns_the_existing_record_not_an_error(client):
    client.post("/events", json=_VALID_EVENT)

    duplicate = dict(_VALID_EVENT, message="a different message, same event_id")
    response = client.post("/events", json=duplicate)

    assert response.status_code == 200
    assert response.json()["message"] == _VALID_EVENT["message"]


def test_ingest_event_missing_a_required_field_returns_422(client):
    incomplete = dict(_VALID_EVENT)
    del incomplete["source"]

    response = client.post("/events", json=incomplete)

    assert response.status_code == 422


def test_ingest_event_defaults_details_to_an_empty_dict(client):
    event = dict(_VALID_EVENT)
    del event["details"]

    response = client.post("/events", json=event)

    assert response.status_code == 201
    assert response.json()["details"] == {}


def test_health_check(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.parametrize("field", ["level", "logger", "source", "event_type", "event_id"])
def test_ingest_event_rejects_an_empty_identifier_field(client, field):
    event = dict(_VALID_EVENT, **{field: ""})

    response = client.post("/events", json=event)

    assert response.status_code == 422


def test_ingest_event_rejects_an_unknown_log_level(client):
    event = dict(_VALID_EVENT, level="BANANA")

    response = client.post("/events", json=event)

    assert response.status_code == 422


@pytest.mark.parametrize("level", ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
def test_ingest_event_accepts_every_real_log_level(client, level):
    event = dict(_VALID_EVENT, event_id=f"level-check-{level}", level=level)

    response = client.post("/events", json=event)

    assert response.status_code == 201