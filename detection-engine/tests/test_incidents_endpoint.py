from datetime import datetime, timedelta, timezone

import pytest

_T0 = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc)


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


def _seed_incident(
    incident_id,
    created_at=_T0,
    pattern="same-source-burst",
    severity="medium",
    confidence=0.3,
    correlated_event_ids=None,
    mitre_techniques=None,
    window_seconds=60,
    summary="test incident",
):
    from app.db import SessionLocal
    from app.incident_models import IncidentORM

    session = SessionLocal()
    session.add(
        IncidentORM(
            incident_id=incident_id,
            created_at=created_at,
            pattern=pattern,
            window_seconds=window_seconds,
            correlated_event_ids=correlated_event_ids or ["e1", "e2"],
            mitre_techniques=mitre_techniques or ["T1195.001"],
            severity=severity,
            confidence=confidence,
            summary=summary,
        )
    )
    session.commit()
    session.close()


def test_list_incidents_is_empty_when_none_exist(client):
    response = client.get("/incidents")

    assert response.status_code == 200
    assert response.json() == {"total": 0, "limit": 50, "offset": 0, "items": []}


def test_list_incidents_returns_newest_first(client):
    _seed_incident("older", created_at=_T0)
    _seed_incident("newer", created_at=_T0 + timedelta(minutes=5))

    response = client.get("/incidents")

    ids = [item["incident_id"] for item in response.json()["items"]]
    assert ids == ["newer", "older"]


def test_list_incidents_reports_the_full_total_regardless_of_limit(client):
    for i in range(5):
        _seed_incident(f"i{i}", created_at=_T0 + timedelta(minutes=i))

    response = client.get("/incidents?limit=2")
    body = response.json()

    assert body["total"] == 5
    assert len(body["items"]) == 2


def test_list_incidents_paginates_with_limit_and_offset(client):
    for i in range(5):
        _seed_incident(f"i{i}", created_at=_T0 + timedelta(minutes=i))

    first_page = client.get("/incidents?limit=2&offset=0").json()["items"]
    second_page = client.get("/incidents?limit=2&offset=2").json()["items"]

    first_ids = {item["incident_id"] for item in first_page}
    second_ids = {item["incident_id"] for item in second_page}
    assert first_ids.isdisjoint(second_ids)


def test_list_incidents_filters_by_exact_severity(client):
    _seed_incident("low-one", severity="medium")
    _seed_incident("high-one", severity="high")

    response = client.get("/incidents?severity=high")
    ids = [item["incident_id"] for item in response.json()["items"]]

    assert ids == ["high-one"]


def test_list_incidents_rejects_an_unknown_severity(client):
    response = client.get("/incidents?severity=bogus")

    assert response.status_code == 422


def test_list_incidents_filters_by_exact_pattern(client):
    _seed_incident("burst", pattern="same-source-burst")
    _seed_incident("composite", pattern="composite-dependency-secret")

    response = client.get("/incidents?pattern=composite-dependency-secret")
    ids = [item["incident_id"] for item in response.json()["items"]]

    assert ids == ["composite"]


def test_list_incidents_filters_by_since(client):
    _seed_incident("before", created_at=_T0)
    _seed_incident("after", created_at=_T0 + timedelta(hours=1))

    response = client.get("/incidents", params={"since": (_T0 + timedelta(minutes=30)).isoformat()})
    ids = [item["incident_id"] for item in response.json()["items"]]

    assert ids == ["after"]


def test_list_incidents_combines_filters(client):
    _seed_incident("match", pattern="same-source-burst", severity="high")
    _seed_incident("wrong-severity", pattern="same-source-burst", severity="medium")
    _seed_incident("wrong-pattern", pattern="composite-dependency-secret", severity="high")

    response = client.get("/incidents?pattern=same-source-burst&severity=high")
    ids = [item["incident_id"] for item in response.json()["items"]]

    assert ids == ["match"]


def test_get_incident_returns_the_full_record(client):
    _seed_incident(
        "full-detail",
        correlated_event_ids=["dep", "sec"],
        mitre_techniques=["T1195.001", "T1552.001"],
        severity="critical",
        confidence=0.9,
        window_seconds=300,
        pattern="composite-dependency-secret",
        summary="malicious-dependency + leaked-secret within 300s",
    )

    response = client.get("/incidents/full-detail")
    body = response.json()

    assert response.status_code == 200
    assert body["incident_id"] == "full-detail"
    assert body["pattern"] == "composite-dependency-secret"
    assert body["correlated_event_ids"] == ["dep", "sec"]
    assert body["mitre_techniques"] == ["T1195.001", "T1552.001"]
    assert body["severity"] == "critical"
    assert body["confidence"] == 0.9
    assert body["window_seconds"] == 300
    assert body["summary"] == "malicious-dependency + leaked-secret within 300s"


def test_get_incident_returns_404_when_not_found(client):
    response = client.get("/incidents/does-not-exist")

    assert response.status_code == 404