import threading
import time
from datetime import datetime, timezone

import pytest

from app.scheduler import CorrelationScheduler, interval_from_env


@pytest.fixture
def db(monkeypatch):
    from app.db import Base, SessionLocal, engine

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    return SessionLocal


def _store(session_factory, event_id, scenario):
    from app.event_models import EventORM

    with session_factory() as session:
        session.add(
            EventORM(
                event_id=event_id, timestamp=datetime.now(timezone.utc), level="INFO", logger="attack_sim",
                source="attack-sim", event_type="attack_scenario_run", message="m",
                details={"scenario": scenario, "status": "failure", "mitre_technique": "T1195.001"},
            )
        )
        session.commit()


def test_a_pass_persists_what_it_finds_and_the_next_pass_finds_nothing_new(db):
    _store(db, "dep", "malicious-dependency")
    _store(db, "sec", "leaked-secret")
    scheduler = CorrelationScheduler(interval_seconds=60, session_factory=db)

    assert [i.pattern for i in scheduler.run_once()] == ["composite-dependency-secret"]
    assert scheduler.run_once() == []


def test_a_failing_pass_does_not_stop_the_schedule(db):
    calls = []
    failed_once = threading.Event()

    def flaky_session():
        calls.append(time.monotonic())
        if not failed_once.is_set():
            failed_once.set()
            raise RuntimeError("database is locked")
        return db()

    scheduler = CorrelationScheduler(interval_seconds=0.05, session_factory=flaky_session)
    scheduler.start()
    deadline = time.monotonic() + 3
    while len(calls) < 3 and time.monotonic() < deadline:
        time.sleep(0.02)
    scheduler.stop()

    assert len(calls) >= 3  # it kept going after the failure


def test_the_app_correlates_on_its_own_when_an_interval_is_set(db, monkeypatch):
    from fastapi.testclient import TestClient

    from app.main import app

    monkeypatch.setenv("CORRELATION_INTERVAL_SECONDS", "0.05")
    with TestClient(app) as client:
        for event_id, scenario in [("dep", "malicious-dependency"), ("sec", "leaked-secret")]:
            client.post("/events", json={
                "timestamp": datetime.now(timezone.utc).isoformat(), "level": "INFO", "logger": "attack_sim",
                "source": "attack-sim", "event_type": "attack_scenario_run", "event_id": event_id, "message": "m",
                "details": {"scenario": scenario, "status": "failure", "mitre_technique": "T1195.001"},
            })
        deadline = time.monotonic() + 3
        while client.get("/incidents").json()["total"] == 0 and time.monotonic() < deadline:
            time.sleep(0.05)

        assert [i["pattern"] for i in client.get("/incidents").json()["items"]] == ["composite-dependency-secret"]


@pytest.mark.parametrize("raw, expected", [(None, 10.0), ("", 10.0), ("2.5", 2.5), ("0", 0.0)])
def test_the_interval_comes_from_the_environment(monkeypatch, raw, expected):
    if raw is None:
        monkeypatch.delenv("CORRELATION_INTERVAL_SECONDS", raising=False)
    else:
        monkeypatch.setenv("CORRELATION_INTERVAL_SECONDS", raw)

    assert interval_from_env() == expected


def test_a_negative_interval_is_refused(monkeypatch):
    monkeypatch.setenv("CORRELATION_INTERVAL_SECONDS", "-1")

    with pytest.raises(ValueError):
        interval_from_env()