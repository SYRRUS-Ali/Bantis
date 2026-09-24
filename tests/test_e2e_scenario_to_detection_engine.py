import sys
import threading
import time
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "detection-engine"))
sys.path.insert(0, str(_REPO_ROOT / "attack-sim"))

_PORT = 18765
_DETECTION_ENGINE_URL = f"http://127.0.0.1:{_PORT}"


@pytest.fixture
def live_detection_engine(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/e2e.db")

    import uvicorn

    from app.db import Base, engine
    from app.main import app as detection_engine_app

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    config = uvicorn.Config(detection_engine_app, host="127.0.0.1", port=_PORT, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    for _ in range(50):
        if server.started:
            break
        time.sleep(0.1)
    else:
        pytest.fail("detection-engine server did not start in time")

    yield engine

    server.should_exit = True
    thread.join(timeout=5)


def test_running_a_scenario_forwards_and_stores_the_event(live_detection_engine, monkeypatch):
    monkeypatch.setenv("BANTIS_ENV", "range-local")
    monkeypatch.setenv("DETECTION_ENGINE_URL", _DETECTION_ENGINE_URL)

    from logging_config import configure_logging

    configure_logging()

    from scenarios.noop import NoopScenario

    scenario = NoopScenario()
    result = scenario.run()
    scenario.log_result(result)

    from sqlalchemy.orm import Session

    from app.event_models import EventORM

    with Session(live_detection_engine) as session:
        rows = session.query(EventORM).filter_by(source="attack-sim").all()

    assert len(rows) == 1
    row = rows[0]
    assert row.event_type == "attack_scenario_run"
    assert row.details["scenario"] == "noop"
    assert row.details["status"] == "success"


def test_a_bare_log_line_with_no_event_id_is_not_forwarded(live_detection_engine, monkeypatch):
    monkeypatch.setenv("BANTIS_ENV", "range-local")
    monkeypatch.setenv("DETECTION_ENGINE_URL", _DETECTION_ENGINE_URL)

    from logging_config import configure_logging

    configure_logging()

    import logging

    logging.getLogger("attack_sim").warning("a bare operational line with no event_id")

    from sqlalchemy.orm import Session

    from app.event_models import EventORM

    with Session(live_detection_engine) as session:
        rows = session.query(EventORM).all()

    assert rows == []