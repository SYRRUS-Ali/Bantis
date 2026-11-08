import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "detection-engine"))
sys.path.insert(0, str(_REPO_ROOT / "attack-sim"))


def test_running_a_scenario_forwards_and_stores_the_event(detection_stack, monkeypatch):
    monkeypatch.setenv("BANTIS_ENV", "range-local")
    monkeypatch.setenv("DETECTION_ENGINE_URL", detection_stack.url)

    from logging_config import configure_logging

    configure_logging()

    from scenarios.noop import NoopScenario

    scenario = NoopScenario()
    result = scenario.run()
    scenario.log_result(result)

    from app.event_models import EventORM
    from sqlalchemy.orm import Session

    with Session(detection_stack.engine) as session:
        rows = session.query(EventORM).filter_by(source="attack-sim").all()

    assert len(rows) == 1
    row = rows[0]
    assert row.event_type == "attack_scenario_run"
    assert row.details["scenario"] == "noop"
    assert row.details["status"] == "success"


def test_a_bare_log_line_with_no_event_id_is_not_forwarded(detection_stack, monkeypatch):
    monkeypatch.setenv("BANTIS_ENV", "range-local")
    monkeypatch.setenv("DETECTION_ENGINE_URL", detection_stack.url)

    from logging_config import configure_logging

    configure_logging()

    import logging

    logging.getLogger("attack_sim").warning("a bare operational line with no event_id")

    from app.event_models import EventORM
    from sqlalchemy.orm import Session

    with Session(detection_stack.engine) as session:
        rows = session.query(EventORM).all()

    assert rows == []