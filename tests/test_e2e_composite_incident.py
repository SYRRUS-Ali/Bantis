import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "detection-engine"))
sys.path.insert(0, str(_REPO_ROOT / "attack-sim"))

_PORT = 18766
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


@pytest.fixture
def real_scenarios(tmp_path, monkeypatch):
    monkeypatch.setenv("BANTIS_ENV", "range-local")

    import scenarios.leaked_secret as ls
    import scenarios.malicious_dependency as md

    requirements_file = tmp_path / "requirements.txt"
    requirements_file.write_text("fastapi==0.120.0\n")
    monkeypatch.setattr(md, "_REQUIREMENTS_FILE", requirements_file)

    real_run = subprocess.run

    def dispatched_fake_run(cmd, **kwargs):
        if cmd[0] == "docker":
            return SimpleNamespace(returncode=1, stdout="", stderr="no matching distribution")
        if cmd[0] == "gitleaks":
            return SimpleNamespace(returncode=1, stdout="", stderr="leak:aws-access-token")
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(subprocess, "run", dispatched_fake_run)

    real_mkdtemp = ls.tempfile.mkdtemp
    monkeypatch.setattr(ls.tempfile, "mkdtemp", lambda *a, **k: real_mkdtemp(*a, dir=str(tmp_path), **k))

    return md.MaliciousDependencyScenario(), ls.LeakedSecretScenario()


def test_real_dependency_and_secret_scenarios_form_one_composite_incident(
    live_detection_engine, real_scenarios, monkeypatch
):
    monkeypatch.setenv("DETECTION_ENGINE_URL", _DETECTION_ENGINE_URL)

    from logging_config import configure_logging

    configure_logging()

    from app.correlation import run_correlation
    from app.event_models import EventORM

    dependency_scenario, secret_scenario = real_scenarios

    dependency_result = dependency_scenario.run()
    dependency_scenario.log_result(dependency_result)
    dependency_scenario.cleanup()

    secret_result = secret_scenario.run()
    secret_scenario.log_result(secret_result)
    secret_scenario.cleanup()

    assert dependency_result.status.value == "failure"
    assert secret_result.status.value == "failure"

    from sqlalchemy.orm import Session

    with Session(live_detection_engine) as session:
        stored = session.query(EventORM).all()
        assert len(stored) == 2
        stored_ids = {event.event_id for event in stored}

        incidents = run_correlation(session)

        assert len(incidents) == 1
        incident = incidents[0]
        assert incident.pattern == "composite-dependency-secret"
        assert incident.severity == "high"
        assert incident.confidence == 0.6
        assert set(incident.correlated_event_ids) == stored_ids