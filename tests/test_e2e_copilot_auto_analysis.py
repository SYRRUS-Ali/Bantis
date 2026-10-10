import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "detection-engine"))
sys.path.insert(0, str(_REPO_ROOT / "ai-copilot"))

_PORT = 18768
_FAKE_SECRET = "AKIAFAKEBANTISATSIM1"


@pytest.fixture
def live_detection_engine(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/e2e.db")

    import uvicorn

    from app.db import Base, engine
    from app.main import app as detection_engine_app

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    server = uvicorn.Server(uvicorn.Config(detection_engine_app, host="127.0.0.1", port=_PORT, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(50):
        if server.started:
            break
        time.sleep(0.1)
    else:
        pytest.fail("detection-engine server did not start in time")

    yield f"http://127.0.0.1:{_PORT}"

    server.should_exit = True
    thread.join(timeout=5)


def _post_event(base_url, event_id, scenario, mitre, **details):
    import http.client
    import json

    body = json.dumps(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": "INFO",
            "logger": "attack_sim",
            "source": "attack-sim",
            "event_type": "attack_scenario_run",
            "event_id": event_id,
            "message": f"{scenario} ran",
            "details": {"scenario": scenario, "status": "failure", "mitre_technique": mitre, **details},
        }
    )
    connection = http.client.HTTPConnection("127.0.0.1", _PORT, timeout=5)
    connection.request("POST", "/events", body=body, headers={"Content-Type": "application/json"})
    assert connection.getresponse().status == 201
    connection.close()


def _correlate():
    from app.correlation import run_correlation
    from app.db import SessionLocal

    with SessionLocal() as session:
        return [incident.incident_id for incident in run_correlation(session)]


class RecordingProvider:
    def __init__(self):
        self.requests = []

    def analyze(self, request):
        from models import CopilotResponse, ProposedAction

        self.requests.append(request)
        return CopilotResponse(
            incident_id=request.incident.incident_id,
            reasoning="recorded",
            confidence=0.5,
            proposed_action=ProposedAction(type="flag_for_review", description="d"),
            model="recording",
            generated_at=datetime.now(timezone.utc),
        )


def test_a_new_incident_is_analyzed_automatically_and_only_once(live_detection_engine):
    from detection_client import DetectionEngineClient
    from worker import CopilotWorker

    _post_event(live_detection_engine, "old-1", "compromised-ci-step", "T1195.002")
    _post_event(live_detection_engine, "old-2", "typosquatting", "T1195.001")
    [old_incident] = _correlate()

    provider = RecordingProvider()
    delivered = []
    worker = CopilotWorker(
        DetectionEngineClient(live_detection_engine),
        provider,
        on_result=lambda incident, response: delivered.append(incident["incident_id"]),
    )

    assert worker.poll_once() == []

    _post_event(
        live_detection_engine, "dep-1", "malicious-dependency", "T1195.001",
        artifact="fake-package==0.0.0", tool_returncode=1, tool_output_tail="no matching distribution",
    )
    _post_event(
        live_detection_engine, "sec-1", "leaked-secret", "T1552.001",
        artifact="config.py", tool_returncode=1, tool_output_tail=f"Secret: {_FAKE_SECRET}",
    )
    [new_incident] = _correlate()

    worker.poll_once()
    worker.poll_once()

    assert delivered == [new_incident]
    assert old_incident not in delivered
    assert len(provider.requests) == 1

    request = provider.requests[0]
    assert request.incident.pattern == "composite-dependency-secret"
    assert [entry.event_id for entry in request.evidence_timeline] == ["dep-1", "sec-1"]
    assert _FAKE_SECRET not in request.model_dump_json()