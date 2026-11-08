import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "detection-engine"))
sys.path.insert(0, str(_REPO_ROOT / "ai-copilot"))

_FAKE_SECRET = "AKIAFAKEBANTISATSIM1"


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
    parsed = urlparse(base_url)
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=5)
    try:
        connection.request("POST", "/events", body=body, headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        response.read()
        assert response.status == 201
    finally:
        connection.close()


def _correlate():
    from app.correlation import run_correlation
    from app.db import SessionLocal

    with SessionLocal() as session:
        return [incident.incident_id for incident in run_correlation(session)]


class RecordingProvider:
    def __init__(self):
        self.requests = []

    def analyze_traced(self, request):
        from models import AnalysisTrace, AttemptRecord, CopilotResponse, ProposedAction

        self.requests.append(request)
        response = CopilotResponse(
            incident_id=request.incident.incident_id,
            reasoning="recorded",
            confidence=0.5,
            proposed_action=ProposedAction(type="flag_for_review", description="d"),
            model="recording",
            generated_at=datetime.now(timezone.utc),
        )
        return AnalysisTrace(
            response=response,
            attempts=[AttemptRecord(number=1, raw_output=response.model_dump_json())],
            system_prompt="recording provider",
        )


def test_a_new_incident_is_analyzed_automatically_and_only_once(detection_stack, tmp_path):
    from decision_log import DecisionLog
    from detection_client import DetectionEngineClient
    from worker import CopilotWorker

    log_path = tmp_path / "decisions.db"

    _post_event(detection_stack.url, "old-1", "compromised-ci-step", "T1195.002")
    _post_event(detection_stack.url, "old-2", "typosquatting", "T1195.001")
    [old_incident] = _correlate()

    provider = RecordingProvider()
    delivered = []
    worker = CopilotWorker(
        DetectionEngineClient(detection_stack.url),
        provider,
        on_result=lambda incident, response: delivered.append(incident["incident_id"]),
        decision_log=DecisionLog(log_path),
    )

    assert worker.poll_once() == []

    _post_event(
        detection_stack.url, "dep-1", "malicious-dependency", "T1195.001",
        artifact="fake-package==0.0.0", tool_returncode=1, tool_output_tail="no matching distribution",
    )
    _post_event(
        detection_stack.url, "sec-1", "leaked-secret", "T1552.001",
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
    # The decision has a durable, verifiable record -- and the secret is
    # not in it either, checked against the file's raw bytes.
    log = DecisionLog(log_path)
    assert [d.record.incident_id for d in log.for_incident(new_incident)] == [new_incident]
    assert not log.has_incident(old_incident)
    assert log.verify() == []
    assert _FAKE_SECRET.encode() not in log_path.read_bytes()


@pytest.mark.parametrize("detection_stack", ["0.2"], indirect=True)
def test_with_no_one_calling_correlation_the_copilot_still_gets_the_incident(detection_stack, tmp_path):
    """The deployed path end to end: events in, detection-engine's own
    scheduler correlates, the worker analyzes. Before the scheduler
    existed, this exact setup produced no incident at all.
    """
    from decision_log import DecisionLog
    from detection_client import DetectionEngineClient
    from worker import CopilotWorker

    provider = RecordingProvider()
    delivered = []
    worker = CopilotWorker(
        DetectionEngineClient(detection_stack.url),
        provider,
        on_result=lambda incident, response: delivered.append(incident["pattern"]),
        decision_log=DecisionLog(tmp_path / "decisions.db"),
    )

    _post_event(detection_stack.url, "dep-1", "malicious-dependency", "T1195.001", artifact="fake==0.0.0")
    _post_event(detection_stack.url, "sec-1", "leaked-secret", "T1552.001", artifact="config.py")

    deadline = time.monotonic() + 10
    while not delivered and time.monotonic() < deadline:
        worker.poll_once()
        time.sleep(0.2)

    assert delivered == ["composite-dependency-secret"]
    assert [e.event_id for e in provider.requests[0].evidence_timeline] == ["dep-1", "sec-1"]