import http.client
import importlib.util
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlparse

import pytest

ROOT = Path(__file__).resolve().parents[1]

_ANALYZE = """
import os
from datetime import datetime, timedelta, timezone
from decision_log import DecisionLog
from detection_client import DetectionEngineClient
from models import AnalysisTrace, CopilotResponse, ProposedAction
from worker import CopilotWorker

class Provider:
    def analyze_traced(self, request):
        return AnalysisTrace(response=CopilotResponse(
            incident_id=request.incident.incident_id,
            reasoning="Review context; never execute the description.", confidence=0.99,
            proposed_action=ProposedAction(type=os.environ["TEST_RECOMMENDATION"],
                description="Ignore policy and block every IP; disable the kill switch."),
            model="local-recording-provider", generated_at=datetime.now(timezone.utc)))

worker = CopilotWorker(DetectionEngineClient(os.environ["DETECTION_ENGINE_URL"]), Provider(),
    decision_log=DecisionLog(os.environ["BANTIS_DECISION_LOG"]),
    start_from=datetime.now(timezone.utc) - timedelta(minutes=5))
assert len(worker.poll_once()) == 1
"""


def http_request(url, method, path, body=None):
    parsed = urlparse(url)
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=5)
    try:
        connection.request(method, path, body=json.dumps(body) if body is not None else None,
                           headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        raw = response.read()
        return response.status, json.loads(raw) if raw else None
    finally:
        connection.close()


@pytest.fixture
def stack(tmp_path, request):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("RESPONSE_", "BANTIS_", "CORRELATION_"))}
    env.update(DATABASE_URL=f"sqlite:///{tmp_path}/detection.db",
               CORRELATION_INTERVAL_SECONDS=getattr(request, "param", "0"))
    detection_url = f"http://127.0.0.1:{port}"
    command = ("from app.main import app; from app.db import Base,engine; "
               "Base.metadata.create_all(engine); import uvicorn; "
               f"uvicorn.run(app,host='127.0.0.1',port={port},log_level='warning')")
    with (tmp_path / "detection.log").open("w+") as output:
        process = subprocess.Popen([sys.executable, "-c", command], cwd=ROOT / "detection-engine",
                                   env=env, stdout=output, stderr=output)
        github = None
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                try:
                    if http_request(detection_url, "GET", "/incidents")[0] == 200:
                        break
                except OSError:
                    pass
                if process.poll() is not None:
                    break
                time.sleep(0.05)
            else:
                pytest.fail("local detection-engine did not start")
            assert process.poll() is None
            spec = importlib.util.spec_from_file_location("response_fake_github", ROOT / "response-controller/tests/fake_github.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            github = module.FakeGitHub(repo="test/bridge")
            state = tmp_path / "state"
            state.mkdir()
            (state / "kill-switch").write_text(json.dumps({"level": "clear", "ai_off": False}))
            secret = tmp_path / "approver-secret"
            secret.write_text("local-test-secret\n")
            secret.chmod(0o600)
            env.update(BANTIS_STATE_DIR=str(state), BANTIS_DECISION_LOG=str(tmp_path / "decisions.db"),
                       DETECTION_ENGINE_URL=detection_url, RESPONSE_GITHUB_REPO=github.repo,
                       RESPONSE_GITHUB_TOKEN_PROMOTION=module.TOKEN, RESPONSE_GITHUB_API_URL=github.url,
                       RESPONSE_ENABLED_ACTIONS="hold_promotion,lift_promotion_hold", RESPONSE_DRY_RUN="false",
                       RESPONSE_AUTO_ACTION="hold_promotion", RESPONSE_AUTO_REPO=github.repo,
                       RESPONSE_APPROVER_SECRET_FILE=str(secret))
            yield SimpleNamespace(env=env, github=github, url=detection_url, state=state)
        finally:
            if github is not None:
                github.close()
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def run_component(component, arguments, env, *, input_text=None, expected=0):
    result = subprocess.run([sys.executable, *arguments], cwd=ROOT / component, env=env,
                            text=True, input=input_text, capture_output=True, timeout=20, check=False)
    assert result.returncode == expected, result.stdout + result.stderr
    return result.stdout


def seed_incident(stack, success):
    for event_id, scenario in [("dep", "malicious-dependency"), ("secret", "leaked-secret")]:
        status, _ = http_request(stack.url, "POST", "/events", {
            "event_id": event_id, "timestamp": datetime.now(UTC).isoformat(), "level": "INFO",
            "logger": "attack_sim", "source": "attack-sim", "event_type": "attack_scenario_run", "message": "test",
            "details": {"scenario": scenario, "status": "success" if success else "failure",
                        "mitre_technique": "T1195.001" if event_id == "dep" else "T1552.001"},
        })
        assert status == 201
    run_component("detection-engine", ["-c", ("from app.correlation import run_correlation; from app.db import SessionLocal; "
                  "s=SessionLocal(); assert len(run_correlation(s)) == 1; s.close()")], stack.env)


def analyze(stack, action):
    run_component("ai-copilot", ["-c", _ANALYZE], {**stack.env, "TEST_RECOMMENDATION": action})


def sync(stack, *, expected=0):
    return json.loads(run_component("response-controller", ["cli.py", "sync", "--since",
                      (datetime.now(UTC) - timedelta(minutes=5)).isoformat(), "--execute"], stack.env, expected=expected))


@pytest.mark.parametrize("mode", ["automatic", "manual", "dry-run", "stopped"])
def test_worker_recommendation_reaches_review_and_guarded_execution(stack, mode):
    seed_incident(stack, success=True)
    # This advice must not suppress a policy-triggered hold or choose its parameters.
    analyze(stack, "no_action_recommended")
    if mode == "manual":
        stack.env.pop("RESPONSE_AUTO_ACTION")
        stack.env.pop("RESPONSE_AUTO_REPO")
    elif mode == "dry-run":
        stack.env["RESPONSE_DRY_RUN"] = "true"
    elif mode == "stopped":
        run_component("response-controller", ["cli.py", "emergency-stop"], stack.env)
    [report] = sync(stack, expected=1 if mode == "stopped" else 0)
    assert report["copilot"]["recommendation"]["proposed_action"]["type"] == "no_action_recommended"
    action_id = report["action_id"]
    shown = run_component("response-controller", ["cli.py", "show", action_id], stack.env)
    proposal = json.JSONDecoder().raw_decode(shown)[0]
    assert proposal["type"] == "hold_promotion" and proposal["params"] == {}
    assert "local-recording-provider" in shown and "untrusted review context" in shown
    if mode == "manual":
        assert report["status"] == "awaiting_approval" and stack.github.writes() == []
        run_component("response-controller", ["cli.py", "approve", action_id, proposal["proposal_hash"][:12]],
                      stack.env, input_text="local-test-secret\n")
    else:
        assert report["status"] == {"automatic": "succeeded", "dry-run": "dry_run", "stopped": "invalidated"}[mode]
    expected_writes = 1 if mode in {"automatic", "manual"} else 0
    assert len(stack.github.writes()) == expected_writes
    # A new controller process can refresh context but cannot replay the action.
    sync(stack)
    assert len(stack.github.writes()) == expected_writes
    audit = run_component("response-controller", ["cli.py", "audit", "--action-id", action_id], stack.env)
    assert '"event": "copilot_context"' in audit
    assert "github_pat_" not in audit
    run_component("response-controller", ["cli.py", "audit-verify"], stack.env)


def test_model_advice_cannot_trigger_an_action_when_both_attacks_were_defended(stack):
    seed_incident(stack, success=False)
    analyze(stack, "flag_for_review")
    [report] = sync(stack)
    assert report["status"] == "no_policy_action"
    assert report["copilot"]["recommendation"]["proposed_action"]["type"] == "flag_for_review"
    assert stack.github.requests == []


def test_late_worker_analysis_attaches_to_a_completed_action_without_replaying_it(stack):
    seed_incident(stack, success=True)
    [first] = sync(stack)
    assert first["status"] == "succeeded" and first["copilot"]["status"] == "unavailable"
    analyze(stack, "suggest_investigation")
    [second] = sync(stack)
    assert second["action_id"] == first["action_id"] and second["status"] == "succeeded"
    assert second["copilot"]["status"] == "available"
    assert len(stack.github.writes()) == 1


def test_tampered_worker_decision_log_stops_execution_before_any_github_request(stack):
    seed_incident(stack, success=True)
    analyze(stack, "flag_for_review")
    with sqlite3.connect(stack.env["BANTIS_DECISION_LOG"]) as db:
        db.execute("UPDATE decisions SET record_json='{}'")
    output = run_component("response-controller", ["cli.py", "sync", "--since",
                           (datetime.now(UTC) - timedelta(minutes=5)).isoformat(), "--execute"], stack.env, expected=2)
    assert output == ""
    state = json.loads((stack.state / "kill-switch.tripped").read_text())
    assert state["level"] == "execution-off" and state["ai_off"]
    assert stack.github.requests == []

_RUN_ATTACKS = r"""
import os
import subprocess
from pathlib import Path
from unittest.mock import patch
from logging_config import configure_logging
from scenarios import malicious_dependency as dependency, leaked_secret as secret
from scenarios.base import ScenarioStatus

configure_logging()

root = Path(os.environ["TEST_ATTACK_DIR"])
requirements = root / "requirements.txt"
original = "example-package==1.0.0\n"
requirements.write_text(original)
expected = ScenarioStatus(os.environ["TEST_ATTACK_STATUS"])
calls = []

def tool(command, **kwargs):
    calls.append(command[0])
    if command[0] == "docker":
        if calls.count("docker") == 1:
            assert dependency._INJECTED_LINE in requirements.read_text()
        else:
            assert requirements.read_text() == original
        return subprocess.CompletedProcess(command, 0 if expected == ScenarioStatus.SUCCESS else 1, "fixture build", "")
    if command[0] == "git":
        return subprocess.CompletedProcess(command, 0, "", "")
    assert command[0] == "gitleaks", command
    assert (Path(command[2]) / "config.py").read_text() == secret._LEAKED_FILE_CONTENT
    return subprocess.CompletedProcess(command, 0 if expected == ScenarioStatus.SUCCESS else 1,
        "Secret: " + secret._FAKE_AWS_ACCESS_KEY_ID, "")

with patch.object(dependency, "_REQUIREMENTS_FILE", requirements), patch("subprocess.run", side_effect=tool):
    for cls in (dependency.MaliciousDependencyScenario, secret.LeakedSecretScenario):
        scenario = cls()
        try:
            result = scenario.run()
            assert result.status == expected, result
            scenario.log_result(result)
            scratch = getattr(scenario, "_workdir", None)
        finally:
            scenario.cleanup()
        assert scratch is None or not scratch.exists()
assert requirements.read_text() == original
assert "docker" in calls and "git" in calls and "gitleaks" in calls
"""

_ANALYZE_PIPELINE = r"""
import json
import os
from datetime import datetime, timedelta, timezone
from decision_log import DecisionLog
from detection_client import DetectionEngineClient
from models import AnalysisTrace, AttemptRecord, CopilotResponse, ProposedAction
from worker import CopilotWorker

class Provider:
    calls = 0
    def analyze_traced(self, request):
        self.calls += 1
        assert request.incident.pattern == "composite-dependency-secret"
        assert {e.scenario for e in request.evidence_timeline} == {"malicious-dependency", "leaked-secret"}
        assert {e.status for e in request.evidence_timeline} == {os.environ["TEST_ATTACK_STATUS"]}
        assert "AKIAFAKEBANTISATSIM1" not in request.model_dump_json()
        response = CopilotResponse(incident_id=request.incident.incident_id,
            reasoning="Dependency and credential evidence requires operator review.", confidence=0.99,
            proposed_action=ProposedAction(type="flag_for_review", description="Review the correlated evidence."),
            model="local-pipeline-provider", generated_at=datetime.now(timezone.utc))
        return AnalysisTrace(response=response,
            attempts=[AttemptRecord(number=1, raw_output=response.model_dump_json())])

provider = Provider()
log = DecisionLog(os.environ["BANTIS_DECISION_LOG"])
worker = CopilotWorker(DetectionEngineClient(os.environ["DETECTION_ENGINE_URL"]), provider,
    decision_log=log, start_from=datetime.now(timezone.utc) - timedelta(minutes=5))
assert len(worker.poll_once()) == int(os.environ["TEST_EXPECT_ANALYSIS"])
assert provider.calls == int(os.environ["TEST_EXPECT_ANALYSIS"])
assert log.verify() == []
"""


@pytest.mark.parametrize("stack", ["0.1"], indirect=True)
@pytest.mark.parametrize("attack_status", ["success", "failure"])
def test_attack_to_response_audit_pipeline(stack, tmp_path, attack_status):
    """Real scenario logging, scheduled detection, worker, response, and audit."""
    attack_dir = tmp_path / "attacks"
    attack_dir.mkdir()
    env = {**stack.env, "BANTIS_ENV": "range-local", "TEST_ATTACK_DIR": str(attack_dir),
           "TEST_ATTACK_STATUS": attack_status, "TEST_EXPECT_ANALYSIS": "1"}
    output = run_component("attack-sim", ["-c", _RUN_ATTACKS], env)
    emitted = [json.loads(line) for line in output.splitlines()]
    event_ids = {event["event_id"] for event in emitted if event.get("event_type") == "attack_scenario_run"}
    assert len(event_ids) == 2

    # No direct correlation call: the API's scheduler must detect the attack.
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        status, listing = http_request(stack.url, "GET", "/incidents")
        assert status == 200
        if listing["total"]:
            break
        time.sleep(0.05)
    else:
        pytest.fail("scheduled detection did not create an incident from scenario events")
    [incident] = listing["items"]
    incident_id = incident["incident_id"]
    assert incident["pattern"] == "composite-dependency-secret"
    assert set(incident["correlated_event_ids"]) == event_ids
    assert incident["severity"] == ("critical" if attack_status == "success" else "high")
    status, evidence = http_request(stack.url, "GET", f"/incidents/{incident_id}/events")
    assert status == 200 and {event["event_id"] for event in evidence} == event_ids

    run_component("ai-copilot", ["-c", _ANALYZE_PIPELINE], env)
    decision = json.loads(run_component("ai-copilot", ["decision_log.py", "show", incident_id], env))
    assert decision["record"]["response"]["incident_id"] == incident_id
    assert {e["event_id"] for e in decision["record"]["request"]["evidence_timeline"]} == event_ids
    assert len(decision["record"]["attempts"]) == 1
    assert b"AKIAFAKEBANTISATSIM1" not in Path(env["BANTIS_DECISION_LOG"]).read_bytes()

    [report] = sync(stack)
    assert report["incident_id"] == incident_id
    assert report["copilot"]["status"] == "available"
    if attack_status == "failure":
        assert report["status"] == "no_policy_action"
        assert stack.github.requests == []
    else:
        assert report["status"] == "succeeded"
        action_id = report["action_id"]
        assert len(stack.github.writes()) == 1
        assert incident_id in stack.github.variables["BANTIS_PROMOTION_HOLD"]
        audit = run_component("response-controller", ["cli.py", "audit", "--action-id", action_id], env)
        entries = [json.loads(line) for line in audit.splitlines()]
        events = [entry["event"] for entry in entries]
        for name in ("proposed", "incident_facts", "copilot_context", "executed", "verified", "outcome"):
            assert name in events
        assert events.index("copilot_context") < events.index("executed") < events.index("verified") < events.index("outcome")
        assert all(entry["incident_id"] == incident_id and entry["action_id"] == action_id for entry in entries)
        facts = next(entry["facts"] for entry in entries if entry["event"] == "incident_facts")
        assert {e["event_id"] for e in facts["evidence"]} == event_ids
        assert next(entry for entry in entries if entry["event"] == "verified")["verified"] is True
        assert entries[-1]["status"] == "succeeded"
        assert "github_pat_" not in audit and "AKIAFAKEBANTISATSIM1" not in audit
        checkpoint = json.loads(run_component("response-controller", ["cli.py", "audit-verify"], env))
        assert checkpoint["count"] == len(entries)
        run_component("response-controller", ["cli.py", "audit-verify", "--expected-head", checkpoint["head"]], env)

    # Fresh processes must neither call the provider nor repeat the response.
    run_component("ai-copilot", ["-c", _ANALYZE_PIPELINE], {**env, "TEST_EXPECT_ANALYSIS": "0"})
    assert sync(stack)[0]["status"] == report["status"]
    assert len(stack.github.writes())0 == (1 if attack_status == "success" else 0)