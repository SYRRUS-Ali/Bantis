"""Exercise dashboard decisions through the real local controller subprocess."""

import json
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from bantis_dashboard.config import Settings
from bantis_dashboard.main import create_app
from bantis_dashboard.response import ResponseController
from bantis_dashboard.detection import UpstreamError
from test_dashboard import ORIGIN, TOKEN, login

ROOT = Path(__file__).resolve().parents[2]
SECRET = "test-private-review-secret"
PATH = "/api/incidents/incident-1"


@pytest.fixture
def review_stack(tmp_path, monkeypatch):
    monkeypatch.setenv("BANTIS_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("RESPONSE_ENABLED_ACTIONS", "lift_promotion_hold")
    monkeypatch.setenv("RESPONSE_DRY_RUN", "true")
    for key in ("RESPONSE_AUTO_ACTION", "RESPONSE_AUTO_REPO", "RESPONSE_GITHUB_REPO", "RESPONSE_GITHUB_TOKEN_PROMOTION"):
        monkeypatch.delenv(key, raising=False)
    secret = tmp_path / "secret"
    secret.write_text(SECRET)
    secret.chmod(0o600)
    monkeypatch.setenv("RESPONSE_APPROVER_SECRET_FILE", str(secret))
    now = datetime.now(UTC)
    source = tmp_path / "proposal.json"
    source.write_text(json.dumps({
        "incident_id": "incident-1", "type": "lift_promotion_hold",
        "policy_rule": "B3:operator-request", "created_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
    }))
    seeded = subprocess.run(
        [sys.executable, str(ROOT / "response-controller/cli.py"), "propose", str(source)],
        text=True, capture_output=True, check=True,
    )
    proposal = json.loads(seeded.stdout)
    app = create_app(
        Settings(token=TOKEN, origin=ORIGIN, response_enabled=True),
        transport=httpx.MockTransport(lambda _: httpx.Response(503)),
    )
    with TestClient(app) as client:
        yield client, proposal, tmp_path


def decision(proposal, operation="dismiss", **changes):
    return {"operation": operation, "action_id": proposal["action_id"],
            "proposal_hash": proposal["proposal_hash"], "secret": SECRET,
            "reason": "False positive", **changes}


def post(client, body, path=PATH):
    return client.post(path + "/review", json=body, headers={"Origin": ORIGIN})


def test_review_requires_session_and_origin(review_stack):
    client, proposal, _ = review_stack
    assert client.get(PATH + "/proposals").status_code == 401
    assert post(client, decision(proposal)).status_code == 401
    login(client)
    assert client.post(PATH + "/review", json=decision(proposal),
                       headers={"Origin": "https://foreign.example"}).status_code == 403
    assert len(client.get(PATH + "/proposals").json()["items"]) == 1


def test_real_modify_replaces_then_dismiss_closes_and_audits(review_stack):
    client, proposal, state_dir = review_stack
    login(client)
    page = client.get(PATH + "/proposals").json()
    assert page["dry_run"] is True
    assert page["items"][0]["proposal_hash"] == proposal["proposal_hash"]
    result = post(client, decision(proposal, "modify", params={})).json()
    assert result["status"] == "modified"
    assert post(client, decision(proposal, "approve")).status_code == 409
    replacement = client.get(PATH + "/proposals").json()["items"][0]
    assert replacement["action_id"] == result["replacement_id"]
    assert replacement["proposal_hash"] != proposal["proposal_hash"]
    assert post(client, decision(replacement)).json()["status"] == "dismissed"
    assert post(client, decision(replacement)).status_code == 409
    assert client.get(PATH + "/proposals").json()["items"] == []
    with sqlite3.connect(state_dir / "reviews.sqlite3") as db:
        events = [json.loads(row[0]) for row in db.execute("SELECT payload FROM events")]
        assert db.execute("SELECT count(*) FROM approvals").fetchone()[0] == 0
    assert [e["event"] for e in events] == ["proposed", "modified", "proposed", "dismissed"]
    assert SECRET not in json.dumps(events)
    assert events[-1]["actor"] != ""


@pytest.mark.parametrize("changes,code", [
    ({"secret": "wrong"}, 403),
    ({"proposal_hash": "0" * 64}, 409),
    ({"reason": " "}, 409),
    ({"operation": "modify", "params": {"unexpected": "value"}}, 422),
    ({"actor": "someone-else"}, 422),
    ({"proposal_hash": "short"}, 422),
])
def test_invalid_decisions_leave_queue_unchanged(review_stack, changes, code):
    client, proposal, _ = review_stack
    login(client)
    response = post(client, decision(proposal, **changes))
    assert response.status_code == code
    assert SECRET not in response.text
    assert client.get(PATH + "/proposals").json()["items"][0]["action_id"] == proposal["action_id"]


def test_cross_incident_decision_is_refused(review_stack):
    client, proposal, _ = review_stack
    login(client)
    assert client.get("/api/incidents/other/proposals").json()["items"] == []
    assert post(client, decision(proposal), "/api/incidents/other").status_code == 409


def test_approval_uses_executor_and_preserves_kill_switch(review_stack):
    client, proposal, state_dir = review_stack
    login(client)
    result = post(client, decision(proposal, "approve"))
    assert result.status_code == 200
    assert result.json()["status"] == "invalidated"
    assert any("kill switch" in reason for reason in result.json()["reasons"])
    with sqlite3.connect(state_dir / "reviews.sqlite3") as db:
        events = [json.loads(row[0])["event"] for row in db.execute("SELECT payload FROM events")]
    assert "approved" in events and "outcome" in events and "executing" not in events


def test_unconfigured_review_is_explicit():
    app = create_app(Settings(token=TOKEN, origin=ORIGIN),
                     transport=httpx.MockTransport(lambda _: httpx.Response(503)))
    with TestClient(app) as client:
        login(client)
        assert client.get(PATH + "/proposals").status_code == 503


@pytest.mark.parametrize("failure", ["missing", "corrupt"])
def test_unavailable_journal_is_reported(review_stack, failure):
    client, _, state_dir = review_stack
    journal = state_dir / "reviews.sqlite3"
    if failure == "missing":
        journal.rename(state_dir / "saved.sqlite3")
    else:
        journal.write_text("invalid sqlite")
    login(client)
    response = client.get(PATH + "/proposals")
    assert response.status_code == 503
    assert "unavailable" in response.json()["detail"]


def test_timeout_is_not_retried_and_does_not_expose_input(monkeypatch):
    calls = []

    def timeout(*args, **kwargs):
        calls.append((args, kwargs))
        raise subprocess.TimeoutExpired(args[0], 120)

    monkeypatch.setattr("bantis_dashboard.response.subprocess.run", timeout)
    with pytest.raises(UpstreamError) as error:
        ResponseController(True).request("incident-1")
    assert len(calls) == 1
    assert "delivery is uncertain" in error.value.message
    assert len(calls[0][0][0]) == 2  # Only interpreter and fixed entry point in argv.


def test_nonfinite_parameters_are_rejected_before_controller_call(review_stack):
    client, proposal, _ = review_stack
    login(client)
    body = decision(proposal, "modify", params={"value": float("nan")})
    response = client.post(PATH + "/review", content=json.dumps(body),
                           headers={"Origin": ORIGIN, "Content-Type": "application/json"})
    assert response.status_code == 422