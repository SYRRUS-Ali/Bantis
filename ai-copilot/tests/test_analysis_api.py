"""Recorded analysis retrieval never invokes the provider or exposes prompts."""

import pytest
from api import create_app
from decision_log import DecisionLog, DecisionRecord
from fastapi.testclient import TestClient
from models import CopilotResponse
from test_followup_api import _AUTH, FakeAsker, _analyzed


@pytest.fixture
def log(tmp_path):
    result = DecisionLog(tmp_path / "decisions.db")
    result.append(_analyzed("inc-1"))
    result.append(DecisionRecord.skipped("inc-skipped", "not correlated"))
    return result


@pytest.fixture
def provider():
    return FakeAsker()


@pytest.fixture
def client(log, provider):
    return TestClient(create_app(log, provider, "test-token-0123456789abcdef"))


def test_analysis_requires_bearer_token(client, provider):
    assert client.get("/incidents/inc-1/analysis").status_code == 401
    assert provider.calls == []


def test_analysis_returns_selected_record_fields(client, provider):
    response = client.get("/incidents/inc-1/analysis", headers=_AUTH)
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "analyzed"
    assert body["analysis"]["confidence"] == 0.7
    assert body["analysis"]["proposed_action"]["requires_approval"] is True
    assert body["can_ask"] is True
    assert set(body) == {
        "incident_id",
        "status",
        "recorded_at",
        "record_id",
        "outcome",
        "model",
        "note",
        "analysis",
        "can_ask",
    }
    assert "system_prompt" not in response.text
    assert "raw_output" not in response.text
    assert "evidence_timeline" not in response.text
    assert provider.calls == []


@pytest.mark.parametrize(
    "incident_id,state", [("inc-missing", "not_recorded"), ("inc-skipped", "skipped")]
)
def test_missing_and_skipped_states_are_distinct(client, incident_id, state):
    body = client.get(f"/incidents/{incident_id}/analysis", headers=_AUTH).json()
    assert body["status"] == state
    assert body["can_ask"] is False
    assert body["analysis"] is None


def test_failed_analysis_is_visible_but_cannot_ground_questions(client, log, provider):
    failed = _analyzed("inc-failed")
    failed.response = CopilotResponse.analysis_failed(
        "inc-failed", "test", "invalid provider output"
    )
    failed.outcome = "analysis_failed"
    log.append(failed)
    body = client.get("/incidents/inc-failed/analysis", headers=_AUTH).json()
    assert body["status"] == "failed"
    assert body["can_ask"] is False
    assert body["analysis"]["reasoning"]
    assert (
        client.post(
            "/incidents/inc-failed/questions", headers=_AUTH, json={"question": "Why?"}
        ).status_code
        == 409
    )
    assert provider.calls == []