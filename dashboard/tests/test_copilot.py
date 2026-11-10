import httpx
import pytest
from bantis_dashboard.config import Settings
from bantis_dashboard.main import create_app
from fastapi.testclient import TestClient
from test_dashboard import INCIDENT, ORIGIN, TOKEN, login

RECORD = {
    "incident_id": "incident-1",
    "status": "analyzed",
    "can_ask": True,
    "recorded_at": "2026-11-09T09:00:00Z",
    "record_id": "record-1",
    "outcome": "flag_for_review",
    "model": "fixture",
    "analysis": {
        "incident_id": "incident-1",
        "reasoning": "Review the correlated signals",
        "confidence": 0.7,
        "proposed_action": {
            "type": "flag_for_review",
            "description": "Investigate",
            "requires_approval": True,
        },
        "model": "fixture",
        "generated_at": "2026-11-09T09:00:00Z",
    },
}
REPLY = {
    "followup_id": "q-1",
    "incident_id": "incident-1",
    "asked_at": "2026-11-09T09:00:00Z",
    "question": "Why?",
    "answer": "Evidence",
    "model": "fixture",
}


@pytest.fixture
def copilot_stack():
    state = {"status": 200, "body": RECORD, "requests": [], "detection_status": 200}

    def copilot(request):
        state["requests"].append(request)
        if state.get("timeout"):
            raise httpx.ReadTimeout("private transport error")
        return httpx.Response(state["status"], json=state["body"])

    app = create_app(
        Settings(token=TOKEN, origin=ORIGIN, copilot_token="private-service-token"),
        transport=httpx.MockTransport(
            lambda request: httpx.Response(state["detection_status"], json=INCIDENT)
        ),
        copilot_transport=httpx.MockTransport(copilot),
    )
    with TestClient(app) as client:
        yield client, state


def test_route_shell_and_session_boundary(copilot_stack):
    client, state = copilot_stack
    assert client.get("/incidents").status_code == 200
    for resource in ("analysis", "questions"):
        assert client.get(f"/api/incidents/incident-1/{resource}").status_code == 401
    assert (
        client.post(
            "/api/incidents/incident-1/questions", json={"question": "Why?"}
        ).status_code
        == 401
    )
    assert state["requests"] == []


def test_selected_analysis_and_server_side_credential(copilot_stack):
    client, state = copilot_stack
    login(client)
    state["body"] = {**RECORD, "system_prompt": "private-prompt"}
    response = client.get("/api/incidents/incident-1/analysis")
    assert response.status_code == 200
    assert response.json()["analysis"]["confidence"] == 0.7
    assert "private" not in response.text
    assert (
        state["requests"][0].headers["Authorization"] == "Bearer private-service-token"
    )


def test_questions_validate_origin_and_body_before_upstream(copilot_stack):
    client, state = copilot_stack
    login(client)
    path = "/api/incidents/incident-1/questions"
    assert (
        client.post(
            path,
            headers={"Origin": "https://foreign.example"},
            json={"question": "Why?"},
        ).status_code
        == 403
    )
    for question in ("", "   ", "x" * 2001):
        assert client.post(path, json={"question": question}).status_code == 422
    assert state["requests"] == []
    state["body"] = REPLY
    response = client.post(path, json={"question": "Why?"}, headers={"Origin": ORIGIN})
    assert response.status_code == 201
    assert len(state["requests"]) == 1
    assert state["requests"][0].method == "POST"
    state["body"] = [{**REPLY, "attempts": "private"}]
    assert client.get(path).json() == [{**REPLY, "asked_at": "2026-11-09T09:00:00Z"}]


@pytest.mark.parametrize(
    "status,expected",
    [
        (401, 503),
        (500, 503),
        (302, 503),
        (404, 404),
        (409, 409),
        (422, 422),
        (429, 429),
    ],
)
def test_upstream_errors_are_sanitized(copilot_stack, status, expected):
    client, state = copilot_stack
    login(client)
    state.update(status=status, body={"detail": "private-error"})
    response = client.get("/api/incidents/incident-1/analysis")
    assert response.status_code == expected
    assert "private" not in response.text


@pytest.mark.parametrize(
    "body",
    [
        {},
        [],
        {**RECORD, "incident_id": "other"},
        {**RECORD, "analysis": {**RECORD["analysis"], "confidence": 3}},
        {**RECORD, "analysis": {**RECORD["analysis"], "incident_id": "other"}},
        {**RECORD, "note": "x" * 2_000_001},
    ],
)
def test_invalid_oversized_or_mismatched_data_is_rejected(copilot_stack, body):
    client, state = copilot_stack
    login(client)
    state["body"] = body
    assert client.get("/api/incidents/incident-1/analysis").status_code == 502


def test_missing_incident_is_checked_before_copilot(copilot_stack):
    client, state = copilot_stack
    login(client)
    state["detection_status"] = 404
    assert client.get("/api/incidents/incident-1/analysis").status_code == 404
    assert state["requests"] == []


def test_optional_copilot_is_explicitly_unconfigured():
    app = create_app(
        Settings(token=TOKEN, origin=ORIGIN),
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json=INCIDENT)
        ),
    )
    with TestClient(app) as client:
        login(client)
        response = client.get("/api/incidents/incident-1/analysis")
        assert response.status_code == 503
        assert "not configured" in response.text


def test_uncertain_post_is_not_retried(copilot_stack):
    client, state = copilot_stack
    login(client)
    state["timeout"] = True
    response = client.post(
        "/api/incidents/incident-1/questions", json={"question": "Why?"}
    )
    assert response.status_code == 503
    assert "Delivery is uncertain" in response.text
    assert "private" not in response.text
    assert len(state["requests"]) == 1


@pytest.mark.parametrize(
    "body",
    [{}, [{**REPLY, "incident_id": "other"}], [{**REPLY, "asked_at": "invalid"}]],
)
def test_invalid_conversation_is_rejected(copilot_stack, body):
    client, state = copilot_stack
    login(client)
    state["body"] = body
    assert client.get("/api/incidents/incident-1/questions").status_code == 502


def test_history_normalizes_and_orders_timestamps(copilot_stack):
    client, state = copilot_stack
    login(client)
    state["body"] = [
        REPLY,
        {**REPLY, "followup_id": "earlier", "asked_at": "2026-11-09T08:00:00"},
    ]
    body = client.get("/api/incidents/incident-1/questions").json()
    assert [item["followup_id"] for item in body] == ["earlier", "q-1"]
    assert body[0]["asked_at"].endswith("Z")


@pytest.mark.parametrize(
    "options",
    [
        {"copilot_url": "file:///tmp/test"},
        {"copilot_token": "short"},
        {"copilot_token": "x" * 16 + "\n"},
    ],
)
def test_invalid_copilot_configuration_is_rejected(options):
    with pytest.raises(ValueError):
        Settings(token=TOKEN, **options)