import json

import httpx
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from bantis_dashboard.config import Settings
from bantis_dashboard.main import create_app
from bantis_dashboard.secret_store import SecretStore
from test_admin import CREATE, HEADERS
from test_dashboard import ORIGIN, TOKEN
from test_orchestration import FakeRunner
from test_provider_setup import login

URL = "/api/setup/services"


@pytest.fixture
def services_stack(tmp_path):
    runner = FakeRunner()
    app = create_app(Settings(token=TOKEN, origin=ORIGIN, state_dir=tmp_path, orchestration_enabled=True, orchestration_range=False),
                     transport=httpx.MockTransport(lambda _: httpx.Response(503)), orchestration_runner=runner)
    with TestClient(app) as client:
        client.post("/api/setup/admin", json=CREATE, headers=HEADERS)
        yield client, runner, tmp_path


def configure(client):
    login(client)
    assert client.post("/api/setup/permissions", json={"ai_requests": False, "telegram_messages": False, "response_decisions": False}, headers=HEADERS).status_code == 200
    assert client.post("/api/setup/provider", json={"provider": "none"}, headers=HEADERS).status_code == 200
    assert client.post("/api/setup/telegram", json={"enabled": False}, headers=HEADERS).status_code == 200


def test_session_exact_origin_and_fixed_start_payload(services_stack):
    client, runner, _ = services_stack
    assert client.get(URL).status_code == 401
    assert client.post(URL + "/start", json={}, headers=HEADERS).status_code == 401
    configure(client)
    for headers in ({}, {"Origin": "http://foreign.example"}):
        assert client.post(URL + "/start", json={}, headers=headers).status_code == 403
    for payload in ({"command": "anything"}, {"services": ["arbitrary"]}, {"env": {"SECRET": "anything"}}):
        assert client.post(URL + "/start", json=payload, headers=HEADERS).status_code == 422
    assert not any("up" in argv for argv, _ in runner.calls)


def test_live_stream_requires_session_origin_and_revokes_on_logout(services_stack):
    client, runner, directory = services_stack
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/setup/services", headers=HEADERS):
            pass
    configure(client)
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/setup/services", headers={"Origin": "http://foreign.example"}):
            pass
    with client.websocket_connect("/ws/setup/services", headers=HEADERS) as websocket:
        assert client.post(URL + "/start", json={}, headers=HEADERS).status_code == 202
        saw_log = False
        for _ in range(30):
            message = websocket.receive_json()
            saw_log |= any("service log" in entry["text"] for entry in message["logs"])
            if message.get("ready") and saw_log:
                break
        else:
            pytest.fail("Startup and service logs were not streamed")
        token = SecretStore(directory).read("orchestration")[0]["copilot_api_token"]
        assert token not in json.dumps(message)
        assert TOKEN not in json.dumps(message)
        assert client.post(URL + "/start", json={}, headers=HEADERS).status_code == 202
        assert len([argv for argv, _ in runner.calls if "up" in argv]) == 1
        client.delete("/api/session", headers=HEADERS)
        with pytest.raises(WebSocketDisconnect):
            while True:
                websocket.receive_json()


def test_host_disabled_never_runs_commands(tmp_path):
    runner = FakeRunner()
    app = create_app(Settings(token=TOKEN, origin=ORIGIN, state_dir=tmp_path),
                     transport=httpx.MockTransport(lambda _: httpx.Response(503)), orchestration_runner=runner)
    with TestClient(app) as client:
        client.post("/api/setup/admin", json=CREATE, headers=HEADERS)
        login(client)
        assert client.get(URL).json()["enabled"] is False
        assert client.post(URL + "/start", json={}, headers=HEADERS).status_code == 503
    assert runner.calls == []