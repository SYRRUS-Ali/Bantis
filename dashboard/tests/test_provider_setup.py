import json
import runpy
import stat
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from bantis_dashboard.config import Settings
from bantis_dashboard.main import create_app
from test_admin import CREATE, HEADERS, PASSWORD
from test_dashboard import ORIGIN, TOKEN

KEY = "test-anthropic-key-private-value"
INPUT = {"provider": "claude", "model": "claude-sonnet-5", "api_key": KEY}
REPLY = {"type": "message", "role": "assistant", "content": [{"type": "text", "text": "OK"}]}
URL = "/api/setup/provider"


@pytest.fixture
def provider_stack(tmp_path):
    upstream = {"status": 200, "body": REPLY, "requests": [], "error": None}

    def handle(request):
        upstream["requests"].append(request)
        if upstream["error"]:
            raise upstream["error"]
        return httpx.Response(upstream["status"], json=upstream["body"])

    directory = tmp_path / "state"
    app = create_app(Settings(token=TOKEN, origin=ORIGIN, state_dir=directory),
                     transport=httpx.MockTransport(lambda _: httpx.Response(503)),
                     provider_transport=httpx.MockTransport(handle))
    with TestClient(app) as client:
        assert client.post("/api/setup/admin", json=CREATE, headers=HEADERS).status_code == 201
        yield client, directory, upstream


def login(client):
    assert client.post("/api/admin/session", json={"username": "admin.user", "password": PASSWORD},
                       headers=HEADERS).status_code == 200


def test_real_provider_request_and_test_bound_private_save(provider_stack):
    client, directory, upstream = provider_stack
    login(client)
    assert client.get(URL).json()["configured"] is False
    assert client.post(URL, json={"provider": "claude"}, headers=HEADERS).status_code == 409
    result = client.post(URL + "/test", json=INPUT, headers=HEADERS)
    assert result.status_code == 200
    assert result.json()["connected"] is True
    assert KEY not in result.text
    assert not (directory / "ai-provider.json").exists()
    assert len(upstream["requests"]) == 1
    sent = upstream["requests"][0]
    assert str(sent.url) == "https://api.anthropic.com/v1/messages"
    assert sent.headers["x-api-key"] == KEY
    assert json.loads(sent.content) == {"model": INPUT["model"], "max_tokens": 16,
                                       "messages": [{"role": "user", "content": "Reply with OK."}]}
    body = {"provider": "claude", "test_id": result.json()["test_id"]}
    saved = client.post(URL, json=body, headers=HEADERS)
    assert saved.status_code == 200 and KEY not in saved.text
    path = directory / "ai-provider.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_text()) == {"version": 1, **INPUT}
    # Verify the actual saved format with the independent Copilot reader.
    reader = Path(__file__).resolve().parents[2] / "ai-copilot/providers/configuration.py"
    load = runpy.run_path(str(reader))["load_provider_file"]
    assert load(str(path)) == {"version": 1, **INPUT}
    assert KEY not in client.get(URL).text
    assert client.post(URL, json=body, headers=HEADERS).status_code == 409


@pytest.mark.parametrize("status,expected", [(401, 422), (403, 422), (400, 422), (404, 422), (429, 429), (500, 503), (302, 503)])
def test_provider_failure_is_sanitized_and_never_saved(provider_stack, status, expected):
    client, directory, upstream = provider_stack
    login(client)
    upstream.update(status=status, body={"error": KEY})
    result = client.post(URL + "/test", json=INPUT, headers=HEADERS)
    assert result.status_code == expected
    assert KEY not in result.text
    assert len(upstream["requests"]) == 1
    assert not (directory / "ai-provider.json").exists()


@pytest.mark.parametrize("body", [{}, {"type": "message", "role": "assistant", "content": []}, [REPLY],
                                  {**REPLY, "padding": "x" * 65537}])
def test_bad_or_oversized_provider_response_cannot_pass(provider_stack, body):
    client, _, upstream = provider_stack
    login(client)
    upstream["body"] = body
    assert client.post(URL + "/test", json=INPUT, headers=HEADERS).status_code == 502


def test_connection_timeout_is_not_retried(provider_stack):
    client, _, upstream = provider_stack
    login(client)
    upstream["error"] = httpx.ReadTimeout(KEY)
    result = client.post(URL + "/test", json=INPUT, headers=HEADERS)
    assert result.status_code == 503 and KEY not in result.text
    assert "uncertain" in result.text and len(upstream["requests"]) == 1


def test_admin_session_and_exact_origin_are_required(provider_stack):
    client, _, upstream = provider_stack
    assert client.get(URL).status_code == 401
    assert client.post(URL + "/test", json=INPUT, headers=HEADERS).status_code == 401
    login(client)
    for headers in ({}, {"Origin": "https://foreign.example"}):
        assert client.post(URL + "/test", json=INPUT, headers=headers).status_code == 403
        assert client.post(URL, json={"provider": "none"}, headers=headers).status_code == 403
    assert upstream["requests"] == []


def test_receipt_cannot_be_used_by_another_session_or_after_logout(provider_stack):
    client, _, _ = provider_stack
    login(client)
    receipt = client.post(URL + "/test", json=INPUT, headers=HEADERS).json()["test_id"]
    # Signing in again rotates the session, even for the same administrator.
    login(client)
    assert client.post(URL, json={"provider": "claude", "test_id": receipt}, headers=HEADERS).status_code == 409
    receipt = client.post(URL + "/test", json=INPUT, headers=HEADERS).json()["test_id"]
    client.delete("/api/session", headers=HEADERS)
    login(client)
    assert client.post(URL, json={"provider": "claude", "test_id": receipt}, headers=HEADERS).status_code == 409


def test_none_is_saved_without_a_provider_call_and_removes_key(provider_stack):
    client, directory, upstream = provider_stack
    login(client)
    receipt = client.post(URL + "/test", json=INPUT, headers=HEADERS).json()["test_id"]
    assert client.post(URL, json={"provider": "claude", "test_id": receipt}, headers=HEADERS).status_code == 200
    assert client.post(URL, json={"provider": "none"}, headers=HEADERS).status_code == 200
    assert json.loads((directory / "ai-provider.json").read_text()) == {"version": 1, "provider": "none"}
    assert len(upstream["requests"]) == 1


@pytest.mark.parametrize("changes", [{"provider": "openai"}, {"endpoint": "http://127.0.0.1"},
                                     {"api_key": KEY + "\n"}, {"api_key": "short"}, {"model": "../path"}])
def test_untrusted_configuration_is_rejected_before_network(provider_stack, changes):
    client, _, upstream = provider_stack
    login(client)
    response = client.post(URL + "/test", json=INPUT | changes, headers=HEADERS)
    assert response.status_code == 422 and KEY not in response.text
    assert upstream["requests"] == []


def test_expired_test_cannot_save(provider_stack, monkeypatch):
    client, _, _ = provider_stack
    login(client)
    result = client.post(URL + "/test", json=INPUT, headers=HEADERS).json()
    import time
    original = time.monotonic
    monkeypatch.setattr("bantis_dashboard.provider_setup.time.monotonic", lambda: original() + 301)
    assert client.post(URL, json={"provider": "claude", "test_id": result["test_id"]}, headers=HEADERS).status_code == 409


def test_test_rate_limit_blocks_additional_network_calls(provider_stack):
    client, _, upstream = provider_stack
    login(client)
    upstream["status"] = 401
    for _ in range(10):
        assert client.post(URL + "/test", json=INPUT, headers=HEADERS).status_code == 422
    assert client.post(URL + "/test", json=INPUT, headers=HEADERS).status_code == 429
    assert len(upstream["requests"]) == 10


def test_failed_save_preserves_previous_selection_and_can_be_retried(provider_stack, monkeypatch):
    client, directory, _ = provider_stack
    login(client)
    client.post(URL, json={"provider": "none"}, headers=HEADERS)
    receipt = client.post(URL + "/test", json=INPUT, headers=HEADERS).json()["test_id"]
    import os
    original = os.replace

    def fail(*args):
        raise OSError("private storage error")

    monkeypatch.setattr("bantis_dashboard.provider_setup.os.replace", fail)
    response = client.post(URL, json={"provider": "claude", "test_id": receipt}, headers=HEADERS)
    assert response.status_code == 503 and "private storage error" not in response.text
    assert client.get(URL).json()["provider"] == "none"
    monkeypatch.setattr("bantis_dashboard.provider_setup.os.replace", original)
    assert client.post(URL, json={"provider": "claude", "test_id": receipt}, headers=HEADERS).status_code == 200
    assert sorted(path.name for path in directory.iterdir()) == ["admin.sqlite3", "ai-provider.json"]


def test_restart_keeps_saved_selection_and_discards_test_receipts(provider_stack):
    client, directory, _ = provider_stack
    login(client)
    client.post(URL, json={"provider": "none"}, headers=HEADERS)
    receipt = client.post(URL + "/test", json=INPUT, headers=HEADERS).json()["test_id"]
    app = create_app(Settings(token=TOKEN, origin=ORIGIN, state_dir=directory),
                     transport=httpx.MockTransport(lambda _: httpx.Response(503)))
    with TestClient(app) as restarted:
        login(restarted)
        assert restarted.get(URL).json()["provider"] == "none"
        assert restarted.post(URL, json={"provider": "claude", "test_id": receipt}, headers=HEADERS).status_code == 409