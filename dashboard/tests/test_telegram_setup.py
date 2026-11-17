import json
import logging
import stat
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from bantis_dashboard.config import Settings
from bantis_dashboard.main import create_app
from bantis_dashboard.telegram_setup import TEST_MESSAGE
from test_admin import CREATE, HEADERS
from test_dashboard import ORIGIN, TOKEN
from test_provider_setup import grant_permissions, login
from bantis_dashboard.secret_store import SecretStore

BOT_TOKEN = "123456789:telegram-fixture-token-private"
INPUT = {"bot_token": BOT_TOKEN, "chat_id": "-100123456789"}
REPLY = {"ok": True, "result": {"message_id": 1, "chat": {"id": -100123456789}, "text": TEST_MESSAGE}}
URL = "/api/setup/telegram"


@pytest.fixture
def telegram_stack(tmp_path):
    upstream = {"status": 200, "body": REPLY, "requests": [], "error": None}

    def handle(request):
        upstream["requests"].append(request)
        if upstream["error"]:
            raise upstream["error"]
        return httpx.Response(upstream["status"], json=upstream["body"])

    directory = tmp_path / "state"
    app = create_app(Settings(token=TOKEN, origin=ORIGIN, state_dir=directory),
                     transport=httpx.MockTransport(lambda _: httpx.Response(503)),
                     telegram_transport=httpx.MockTransport(handle))
    grant_permissions(directory)
    with TestClient(app) as client:
        assert client.post("/api/setup/admin", json=CREATE, headers=HEADERS).status_code == 201
        yield client, directory, upstream


def test_test_message_private_save_and_redaction(telegram_stack, caplog):
    client, directory, upstream = telegram_stack
    login(client)
    assert client.get(URL).json() == {"configured": False, "enabled": False, "chat_id": None, "has_token": False}
    assert client.post(URL, json={"enabled": True}, headers=HEADERS).status_code == 409
    with caplog.at_level(logging.DEBUG):
        result = client.post(URL + "/test", json=INPUT, headers=HEADERS)
    assert result.status_code == 200 and result.json()["connected"] is True
    assert BOT_TOKEN not in result.text and BOT_TOKEN not in caplog.text
    assert not (directory / "telegram.json").exists()
    assert len(upstream["requests"]) == 1
    sent = upstream["requests"][0]
    assert str(sent.url) == f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    assert json.loads(sent.content) == {"chat_id": INPUT["chat_id"], "text": TEST_MESSAGE}
    body = {"enabled": True, "test_id": result.json()["test_id"]}
    assert client.post(URL, json=body | {"chat_id": "42"}, headers=HEADERS).status_code == 422
    saved = client.post(URL, json=body, headers=HEADERS)
    assert saved.status_code == 200 and BOT_TOKEN not in saved.text
    path = directory / "telegram.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert BOT_TOKEN not in path.read_text()
    assert json.loads(path.read_text())["version"] == 2
    assert SecretStore(directory).read("telegram")[0] == {"version": 1, "enabled": True, **INPUT}
    assert BOT_TOKEN not in client.get(URL).text
    assert client.post(URL, json=body, headers=HEADERS).status_code == 409


def test_skip_removes_token_without_a_network_request(telegram_stack):
    client, directory, upstream = telegram_stack
    login(client)
    receipt = client.post(URL + "/test", json=INPUT, headers=HEADERS).json()["test_id"]
    assert client.post(URL, json={"enabled": True, "test_id": receipt}, headers=HEADERS).status_code == 200
    skipped = client.post(URL, json={"enabled": False}, headers=HEADERS)
    assert skipped.json() == {"configured": True, "enabled": False, "chat_id": None, "has_token": False}
    assert SecretStore(directory).read("telegram")[0] == {"version": 1, "enabled": False}
    assert len(upstream["requests"]) == 1
    assert client.post(URL, json={"enabled": True, "test_id": receipt}, headers=HEADERS).status_code == 409


@pytest.mark.parametrize("status,code,expected", [(400, 400, 422), (401, 401, 422), (403, 403, 422),
                                                  (404, 404, 422), (429, 429, 429), (500, 500, 503),
                                                  (302, 302, 503), (200, 400, 422)])
def test_failure_is_sanitized_and_not_saved(telegram_stack, status, code, expected):
    client, directory, upstream = telegram_stack
    login(client)
    upstream.update(status=status, body={"ok": False, "error_code": code, "description": BOT_TOKEN})
    result = client.post(URL + "/test", json=INPUT, headers=HEADERS)
    assert result.status_code == expected and BOT_TOKEN not in result.text
    assert len(upstream["requests"]) == 1
    assert not (directory / "telegram.json").exists()
    assert client.post(URL, json={"enabled": True}, headers=HEADERS).status_code == 409


@pytest.mark.parametrize("body", [{}, [], {"ok": True}, {"ok": True, "result": {}},
                                  {**REPLY, "ok": 1}, {**REPLY, "padding": "x" * 65537},
                                  {"ok": True, "result": {**REPLY["result"], "chat": {"id": 42}}}])
def test_invalid_response_cannot_pass(telegram_stack, body):
    client, _, upstream = telegram_stack
    login(client)
    upstream["body"] = body
    assert client.post(URL + "/test", json=INPUT, headers=HEADERS).status_code == 502


def test_timeout_is_not_retried_and_invalidates_previous_receipt(telegram_stack):
    client, _, upstream = telegram_stack
    login(client)
    receipt = client.post(URL + "/test", json=INPUT, headers=HEADERS).json()["test_id"]
    upstream["error"] = httpx.ReadTimeout(BOT_TOKEN)
    result = client.post(URL + "/test", json=INPUT, headers=HEADERS)
    assert result.status_code == 503 and BOT_TOKEN not in result.text and "uncertain" in result.text
    assert len(upstream["requests"]) == 2
    assert client.post(URL, json={"enabled": True, "test_id": receipt}, headers=HEADERS).status_code == 409


def test_session_and_exact_origin_are_required(telegram_stack):
    client, _, upstream = telegram_stack
    assert client.get(URL).status_code == 401
    assert client.post(URL + "/test", json=INPUT, headers=HEADERS).status_code == 401
    login(client)
    for headers in ({}, {"Origin": "https://foreign.example"}):
        assert client.post(URL + "/test", json=INPUT, headers=headers).status_code == 403
        assert client.post(URL, json={"enabled": False}, headers=headers).status_code == 403
    assert upstream["requests"] == []


def test_token_mode_cannot_configure_telegram():
    app = create_app(Settings(token=TOKEN, origin=ORIGIN), transport=httpx.MockTransport(lambda _: httpx.Response(503)))
    with TestClient(app) as client:
        client.post("/api/session", json={"token": TOKEN}, headers=HEADERS)
        assert client.get(URL).status_code == 503
        assert client.post(URL, json={"enabled": False}, headers=HEADERS).status_code == 503


@pytest.mark.parametrize("operation", ["rotate", "logout", "expire"])
def test_receipt_is_bound_to_session_and_expiry(telegram_stack, monkeypatch, operation):
    client, _, _ = telegram_stack
    login(client)
    receipt = client.post(URL + "/test", json=INPUT, headers=HEADERS).json()["test_id"]
    if operation == "expire":
        original = time.monotonic
        monkeypatch.setattr("bantis_dashboard.telegram_setup.time.monotonic", lambda: original() + 301)
    else:
        if operation == "logout":
            client.delete("/api/session", headers=HEADERS)
        login(client)
    assert client.post(URL, json={"enabled": True, "test_id": receipt}, headers=HEADERS).status_code == 409


def test_session_expiring_during_delivery_cannot_save(telegram_stack):
    client, _, upstream = telegram_stack
    login(client)
    # Expire the session between authentication and completion of the test.
    original = client.app.state.sessions.valid
    checks = 0

    def valid(session_id):
        nonlocal checks
        checks += 1
        return original(session_id) if checks == 1 else False

    client.app.state.sessions.valid = valid
    result = client.post(URL + "/test", json=INPUT, headers=HEADERS)
    assert result.status_code == 401
    assert len(upstream["requests"]) == 1


@pytest.mark.parametrize("changes", [{"bot_token": "bad/token"}, {"bot_token": BOT_TOKEN + "\n"},
                                     {"chat_id": "0"}, {"chat_id": "../chat"}, {"chat_id": 123},
                                     {"endpoint": "http://127.0.0.1"}])
def test_bad_inputs_never_reach_telegram(telegram_stack, changes):
    client, _, upstream = telegram_stack
    login(client)
    result = client.post(URL + "/test", json=INPUT | changes, headers=HEADERS)
    assert result.status_code == 422 and BOT_TOKEN not in result.text
    assert "bot token" in result.json()["detail"]
    assert upstream["requests"] == []


def test_rate_limit_blocks_additional_messages(telegram_stack):
    client, _, upstream = telegram_stack
    login(client)
    upstream.update(status=401, body={"ok": False, "error_code": 401})
    for _ in range(10):
        assert client.post(URL + "/test", json=INPUT, headers=HEADERS).status_code == 422
    assert client.post(URL + "/test", json=INPUT, headers=HEADERS).status_code == 429
    assert len(upstream["requests"]) == 10


def test_failed_save_preserves_selection_and_receipt(telegram_stack, monkeypatch):
    client, directory, _ = telegram_stack
    login(client)
    client.post(URL, json={"enabled": False}, headers=HEADERS)
    receipt = client.post(URL + "/test", json=INPUT, headers=HEADERS).json()["test_id"]
    import os
    original = os.replace

    def fail(*args):
        raise OSError(BOT_TOKEN)

    monkeypatch.setattr("bantis_dashboard.secret_store.os.replace", fail)
    body = {"enabled": True, "test_id": receipt}
    result = client.post(URL, json=body, headers=HEADERS)
    assert result.status_code == 503 and BOT_TOKEN not in result.text
    assert client.get(URL).json()["enabled"] is False
    monkeypatch.setattr("bantis_dashboard.secret_store.os.replace", original)
    assert client.post(URL, json=body, headers=HEADERS).status_code == 200
    assert sorted(p.name for p in directory.iterdir()) == [".secrets.key", "admin.sqlite3", "permissions.json", "telegram.json"]


def test_restart_preserves_selection_but_not_receipts(telegram_stack):
    client, directory, _ = telegram_stack
    login(client)
    receipt = client.post(URL + "/test", json=INPUT, headers=HEADERS).json()["test_id"]
    assert client.post(URL, json={"enabled": True, "test_id": receipt}, headers=HEADERS).status_code == 200
    new_receipt = client.post(URL + "/test", json=INPUT, headers=HEADERS).json()["test_id"]
    app = create_app(Settings(token=TOKEN, origin=ORIGIN, state_dir=directory),
                     transport=httpx.MockTransport(lambda _: httpx.Response(503)))
    with TestClient(app) as restarted:
        login(restarted)
        assert restarted.get(URL).json()["chat_id"] == INPUT["chat_id"]
        assert restarted.post(URL, json={"enabled": True, "test_id": new_receipt}, headers=HEADERS).status_code == 409


def test_invalid_or_public_saved_file_is_unavailable(telegram_stack):
    client, directory, _ = telegram_stack
    login(client)
    path = directory / "telegram.json"
    SecretStore(directory).write("telegram", {"version": 1, "enabled": True, **INPUT})
    path.chmod(0o644)
    assert client.get(URL).status_code == 503
    path.chmod(0o600)
    assert client.get(URL).status_code == 200
    path.write_text('{"version": 1, "enabled": false, "bot_token": "unexpected"}')
    assert client.get(URL).status_code == 503
    path.write_text("broken")
    assert client.get(URL).status_code == 503


def test_public_channel_username_is_supported(telegram_stack):
    client, _, _ = telegram_stack
    login(client)
    assert client.post(URL + "/test", json=INPUT | {"chat_id": "@bantis_channel"}, headers=HEADERS).status_code == 200