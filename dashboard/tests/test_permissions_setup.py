import json

import httpx
import pytest
from fastapi.testclient import TestClient

from bantis_dashboard.config import Settings
from bantis_dashboard.main import create_app
from bantis_dashboard.permissions_setup import PermissionsSave, PermissionsSetup
from bantis_dashboard.secret_store import SecretStore
from test_admin import CREATE, HEADERS
from test_dashboard import ORIGIN, TOKEN
from test_provider_setup import INPUT as PROVIDER_INPUT, REPLY as PROVIDER_REPLY, login
from test_telegram_setup import INPUT as TELEGRAM_INPUT, REPLY as TELEGRAM_REPLY

URL = "/api/setup/permissions"
OFF = {"ai_requests": False, "telegram_messages": False, "response_decisions": False}
ON = {"ai_requests": True, "telegram_messages": True, "response_decisions": False}
DECISION = {"operation": "dismiss", "action_id": "test", "proposal_hash": "a" * 64,
            "secret": "separate-controller-secret"}


@pytest.fixture
def stack(tmp_path):
    calls = []

    def upstream(request):
        calls.append(request)
        return httpx.Response(200, json=TELEGRAM_REPLY if request.url.host == "api.telegram.org" else PROVIDER_REPLY)

    app = create_app(Settings(token=TOKEN, origin=ORIGIN, state_dir=tmp_path),
                     transport=httpx.MockTransport(lambda _: httpx.Response(503)),
                     provider_transport=httpx.MockTransport(upstream), telegram_transport=httpx.MockTransport(upstream))
    with TestClient(app) as client:
        client.post("/api/setup/admin", json=CREATE, headers=HEADERS)
        yield client, tmp_path, calls


def test_default_permissions_block_optional_side_effects(stack):
    client, _, calls = stack
    login(client)
    saved = client.get(URL).json()
    assert saved["configured"] is False
    assert all(saved[key] is False for key in OFF)
    assert saved["storage"] == {"encryption": "Fernet", "key_available": True, "private_permissions": True}
    assert client.post("/api/setup/provider/test", json=PROVIDER_INPUT, headers=HEADERS).status_code == 403
    assert client.post("/api/setup/telegram/test", json=TELEGRAM_INPUT, headers=HEADERS).status_code == 403
    assert client.post("/api/incidents/test/questions", json={"question": "Why?"}, headers=HEADERS).status_code == 403
    assert client.post("/api/incidents/test/review", json=DECISION, headers=HEADERS).status_code == 403
    assert calls == []
    # Optional integrations can still be explicitly disabled.
    assert client.post("/api/setup/provider", json={"provider": "none"}, headers=HEADERS).status_code == 200
    assert client.post("/api/setup/telegram", json={"enabled": False}, headers=HEADERS).status_code == 200


def test_permissions_require_admin_session_exact_origin_and_strict_values(stack):
    client, _, _ = stack
    assert client.get(URL).status_code == 401
    assert client.post(URL, json=ON, headers=HEADERS).status_code == 401
    login(client)
    for headers in ({}, {"Origin": "http://foreign.example"}):
        assert client.post(URL, json=ON, headers=headers).status_code == 403
    for body in ({}, ON | {"ai_requests": "true"}, ON | {"live_execution": True}):
        assert client.post(URL, json=body, headers=HEADERS).status_code == 422


def test_permissions_enable_and_revoke_requests_and_receipts(stack):
    client, directory, calls = stack
    login(client)
    assert client.post(URL, json=ON, headers=HEADERS).status_code == 200
    first = client.post("/api/setup/provider/test", json=PROVIDER_INPUT, headers=HEADERS).json()["test_id"]
    second = client.post("/api/setup/telegram/test", json=TELEGRAM_INPUT, headers=HEADERS).json()["test_id"]
    assert len(calls) == 2
    assert client.post(URL, json=OFF, headers=HEADERS).status_code == 200
    assert client.post("/api/setup/provider", json={"provider": "claude", "test_id": first}, headers=HEADERS).status_code == 403
    assert client.post("/api/setup/telegram", json={"enabled": True, "test_id": second}, headers=HEADERS).status_code == 403
    assert client.post(URL, json=ON, headers=HEADERS).status_code == 200
    assert client.post("/api/setup/provider", json={"provider": "claude", "test_id": first}, headers=HEADERS).status_code == 409
    assert client.post("/api/setup/telegram", json={"enabled": True, "test_id": second}, headers=HEADERS).status_code == 409
    assert json.loads((directory / "permissions.json").read_text())["version"] == 2
    assert SecretStore(directory).read("permissions")[0] == {"version": 1, **ON}


def test_host_disabled_review_cannot_be_enabled_and_no_execution_flags_are_written(stack):
    client, directory, _ = stack
    login(client)
    assert client.post(URL, json=ON | {"response_decisions": True}, headers=HEADERS).status_code == 409
    assert not (directory / "permissions.json").exists()
    assert client.post(URL, json=OFF, headers=HEADERS).status_code == 200
    assert SecretStore(directory).read("permissions")[0] == {"version": 1, **OFF}


def test_permission_failure_cannot_dispatch_controller_decision(stack, monkeypatch):
    client, directory, _ = stack
    login(client)
    calls = []
    monkeypatch.setattr("bantis_dashboard.response.ResponseController.request", lambda *args: calls.append(args))
    (directory / "permissions.json").write_text("invalid")
    (directory / "permissions.json").chmod(0o600)
    assert client.post("/api/incidents/test/review", json=DECISION, headers=HEADERS).status_code == 503
    assert calls == []


def test_encrypted_permissions_survive_restart(stack):
    client, directory, _ = stack
    login(client)
    client.post(URL, json=ON, headers=HEADERS)
    app = create_app(Settings(token=TOKEN, origin=ORIGIN, state_dir=directory),
                     transport=httpx.MockTransport(lambda _: httpx.Response(503)))
    with TestClient(app) as restarted:
        login(restarted)
        result = restarted.get(URL).json()
        assert result["configured"] is True
        assert all(result[key] == value for key, value in ON.items())


def test_private_key_loss_disables_capabilities_and_never_recreates_key(stack):
    client, directory, _ = stack
    login(client)
    client.post(URL, json=ON, headers=HEADERS)
    key = directory / ".secrets.key"
    key.unlink()
    assert client.get(URL).status_code == 503
    assert client.post(URL, json=OFF, headers=HEADERS).status_code == 503
    assert client.post("/api/setup/provider/test", json=PROVIDER_INPUT, headers=HEADERS).status_code == 503
    assert not key.exists()


def test_manual_decisions_still_require_the_controller_contract(tmp_path):
    tmp_path.chmod(0o700)
    permissions = PermissionsSetup(SecretStore(tmp_path), response_enabled=True)
    saved = permissions.save(PermissionsSave(**(OFF | {"response_decisions": True})))
    assert saved["response_review_available"] is True
    assert saved["response_decisions"] is True
    assert not any(key in saved for key in ("dry_run", "enabled_actions", "automatic"))


def test_tampered_permissions_cannot_be_overwritten_as_a_recovery_shortcut(stack):
    client, directory, _ = stack
    login(client)
    client.post(URL, json=ON, headers=HEADERS)
    path = directory / "permissions.json"
    path.write_text("tampered")
    assert client.get(URL).status_code == 503
    assert client.post(URL, json=OFF, headers=HEADERS).status_code == 503
    assert path.read_text() == "tampered"


def test_permissions_changed_during_network_test_discard_the_receipt(stack, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    import threading

    client, _, _ = stack
    login(client)
    client.post(URL, json=ON, headers=HEADERS)
    reached = threading.Event()
    release = threading.Event()
    from bantis_dashboard.provider_setup import ProviderSetup
    original = ProviderSetup.test

    def pause(self, body, session_id):
        reached.set()
        assert release.wait(5)
        return original(self, body, session_id)

    monkeypatch.setattr(ProviderSetup, "test", pause)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(client.post, "/api/setup/provider/test", json=PROVIDER_INPUT, headers=HEADERS)
        try:
            assert reached.wait(5)
            assert client.post(URL, json=OFF, headers=HEADERS).status_code == 200
        finally:
            release.set()
        response = future.result(timeout=10)
    assert response.status_code == 409
    assert "Permissions changed" in response.text


def test_enabled_manual_decisions_preserve_separate_controller_authorization(tmp_path, monkeypatch):
    calls = []

    def controller(self, incident_id, decision=None):
        calls.append((incident_id, decision))
        return {"error": "Controller authorization still applies"}

    monkeypatch.setattr("bantis_dashboard.response.ResponseController.request", controller)
    app = create_app(Settings(token=TOKEN, origin=ORIGIN, state_dir=tmp_path, response_enabled=True),
                     transport=httpx.MockTransport(lambda _: httpx.Response(503)))
    with TestClient(app) as client:
        client.post("/api/setup/admin", json=CREATE, headers=HEADERS)
        login(client)
        assert client.post(URL, json=ON | {"response_decisions": True}, headers=HEADERS).status_code == 200
        without_secret = {key: value for key, value in DECISION.items() if key != "secret"}
        assert client.post("/api/incidents/test/review", json=without_secret, headers=HEADERS).status_code == 422
        assert calls == []
        assert client.post("/api/incidents/test/review", json=DECISION, headers=HEADERS).status_code == 200
        assert len(calls) == 1 and calls[0][1].secret == DECISION["secret"]
        assert client.post(URL, json=OFF, headers=HEADERS).status_code == 200
        assert client.post("/api/incidents/test/review", json=DECISION, headers=HEADERS).status_code == 403
        assert len(calls) == 1