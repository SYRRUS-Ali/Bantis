import sqlite3
import stat
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from bantis_dashboard.admin import AdminError, AdminStore, AuthLimiter
from bantis_dashboard.config import Settings
from bantis_dashboard.main import COOKIE, create_app
from test_dashboard import ORIGIN, TOKEN

PASSWORD = "a unique administrator passphrase"
CREATE = {"username": "Admin.User", "password": PASSWORD,
          "password_confirmation": PASSWORD, "bootstrap_token": TOKEN}
HEADERS = {"Origin": ORIGIN}


def app_for(directory, **options):
    return create_app(Settings(token=TOKEN, origin=ORIGIN, state_dir=directory, **options),
                      transport=httpx.MockTransport(lambda _: httpx.Response(503)))


@pytest.fixture
def setup(tmp_path):
    directory = tmp_path / "dashboard-state"
    app = app_for(directory)
    with TestClient(app) as client:
        yield client, app, directory


def create(client, **changes):
    return client.post("/api/setup/admin", json=CREATE | changes, headers=HEADERS)


def sign_in(client, **changes):
    return client.post("/api/admin/session", json={"username": "admin.user", "password": PASSWORD} | changes,
                       headers=HEADERS)


def test_first_run_persists_private_hash_and_requires_sign_in(setup):
    client, _, directory = setup
    assert client.get("/api/setup").json() == {"enabled": True, "admin_created": False}
    assert client.get("/setup").status_code == 200
    response = create(client)
    assert response.status_code == 201
    assert response.json() == {"created": True, "username": "admin.user"}
    assert COOKIE not in client.cookies
    assert client.get("/api/status").status_code == 401
    assert client.get("/api/setup").json() == {"enabled": True, "admin_created": True}
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    path = directory / "admin.sqlite3"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with sqlite3.connect(path) as db:
        row = db.execute("SELECT username, salt, password_hash, algorithm FROM administrator").fetchone()
    assert row[0] == "admin.user" and len(row[1]) == 16 and len(row[2]) == 32
    assert row[3] == "scrypt-v1"
    assert PASSWORD.encode() not in path.read_bytes() and TOKEN.encode() not in path.read_bytes()
    assert PASSWORD not in response.text and TOKEN not in response.text
    assert sign_in(client, username="ADMIN.USER").status_code == 200
    assert client.get("/api/status").status_code == 200


def test_account_and_setup_lock_survive_restart(setup):
    client, _, directory = setup
    assert create(client).status_code == 201
    assert sign_in(client).status_code == 200
    old_session = client.cookies[COOKIE]
    with TestClient(app_for(directory)) as restarted:
        restarted.cookies.set(COOKIE, old_session)
        assert restarted.get("/api/status").status_code == 401
        assert restarted.get("/api/setup").json()["admin_created"] is True
        assert create(restarted, username="replacement").status_code == 409
        assert sign_in(restarted).status_code == 200


@pytest.mark.parametrize("stage", ["before", "after"])
def test_bootstrap_token_cannot_open_admin_dashboard(setup, stage):
    client, _, _ = setup
    if stage == "after":
        create(client)
    assert client.post("/api/session", json={"token": TOKEN}, headers=HEADERS).status_code == 401
    assert client.get("/api/status").status_code == 401


@pytest.mark.parametrize("origin", [None, "null", "https://foreign.example"])
def test_setup_and_admin_sign_in_require_exact_origin(setup, origin):
    client, _, _ = setup
    headers = {"Origin": origin} if origin is not None else {}
    assert client.post("/api/setup/admin", json=CREATE, headers=headers).status_code == 403
    assert client.post("/api/admin/session", json={"username": "admin", "password": PASSWORD},
                       headers=headers).status_code == 403
    assert client.get("/api/setup").json()["admin_created"] is False


@pytest.mark.parametrize("changes", [
    {"username": "ab"}, {"username": " admin"}, {"username": "<script>"},
    {"username": "a" * 65}, {"password": "short", "password_confirmation": "short"},
    {"password_confirmation": "a different long passphrase"},
    {"password": " " * 15, "password_confirmation": " " * 15},
    {"password": "x" * 129, "password_confirmation": "x" * 129},
    {"role": "admin"}, {"bootstrap_token": "x" * 513},
])
def test_validation_never_persists_or_echoes_credentials(setup, changes):
    client, _, _ = setup
    response = create(client, **changes)
    assert response.status_code == 422
    assert PASSWORD not in response.text and TOKEN not in response.text
    assert client.get("/api/setup").json()["admin_created"] is False


def test_wrong_bootstrap_and_password_do_not_authorize(setup):
    client, _, _ = setup
    assert create(client, bootstrap_token="wrong-secret").status_code == 403
    assert create(client).status_code == 201
    assert sign_in(client, password="incorrect password").status_code == 401
    assert sign_in(client, username="unknown").status_code == 401
    assert client.get("/api/status").status_code == 401
    assert sign_in(client).status_code == 200


def test_duplicate_creation_cannot_replace_account(setup):
    client, _, _ = setup
    assert create(client).status_code == 201
    assert create(client, username="intruder").status_code == 409
    assert sign_in(client, username="intruder").status_code == 401
    assert sign_in(client).status_code == 200


def test_concurrent_process_stores_create_exactly_one_admin(tmp_path):
    stores = [AdminStore(tmp_path), AdminStore(tmp_path)]

    def attempt(index):
        try:
            stores[index].create(f"admin{index}", PASSWORD)
            return 201
        except AdminError as exc:
            return exc.status

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(attempt, range(2))) == [201, 409]
    with sqlite3.connect(tmp_path / "admin.sqlite3") as db:
        assert db.execute("SELECT count(*) FROM administrator").fetchone()[0] == 1


def test_failed_write_can_be_retried_without_partial_account(setup, monkeypatch):
    client, _, _ = setup
    from bantis_dashboard import admin

    original = admin.password_hash

    def fail(*args):
        raise AdminError(503, "Password hashing unavailable")

    monkeypatch.setattr(admin, "password_hash", fail)
    assert create(client).status_code == 503
    assert client.get("/api/setup").json()["admin_created"] is False
    monkeypatch.setattr(admin, "password_hash", original)
    assert create(client).status_code == 201


@pytest.mark.parametrize("failure", ["missing", "corrupt", "invalid_record"])
def test_unavailable_state_fails_closed_without_reopening_setup(setup, failure):
    client, _, directory = setup
    assert create(client).status_code == 201
    path = directory / "admin.sqlite3"
    if failure == "missing":
        path.rename(directory / "saved.sqlite3")
    elif failure == "corrupt":
        path.write_text("broken sqlite")
    else:
        with sqlite3.connect(path) as db:
            db.execute("UPDATE administrator SET algorithm = 'unknown'")
    assert client.get("/api/setup").status_code == 503
    assert create(client).status_code == 503
    assert sign_in(client).status_code == 503
    if failure == "missing":
        assert not path.exists()


def test_bootstrap_attempts_are_rate_limited(setup):
    client, _, _ = setup
    for _ in range(10):
        assert create(client, bootstrap_token="incorrect").status_code == 403
    response = create(client)
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "60"


def test_limiter_recovers_after_window(monkeypatch):
    now = [0.0]
    monkeypatch.setattr("bantis_dashboard.admin.time.monotonic", lambda: now[0])
    limiter = AuthLimiter()
    for _ in range(10):
        limiter.check()
    with pytest.raises(AdminError) as error:
        limiter.check()
    assert error.value.status == 429
    now[0] = 60
    limiter.check()


def test_admin_cookie_rotation_logout_and_websocket_revocation(setup):
    client, app, _ = setup
    create(client)
    response = sign_in(client)
    assert "HttpOnly" in response.headers["set-cookie"]
    assert "SameSite=strict" in response.headers["set-cookie"]
    first = client.cookies[COOKIE]
    sign_in(client)
    assert not app.state.sessions.valid(first)
    with client.websocket_connect("/ws", headers=HEADERS) as ws:
        ws.receive_json()
        session_id = client.cookies[COOKIE]
        assert client.delete("/api/session", headers=HEADERS).status_code == 200
        client.portal.call(app.state.feed.poll)
        with pytest.raises(WebSocketDisconnect):
            ws.receive_json()
        assert not app.state.sessions.valid(session_id)


def test_state_directory_configuration_rejects_relative_or_public_paths(tmp_path):
    from pathlib import Path

    with pytest.raises(ValueError, match="absolute path"):
        Settings(token=TOKEN, state_dir=Path("relative"))
    public = tmp_path / "public"
    public.mkdir(mode=0o755)
    with pytest.raises(AdminError):
        app_for(public)


@pytest.mark.parametrize("content", [b"", b"broken sqlite database"])
def test_restart_cannot_reinitialize_existing_invalid_database(tmp_path, content):
    path = tmp_path / "admin.sqlite3"
    path.write_bytes(content)
    path.chmod(0o600)
    with pytest.raises(AdminError):
        app_for(tmp_path)
    assert path.read_bytes() == content


def test_token_mode_keeps_setup_disabled():
    app = create_app(Settings(token=TOKEN, origin=ORIGIN),
                      transport=httpx.MockTransport(lambda _: httpx.Response(503)))
    with TestClient(app) as client:
        assert client.get("/api/setup").json() == {"enabled": False, "admin_created": False}
        assert create(client).status_code == 503
        assert client.post("/api/session", json={"token": TOKEN}).status_code == 200