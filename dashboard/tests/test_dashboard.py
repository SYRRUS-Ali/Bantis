import json
import time

import httpx
import pytest
from bantis_dashboard.config import Settings
from bantis_dashboard.main import COOKIE, create_app
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

ORIGIN = "http://testserver"
TOKEN = "dashboard-test-token-with-at-least-32-bytes"
INCIDENT = {
    "incident_id": "incident-1",
    "created_at": "2026-11-09T09:00:00Z",
    "pattern": "same-source-burst",
    "window_seconds": 60,
    "correlated_event_ids": ["e-b", "e-a"],
    "mitre_techniques": ["T1195.001"],
    "severity": "high",
    "confidence": 0.5,
    "summary": "Dependency signals observed",
}


@pytest.fixture
def stack():
    upstream = {"status": 200, "invalid": None, "requests": [], "total": 1}

    def handle(request):
        upstream["requests"].append(request)
        if upstream["status"] != 200:
            return httpx.Response(upstream["status"], text="private-upstream-error")
        if upstream["invalid"] is not None:
            return httpx.Response(200, content=upstream["invalid"])
        if request.url.path.endswith("/events"):
            return httpx.Response(
                200,
                json=[
                    {
                        "event_id": event_id,
                        "timestamp": "2026-11-09T09:00:00Z",
                        "source": "attack-sim",
                        "event_type": "attack_scenario_run",
                        "message": "secret-message",
                        "details": {
                            "scenario": "malicious-dependency",
                            "tool_output_tail": "raw-secret",
                            "other": "secret",
                        },
                    }
                    for event_id in ["e-b", "e-a"]
                ],
            )
        if request.url.path.endswith("incident-1"):
            return httpx.Response(200, json=INCIDENT)
        params = request.url.params
        items = [INCIDENT] if upstream["total"] else []
        if params.get("severity") not in {None, "high"}:
            items = []
        return httpx.Response(
            200,
            json={
                "total": upstream["total"] if items else 0,
                "limit": int(params.get("limit", "20")),
                "offset": int(params.get("offset", "0")),
                "items": items,
            },
        )

    app = create_app(
        Settings(token=TOKEN, origin=ORIGIN, poll_seconds=300),
        transport=httpx.MockTransport(handle),
    )
    with TestClient(app) as client:
        yield client, app, upstream


def login(client):
    response = client.post(
        "/api/session", json={"token": TOKEN}, headers={"Origin": ORIGIN}
    )
    assert response.status_code == 200
    return response


def snapshot(ws):
    value = ws.receive_json()
    if value["sequence"] == 0:
        value = ws.receive_json()
    return value


@pytest.mark.parametrize(
    "path",
    [
        "/api/status",
        "/api/session",
        "/api/incidents",
        "/api/incidents/incident-1",
        "/api/incidents/incident-1/events",
    ],
)
def test_private_http_routes_require_session(stack, path):
    client, _, _ = stack
    assert client.get(path).status_code == 401


def test_shell_and_assets_are_served_with_security_headers(stack):
    client, _, _ = stack
    response = client.get("/")
    assert response.status_code == 200
    assert 'lang="en"' in response.text
    assert "Dependency signals observed" not in response.text
    assert response.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/styles.css").status_code == 200
    assert client.get("/health").json()["status"] == "ok"


def test_wrong_host_is_rejected(stack):
    client, _, _ = stack
    assert client.get("/", headers={"Host": "attacker.example"}).status_code == 400


def test_login_and_logout_use_revocable_httponly_cookie(stack):
    client, app, _ = stack
    response = login(client)
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie
    assert TOKEN not in cookie
    old_session = client.cookies[COOKIE]
    assert client.get("/api/session").status_code == 200
    assert client.delete("/api/session", headers={"Origin": ORIGIN}).status_code == 200
    assert not app.state.sessions.valid(old_session)
    client.cookies.set(COOKIE, old_session)
    assert client.get("/api/status").status_code == 401


def test_invalid_login_and_validation_never_echo_token(stack):
    client, _, _ = stack
    assert client.post("/api/session", json={"token": "wrong"}).status_code == 401
    secret = "private-value" * 60
    response = client.post("/api/session", json={"token": secret})
    assert response.status_code == 422
    assert secret not in response.text
    assert "private-value" not in response.text


@pytest.mark.parametrize("method", ["post", "delete"])
def test_cross_origin_session_mutations_are_rejected(stack, method):
    client, _, _ = stack
    options = {"json": {"token": TOKEN}} if method == "post" else {}
    assert (
        getattr(client, method)(
            "/api/session", headers={"Origin": "https://attacker.example"}, **options
        ).status_code
        == 403
    )


def test_session_expiry_and_rotation(stack):
    client, app, _ = stack
    login(client)
    previous = client.cookies[COOKIE]
    login(client)
    assert not app.state.sessions.valid(previous)
    app.state.sessions.entries[client.cookies[COOKIE]] = time.monotonic() - 1
    assert client.get("/api/incidents").status_code == 401


def test_filter_and_pagination_forwarding(stack):
    client, _, upstream = stack
    login(client)
    response = client.get(
        "/api/incidents",
        params={
            "severity": "high",
            "pattern": "same-source-burst",
            "since": "2026-11-09T09:00:00Z",
            "limit": 10,
            "offset": 20,
        },
    )
    assert response.status_code == 200
    params = upstream["requests"][-1].url.params
    assert dict(params) == {
        "severity": "high",
        "pattern": "same-source-burst",
        "since": "2026-11-09T09:00:00+00:00",
        "limit": "10",
        "offset": "20",
    }
    assert response.json()["items"][0]["incident_id"] == "incident-1"
    assert all(request.method == "GET" for request in upstream["requests"])


@pytest.mark.parametrize(
    "query", ["limit=0", "limit=201", "offset=-1", "severity=unknown", "since=bad"]
)
def test_invalid_filters_are_rejected(stack, query):
    client, _, _ = stack
    login(client)
    assert client.get(f"/api/incidents?{query}").status_code == 422


def test_detail_and_evidence_are_read_only_and_selected_fields_only(stack):
    client, _, _ = stack
    login(client)
    assert client.get("/api/incidents/incident-1").json()["incident_id"] == "incident-1"
    evidence = client.get("/api/incidents/incident-1/events")
    assert evidence.status_code == 200
    assert [event["event_id"] for event in evidence.json()] == ["e-a", "e-b"]
    assert evidence.json()[0]["details"] == {"scenario": "malicious-dependency"}
    assert "raw-secret" not in evidence.text and "secret-message" not in evidence.text
    assert (
        client.post(
            "/api/incidents/incident-1", json={"status": "resolved"}
        ).status_code
        == 405
    )


def test_upstream_failure_is_explicit_and_does_not_leak_private_errors(stack):
    client, _, upstream = stack
    login(client)
    upstream["status"] = 500
    response = client.get("/api/incidents")
    assert response.status_code == 503
    assert "private-upstream-error" not in response.text
    upstream["status"] = 404
    assert client.get("/api/incidents/missing").status_code == 404


@pytest.mark.parametrize(
    "payload",
    [
        b"not-json",
        b"{}",
        b"[]",
        json.dumps(
            {
                "total": 1,
                "limit": 20,
                "offset": 0,
                "items": [{**INCIDENT, "confidence": 3}],
            }
        ).encode(),
        b" " * 2_000_001,
    ],
    ids=[
        "invalid-json",
        "missing-fields",
        "wrong-shape",
        "invalid-confidence",
        "oversized",
    ],
)
def test_invalid_or_oversized_upstream_data_is_rejected(stack, payload):
    client, _, upstream = stack
    login(client)
    upstream["invalid"] = payload
    assert client.get("/api/incidents").status_code == 502


def test_transport_failure_becomes_service_unavailable():
    def fail(request):
        raise httpx.ConnectError("private connection details")

    app = create_app(
        Settings(token=TOKEN, origin=ORIGIN), transport=httpx.MockTransport(fail)
    )
    with TestClient(app) as client:
        login(client)
        response = client.get("/api/incidents")
        assert response.status_code == 503
        assert "private connection" not in response.text


def test_websocket_rejects_missing_session_and_cross_origin(stack):
    client, _, _ = stack
    with (
        pytest.raises(WebSocketDisconnect) as error,
        client.websocket_connect("/ws", headers={"Origin": ORIGIN}),
    ):
        pass
    assert error.value.code == 1008
    login(client)
    for origin in [None, "null", "https://attacker.example"]:
        with (
            pytest.raises(WebSocketDisconnect),
            client.websocket_connect(
                "/ws", headers={"Origin": origin} if origin else {}
            ),
        ):
            pass


def test_websocket_shares_updates_and_retains_stale_count_on_failure(stack):
    client, app, upstream = stack
    login(client)
    with client.websocket_connect("/ws", headers={"Origin": ORIGIN}) as first:
        initial = snapshot(first)
        assert initial["detection_engine"] == {
            "status": "available",
            "total_incidents": 1,
        }
        with client.websocket_connect("/ws", headers={"Origin": ORIGIN}) as second:
            assert snapshot(second) == initial
            upstream["status"] = 503
            client.portal.call(app.state.feed.poll)
            failed = first.receive_json()
            assert second.receive_json() == failed
            assert failed["detection_engine"] == {
                "status": "unavailable",
                "total_incidents": 1,
            }
            assert failed["last_success_at"] == initial["last_success_at"]
            upstream["status"] = 200
            upstream["total"] = 0
            client.portal.call(app.state.feed.poll)
            assert first.receive_json()["detection_engine"] == {
                "status": "available",
                "total_incidents": 0,
            }


def test_logout_revokes_an_open_websocket(stack):
    client, app, _ = stack
    login(client)
    with client.websocket_connect("/ws", headers={"Origin": ORIGIN}) as ws:
        snapshot(ws)
        client.delete("/api/session")
        client.portal.call(app.state.feed.poll)
        with pytest.raises(WebSocketDisconnect) as error:
            ws.receive_json()
        assert error.value.code == 1008


@pytest.mark.parametrize(
    "options",
    [
        {"token": "short"},
        {"origin": "http://host/path"},
        {"origin": "http://user:password@host"},
        {"poll_seconds": float("nan")},
        {"poll_seconds": 0},
        {"detection_url": "file:///tmp/test"},
    ],
)
def test_invalid_configuration_fails_before_serving(options):
    with pytest.raises(ValueError):
        Settings(**({"token": TOKEN} | options))


def test_https_uses_secure_cookie():
    app = create_app(
        Settings(token=TOKEN, origin="https://testserver"),
        transport=httpx.MockTransport(lambda request: httpx.Response(503)),
    )
    with TestClient(app, base_url="https://testserver") as client:
        response = client.post(
            "/api/session",
            json={"token": TOKEN},
            headers={"Origin": "https://testserver"},
        )
        assert "Secure" in response.headers["set-cookie"]