"""Dashboard reads the real Detection Engine over loopback HTTP."""

from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect


def test_dashboard_reads_real_incident_and_revokes_stream(detection_stack, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "dashboard"))
    from app.correlation import run_correlation
    from app.db import SessionLocal
    from bantis_dashboard.config import Settings
    from bantis_dashboard.main import create_app

    origin = "http://testserver"
    token = "dashboard-integration-test-access-token"
    with httpx.Client(base_url=detection_stack.url) as detection:
        response = detection.post(
            "/events",
            json={
                "event_id": "dashboard-event",
                "timestamp": "2026-11-09T09:00:00Z",
                "level": "WARNING",
                "logger": "integration",
                "source": "pipeline",
                "event_type": "container_image_pull",
                "message": "private-evidence-message",
                "details": {
                    "registry": "untrusted.example",
                    "image": "fixture:latest",
                    "tool_output_tail": "private-output",
                },
            },
        )
        assert response.status_code == 201
    with SessionLocal() as session:
        run_correlation(session)

    app = create_app(
        Settings(
            token=token,
            origin=origin,
            detection_url=detection_stack.url,
            poll_seconds=300,
        )
    )
    with TestClient(app) as dashboard:
        assert dashboard.get("/api/incidents").status_code == 401
        assert (
            dashboard.post(
                "/api/session", json={"token": token}, headers={"Origin": origin}
            ).status_code
            == 200
        )
        page = dashboard.get("/api/incidents?severity=high").json()
        assert page["total"] == 1
        incident_id = page["items"][0]["incident_id"]
        assert (
            dashboard.get(f"/api/incidents/{incident_id}").json()["pattern"]
            == "untrusted-registry-pull"
        )
        evidence = dashboard.get(f"/api/incidents/{incident_id}/events")
        assert evidence.json()[0]["event_id"] == "dashboard-event"
        assert evidence.json()[0]["details"] == {
            "registry": "untrusted.example",
            "image": "fixture:latest",
        }
        assert (
            "private-output" not in evidence.text
            and "private-evidence-message" not in evidence.text
        )
        with dashboard.websocket_connect("/ws", headers={"Origin": origin}) as ws:
            current = ws.receive_json()
            if current["sequence"] == 0:
                current = ws.receive_json()
            assert current["detection_engine"]["total_incidents"] == 1
            dashboard.delete("/api/session", headers={"Origin": origin})
            dashboard.portal.call(app.state.feed.poll)
            with pytest.raises(WebSocketDisconnect) as error:
                ws.receive_json()
            assert error.value.code == 1008


def test_live_feed_streams_uncorrelated_arrivals_from_real_engine(
    detection_stack, monkeypatch
):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "dashboard"))
    from bantis_dashboard.config import Settings
    from bantis_dashboard.main import create_app

    origin = "http://testserver"
    token = "dashboard-live-feed-integration-token"
    app = create_app(
        Settings(
            token=token,
            origin=origin,
            detection_url=detection_stack.url,
            poll_seconds=300,
        )
    )
    with (
        TestClient(app) as dashboard,
        httpx.Client(base_url=detection_stack.url) as detection,
    ):
        assert dashboard.get("/api/live-feed").status_code == 401
        dashboard.post(
            "/api/session", json={"token": token}, headers={"Origin": origin}
        )
        with dashboard.websocket_connect(
            "/ws/events", headers={"Origin": origin}
        ) as ws:
            current = ws.receive_json()
            if current["sequence"] == 0:
                current = ws.receive_json()
            assert current["total"] == 0 and current["status"] == "available"
            event = {
                "event_id": "uncorrelated-http",
                "timestamp": "2020-01-01T00:00:00Z",
                "level": "info",
                "logger": "integration",
                "source": "api",
                "event_type": "http_request",
                "message": "private-message",
                "details": {
                    "artifact": "fixture",
                    "tool_output_tail": "private-output",
                },
            }
            assert detection.post("/events", json=event).status_code == 201
            assert detection.post("/events", json=event).status_code == 200
            dashboard.portal.call(app.state.live_feed.poll)
            received = ws.receive_json()
            assert received["total"] == 1
            assert received["items"][0]["event_id"] == "uncorrelated-http"
            assert received["items"][0]["timestamp"] == "2020-01-01T00:00:00Z"
            assert received["items"][0]["details"] == {"artifact": "fixture"}
            assert "private-message" not in str(
                received
            ) and "private-output" not in str(received)
            assert dashboard.get("/api/incidents").json()["total"] == 0
            dashboard.delete("/api/session")
            dashboard.portal.call(app.state.live_feed.poll)
            with pytest.raises(WebSocketDisconnect) as error:
                ws.receive_json()
            assert error.value.code == 1008