import time

import pytest
from starlette.websockets import WebSocketDisconnect

from test_dashboard import EVENT, ORIGIN, login, snapshot, stack  # noqa: F401


def test_live_page_has_no_private_records_and_keeps_shared_shell(stack):
    client, _, _ = stack
    response = client.get("/live-feed")
    assert response.status_code == 200
    assert 'id="live-feed-view"' in response.text
    assert "private-raw-message" not in response.text
    assert 'href="/live-feed"' in response.text


def test_live_snapshot_normalizes_and_selects_fields(stack):
    client, app, _ = stack
    login(client)
    client.portal.call(app.state.live_feed.poll)
    response = client.get("/api/live-feed")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "available" and data["total"] == 1
    assert data["items"][0]["level"] == "INFO"
    assert data["items"][0]["details"] == {"image": "fixture:latest"}
    assert (
        "private-raw-message" not in response.text
        and "private-output" not in response.text
    )
    assert data["poll_seconds"] == 300


def test_two_live_clients_share_one_poll_and_receive_new_arrivals(stack):
    client, app, upstream = stack
    login(client)
    client.portal.call(app.state.live_feed.poll)
    calls = len(upstream["requests"])
    with client.websocket_connect("/ws/events", headers={"Origin": ORIGIN}) as first:
        initial = snapshot(first)
        with client.websocket_connect(
            "/ws/events", headers={"Origin": ORIGIN}
        ) as second:
            assert snapshot(second) == initial
            assert len(upstream["requests"]) == calls
            upstream["events"] = [
                {
                    **EVENT,
                    "event_id": "new-arrival",
                    "timestamp": "2020-01-01T00:00:00Z",
                    "received_at": "2026-11-09T09:00:02Z",
                },
                EVENT,
            ]
            upstream["event_total"] = 2
            client.portal.call(app.state.live_feed.poll)
            update = first.receive_json()
            assert second.receive_json() == update
            assert update["sequence"] > initial["sequence"]
            assert [event["event_id"] for event in update["items"]] == [
                "new-arrival",
                "event-1",
            ]
            assert not update["gap_possible"]
            assert len(upstream["requests"]) == calls + 1


def test_live_source_failure_preserves_rows_and_recovers(stack):
    client, app, upstream = stack
    login(client)
    client.portal.call(app.state.live_feed.poll)
    with client.websocket_connect("/ws/events", headers={"Origin": ORIGIN}) as ws:
        initial = snapshot(ws)
        upstream["event_status"] = 503
        client.portal.call(app.state.live_feed.poll)
        failed = ws.receive_json()
        assert failed["status"] == "unavailable"
        assert failed["items"] == initial["items"]
        assert failed["last_success_at"] == initial["last_success_at"]
        upstream["event_status"] = 200
        upstream["events"] = []
        upstream["event_total"] = 0
        client.portal.call(app.state.live_feed.poll)
        recovered = ws.receive_json()
        assert recovered["status"] == "available" and recovered["items"] == []
        assert recovered["total"] == 0 and recovered["gap_possible"]


def test_live_gap_is_visible_when_poll_outgrows_window(stack):
    client, app, upstream = stack
    login(client)
    client.portal.call(app.state.live_feed.poll)
    upstream["events"] = [{**EVENT, "event_id": "different"}]
    upstream["event_total"] = 1000
    client.portal.call(app.state.live_feed.poll)
    assert client.get("/api/live-feed").json()["gap_possible"]


@pytest.mark.parametrize(
    "invalid",
    [
        [{**EVENT, "level": "nonsense"}],
        [EVENT, EVENT],
        [{**EVENT, "received_at": "invalid"}],
    ],
)
def test_invalid_live_data_fails_closed_without_overwriting_window(stack, invalid):
    client, app, upstream = stack
    login(client)
    client.portal.call(app.state.live_feed.poll)
    before = client.get("/api/live-feed").json()
    upstream["events"] = invalid
    client.portal.call(app.state.live_feed.poll)
    after = client.get("/api/live-feed").json()
    assert after["status"] == "unavailable" and after["items"] == before["items"]


def test_initial_live_outage_is_not_reported_as_zero(stack):
    client, app, upstream = stack
    login(client)
    upstream["event_status"] = 503
    # A fresh feed has no successful data to preserve.
    from bantis_dashboard.live_feed import LiveFeed

    app.state.live_feed = LiveFeed(app.state.detection, 300)
    client.portal.call(app.state.live_feed.poll)
    data = client.get("/api/live-feed").json()
    assert (
        data["status"] == "unavailable"
        and data["total"] is None
        and data["items"] == []
    )


@pytest.mark.parametrize("origin", [None, "null", "https://attacker.example"])
def test_live_socket_requires_exact_origin(stack, origin):
    client, _, _ = stack
    login(client)
    with (
        pytest.raises(WebSocketDisconnect) as error,
        client.websocket_connect(
            "/ws/events", headers={"Origin": origin} if origin else {}
        ),
    ):
        pass
    assert error.value.code == 1008


def test_live_socket_rejects_missing_or_expired_session(stack):
    client, app, _ = stack
    with (
        pytest.raises(WebSocketDisconnect),
        client.websocket_connect("/ws/events", headers={"Origin": ORIGIN}),
    ):
        pass
    login(client)
    for key in app.state.sessions.entries:
        app.state.sessions.entries[key] = time.monotonic() - 1
    with (
        pytest.raises(WebSocketDisconnect),
        client.websocket_connect("/ws/events", headers={"Origin": ORIGIN}),
    ):
        pass


def test_logout_revokes_live_stream(stack):
    client, app, _ = stack
    login(client)
    with client.websocket_connect("/ws/events", headers={"Origin": ORIGIN}) as ws:
        snapshot(ws)
        client.delete("/api/session")
        client.portal.call(app.state.live_feed.poll)
        with pytest.raises(WebSocketDisconnect) as error:
            ws.receive_json()
        assert error.value.code == 1008


def test_live_window_cannot_exceed_500_events(stack):
    client, app, upstream = stack
    login(client)
    upstream["events"] = [{**EVENT, "event_id": str(index)} for index in range(501)]
    client.portal.call(app.state.live_feed.poll)
    assert client.get("/api/live-feed").json()["status"] == "unavailable"