"""Exercise stream shutdown while shared polling and sibling clients stay active."""

import asyncio

import anyio
import pytest
from bantis_dashboard.main import COOKIE
from test_dashboard import ORIGIN, login, snapshot

pytest_plugins = ["test_dashboard"]


@pytest.mark.parametrize(
    "path,feed_name", [("/ws", "feed"), ("/ws/events", "live_feed")]
)
def test_repeated_disconnects_do_not_cancel_sibling_streams(stack, path, feed_name):
    client, app, _ = stack
    login(client)
    feed = getattr(app.state, feed_name)
    client.portal.call(feed.poll)
    with client.websocket_connect(path, headers={"Origin": ORIGIN}) as survivor:
        previous = snapshot(survivor)
        for _ in range(30):
            with client.websocket_connect(path, headers={"Origin": ORIGIN}) as closing:
                assert snapshot(closing) == previous
                client.portal.call(feed.poll)
                previous = survivor.receive_json()
                assert closing.receive_json() == previous
            # The other client's disconnect must neither stop polling nor cancel us.
            client.portal.call(feed.poll)
            current = survivor.receive_json()
            assert current["sequence"] > previous["sequence"]
            previous = current


@pytest.mark.parametrize("path", ["/ws", "/ws/events"])
@pytest.mark.parametrize("cancel_delay", range(6))
def test_disconnect_racing_with_asgi_cancellation_finishes_cleanly(
    stack, path, cancel_delay
):
    client, app, _ = stack
    login(client)
    session_id = client.cookies.get(COOKIE)

    async def connection():
        sent = anyio.Event()
        connected = False
        messages = []
        loop = asyncio.get_running_loop()

        def cancel_after_turns(remaining):
            if remaining:
                loop.call_soon(cancel_after_turns, remaining - 1)
            else:
                shutdown.cancel()

        async def receive():
            nonlocal connected
            if not connected:
                connected = True
                return {"type": "websocket.connect"}
            await sent.wait()
            # ASGI servers may cancel a connection immediately after disconnect.
            loop.call_soon(cancel_after_turns, cancel_delay)
            return {"type": "websocket.disconnect", "code": 1000}

        async def send(message):
            messages.append(message)
            if message["type"] == "websocket.send":
                sent.set()

        scope = {
            "type": "websocket",
            "path": path,
            "root_path": "",
            "scheme": "ws",
            "query_string": b"",
            "server": ("testserver", 80),
            "client": ("testclient", 50000),
            "headers": [
                (b"host", b"testserver"),
                (b"origin", ORIGIN.encode()),
                (b"cookie", f"{COOKIE}={session_id}".encode()),
            ],
        }
        with anyio.fail_after(2), anyio.CancelScope() as shutdown:
            await app(scope, receive, send)
            # Keep the server-side scope alive until its scheduled shutdown,
            # just as TestClient does after the application returns.
            await anyio.sleep_forever()
        assert shutdown.cancelled_caught
        assert any(message["type"] == "websocket.send" for message in messages)

    client.portal.call(connection)