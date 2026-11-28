import json
import sqlite3
from threading import Thread
from urllib.request import urlopen
from wsgiref.simple_server import make_server

import pytest

from gap_detector.api import create_app
from gap_detector.review_queue import ReviewQueue
from gap_detector.suggester import suggest_rules
from test_suggester import event, report_for


def request(app, path="/rules/suggestions/pending", method="GET"):
    response = {}

    def start_response(status, headers):
        response.update(status=status, headers=dict(headers))

    response["body"] = json.loads(b"".join(app(
        {"PATH_INFO": path, "REQUEST_METHOD": method}, start_response)))
    return response


def test_pending_endpoint_reflects_persistent_review_decisions(tmp_path):
    path = tmp_path / "queue.db"
    queue = ReviewQueue(path)
    app = create_app(queue)
    assert request(app)["body"] == {"items": []}
    queue.enqueue(suggest_rules(report_for(tmp_path, event())))
    proposal, = request(app)["body"]["items"]
    assert proposal == queue.list()[0]
    assert proposal["draft"]["enabled"] is False
    queue.decide(proposal["proposal_id"], "approved", reviewer="operator", reason="Checked evidence")
    queue.enqueue(suggest_rules(report_for(tmp_path, event("leaked-secret"))))
    rejected, = queue.list()
    queue.decide(rejected["proposal_id"], "rejected", reviewer="operator", reason="Needs pipeline repair")
    response = request(create_app(ReviewQueue(path)))
    assert response["status"] == "200 OK"
    assert response["body"] == {"items": []}
    assert response["headers"]["Cache-Control"] == "no-store"
    assert response["headers"]["Content-Type"] == "application/json"
    assert len(queue.list(None)) == 2
    assert all(item["draft"]["enabled"] is False for item in queue.list(None))


def test_pending_endpoint_over_http(tmp_path):
    queue = ReviewQueue(tmp_path / "queue.db")
    queue.enqueue(suggest_rules(report_for(tmp_path, event())))
    with make_server("127.0.0.1", 0, create_app(queue)) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/rules/suggestions/pending"
            with urlopen(url, timeout=2) as response:
                assert response.status == 200
                assert response.headers["Cache-Control"] == "no-store"
                assert json.load(response) == {"items": queue.list()}
        finally:
            server.shutdown()
            thread.join(timeout=2)


def test_endpoint_rejects_unknown_paths_and_writes(tmp_path):
    queue = ReviewQueue(tmp_path / "queue.db")
    app = create_app(queue)
    assert request(app, path="/unknown")["status"] == "404 Not Found"
    response = request(app, method="POST")
    assert response["status"] == "405 Method Not Allowed"
    assert response["headers"]["Allow"] == "GET"
    assert not queue.path.exists()


@pytest.mark.parametrize("error", [OSError, sqlite3.OperationalError, ValueError])
def test_queue_failure_is_unavailable_and_does_not_leak_details(tmp_path, monkeypatch, error):
    queue = ReviewQueue(tmp_path / "queue.db")

    def fail(**kwargs):
        raise error("private queue details")

    monkeypatch.setattr(queue, "list", fail)
    response = request(create_app(queue))
    assert response["status"] == "503 Service Unavailable"
    assert response["body"] == {"error": "Review queue unavailable"}