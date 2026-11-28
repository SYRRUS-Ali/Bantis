"""Local HTTP access to pending rule proposals; review remains a CLI operation."""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from wsgiref.simple_server import make_server

from .review_queue import ReviewQueue


def create_app(queue: ReviewQueue):
    def app(environ, start_response):
        headers = []
        if environ["PATH_INFO"] != "/rules/suggestions/pending":
            status, result = "404 Not Found", {"error": "Not found"}
        elif environ["REQUEST_METHOD"] != "GET":
            status, result = "405 Method Not Allowed", {"error": "Method not allowed"}
            headers.append(("Allow", "GET"))
        else:
            try:
                result = {"items": queue.list(status="pending_review")}
                status = "200 OK"
            except (OSError, ValueError, sqlite3.Error):
                status, result = "503 Service Unavailable", {"error": "Review queue unavailable"}
        body = json.dumps(result).encode("utf-8")
        start_response(status, headers + [("Content-Type", "application/json"),
                                         ("Content-Length", str(len(body))),
                                         ("Cache-Control", "no-store")])
        return [body]

    return app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Serve pending rule proposals on loopback.")
    parser.add_argument("--queue", required=True, type=Path)
    parser.add_argument("--port", type=int, default=8200)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    with make_server("127.0.0.1", args.port, create_app(ReviewQueue(args.queue))) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())