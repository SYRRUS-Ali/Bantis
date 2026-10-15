#!/usr/bin/env python3
"""Exports real Sprint 3 incidents for evaluating the Copilot's prompt.

Runs the four M2 scenarios for real against a live detection-engine (the
same machinery as run_m2_baseline.py), posts one untrusted-registry image
pull so all three Sprint 3 correlation rules are represented, correlates,
and reads every incident and its evidence back through detection-engine's
own HTTP API -- exactly what ai-copilot's worker would fetch.

    python tests/export_sprint3_incidents.py   # writes ai-copilot/eval/sprint3_incidents.json
"""

from __future__ import annotations

import http.client
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import run_m2_baseline as baseline

_OUTPUT = Path(__file__).resolve().parents[1] / "ai-copilot" / "eval" / "sprint3_incidents.json"


def _http(method: str, path: str, body: dict | None = None):
    connection = http.client.HTTPConnection("127.0.0.1", baseline._PORT, timeout=10)
    try:
        payload = json.dumps(body).encode() if body is not None else None
        connection.request(method, path, body=payload, headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        data = response.read()
        if response.status >= 300:
            raise RuntimeError(f"{method} {path} -> HTTP {response.status}: {data[:200]!r}")
        return json.loads(data)
    finally:
        connection.close()


def main() -> int:
    tmp_dir = Path(tempfile.mkdtemp(prefix="bantis-sprint3-export-"))
    os.environ["BANTIS_ENV"] = "range-local"
    os.environ["DETECTION_ENGINE_URL"] = baseline._DETECTION_ENGINE_URL

    server = thread = None
    real_run = None
    try:
        server, thread, engine = baseline._start_detection_engine(tmp_dir)
        real_run = baseline._mock_external_tools()

        from logging_config import configure_logging

        configure_logging()
        baseline._run_all_scenarios(tmp_dir)

        # Sprint 3's third rule has no producer yet; post the event a CI
        # pull from an untrusted registry would emit.
        _http("POST", "/events", {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": "INFO",
            "logger": "ci",
            "source": "ci",
            "event_type": "container_image_pull",
            "event_id": "sprint3-untrusted-pull",
            "message": "pulled image during build",
            "details": {"registry": "registry.evil-mirror.example", "image": "registry.evil-mirror.example/python:3.12-slim"},
        })

        from sqlalchemy.orm import Session

        from app.correlation import run_correlation

        with Session(engine) as session:
            run_correlation(session)

        incidents = _http("GET", "/incidents?limit=200")["items"]
        exported = [
            {"incident": incident, "events": _http("GET", f"/incidents/{incident['incident_id']}/events")}
            for incident in sorted(incidents, key=lambda i: i["pattern"])
        ]
    finally:
        if real_run is not None:
            subprocess.run = real_run
        if server is not None:
            server.should_exit = True
            thread.join(timeout=5)
        shutil.rmtree(tmp_dir, ignore_errors=True)

    _OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    _OUTPUT.write_text(json.dumps({"incidents": exported}, indent=2) + "\n")
    for item in exported:
        incident = item["incident"]
        print(f"{incident['pattern']:30} severity={incident['severity']:8} events={len(item['events'])}")
    print(f"wrote {_OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    raise SystemExit(main())