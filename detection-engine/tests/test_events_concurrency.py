import subprocess
import sys
from pathlib import Path

_APP_ROOT = Path(__file__).resolve().parents[1]
_CONCURRENT_REQUESTS = 20


def test_concurrent_posts_for_the_same_event_id_never_500(tmp_path):
    db_path = tmp_path / "concurrency_check.db"
    script = f"""
import json
import os
import threading
import time
import urllib.error
import urllib.request
from collections import Counter

os.environ["DATABASE_URL"] = "sqlite:///{db_path}"

import uvicorn
from app.db import Base, engine
from app.main import app as detection_engine_app

Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)

port = 18790
config = uvicorn.Config(detection_engine_app, host="127.0.0.1", port=port, log_level="error")
server = uvicorn.Server(config)
thread = threading.Thread(target=server.run, daemon=True)
thread.start()
for _ in range(50):
    if server.started:
        break
    time.sleep(0.1)
else:
    raise SystemExit("server did not start in time")

event = {{
    "timestamp": "2026-10-03T12:00:00Z",
    "level": "INFO",
    "logger": "attack_sim",
    "source": "attack-sim",
    "event_type": "attack_scenario_run",
    "event_id": "concurrency-race-test-event-id",
    "message": "concurrent ingestion race probe",
    "details": {{}},
}}
body = json.dumps(event).encode()

results = []
lock = threading.Lock()
barrier = threading.Barrier({_CONCURRENT_REQUESTS})

def post():
    request = urllib.request.Request(
        f"http://127.0.0.1:{{port}}/events",
        data=body,
        headers={{"Content-Type": "application/json"}},
        method="POST",
    )
    barrier.wait()
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            status = str(response.status)
    except urllib.error.HTTPError as exc:
        status = f"HTTP {{exc.code}}"
    with lock:
        results.append(status)

threads = [threading.Thread(target=post) for _ in range({_CONCURRENT_REQUESTS})]
for t in threads:
    t.start()
for t in threads:
    t.join()

server.should_exit = True
thread.join(timeout=5)

counts = Counter(results)
print("RESULTS:", dict(counts))
assert not any(s.startswith("HTTP 5") for s in results), f"server errors: {{counts}}"
assert counts["201"] == 1, f"expected exactly one 201, got: {{counts}}"
assert counts["200"] == {_CONCURRENT_REQUESTS} - 1, f"expected the rest as 200, got: {{counts}}"
print("OK")
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=_APP_ROOT,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "OK" in result.stdout