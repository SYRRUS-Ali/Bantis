"""Real producer formatting, HTTP ingestion, scheduling, and gap-detector CLI."""

import importlib.util
import json
import logging
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from gap_detector.client import IncidentClient

ROOT = Path(__file__).resolve().parents[2]


def test_saved_producer_log_compared_with_real_scheduled_incidents(tmp_path):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    env = {**os.environ, "DATABASE_URL": f"sqlite:///{tmp_path / 'detection.db'}",
           "CORRELATION_INTERVAL_SECONDS": "0.02"}
    with (tmp_path / "server.log").open("w") as server_log:
        server = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port)],
            cwd=ROOT / "detection-engine", env=env, stdout=server_log, stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 10
            while True:
                try:
                    with urlopen(url + "/health", timeout=0.2) as response:
                        assert response.status == 200
                    break
                except (URLError, TimeoutError):
                    if server.poll() is not None or time.monotonic() > deadline:
                        raise AssertionError("temporary Detection Engine failed to start")
                    time.sleep(0.05)

            spec = importlib.util.spec_from_file_location("attack_logging", ROOT / "attack-sim/logging_config.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            formatter = module.JSONFormatter()
            now = datetime.now(timezone.utc)
            lines = []
            for event_id, scenario, status, age in [
                ("dependency", "malicious-dependency", "failure", 0),
                ("secret", "leaked-secret", "failure", 0),
                ("isolated", "typosquatting", "success", 400),
                ("lost", "compromised-ci-step", "success", 400),
                ("invalid", "compromised-ci-step", "error", 400),
            ]:
                record = logging.LogRecord("attack_sim", logging.INFO, "", 0, "exercise result", (), None)
                record.created = (now - timedelta(seconds=age)).timestamp()
                record.event_id = event_id
                record.source = "attack-sim"
                record.event_type = "attack_scenario_run"
                record.details = {"scenario": scenario, "status": status}
                line = formatter.format(record)
                lines.append(line)
                if event_id != "lost":  # producer evidence exists despite a forwarding loss
                    request = Request(url + "/events", data=line.encode(), headers={"Content-Type": "application/json"})
                    with urlopen(request, timeout=2) as response:
                        assert response.status == 201
            history = tmp_path / "attack.log"
            history.write_text("\n".join(lines) + "\nsuccess: scenario finished\n")
            client = IncidentClient(url, page_size=1)
            deadline = time.monotonic() + 5
            while not client.incidents():
                assert time.monotonic() < deadline, "scheduler did not form the composite incident"
                time.sleep(0.02)
            output = tmp_path / "gaps.json"
            command = [sys.executable, "-m", "gap_detector", "--history", str(history),
                       "--detection-url", url, "--output", str(output)]
            result = subprocess.run(command, cwd=ROOT / "gap-detector", capture_output=True, text=True, timeout=10)
            assert result.returncode == 1, result.stderr
            report = json.loads(output.read_text())
            assert report["counts"] == {"detected": 2, "gap": 2, "late_detection": 0, "pending": 0, "invalid": 1}
            runs = {item["event_id"]: item for item in report["runs"]}
            assert runs["dependency"]["incident_ids"] == runs["secret"]["incident_ids"]
            assert runs["lost"]["state"] == runs["isolated"]["state"] == "gap"
            previous = output.read_bytes()
            server.terminate()
            server.wait(timeout=5)
            result = subprocess.run(command, cwd=ROOT / "gap-detector", capture_output=True, text=True, timeout=10)
            assert result.returncode == 2
            assert output.read_bytes() == previous
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)