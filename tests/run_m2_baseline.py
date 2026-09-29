from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "detection-engine"))
sys.path.insert(0, str(_REPO_ROOT / "attack-sim"))

_PORT = 18767
_DETECTION_ENGINE_URL = f"http://127.0.0.1:{_PORT}"

_SCENARIO_IDS = ["malicious-dependency", "leaked-secret", "compromised-ci-step", "typosquatting"]

_SAMPLE_WORKFLOW = """\
name: Range CI/CD Pipeline

jobs:
  build:
    name: Build Docker Image
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v7

      - name: Build image
        run: docker build .
"""


def _start_detection_engine(tmp_dir: Path):
    os.environ["DATABASE_URL"] = f"sqlite:///{tmp_dir / 'baseline.db'}"

    import uvicorn

    from app.db import Base, engine
    from app.main import app as detection_engine_app

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    config = uvicorn.Config(detection_engine_app, host="127.0.0.1", port=_PORT, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    for _ in range(50):
        if server.started:
            break
        time.sleep(0.1)
    else:
        raise RuntimeError("detection-engine server did not start in time")

    return server, thread, engine


def _mock_external_tools():
    real_run = subprocess.run

    def dispatched_fake_run(cmd, **kwargs):
        if cmd[0] == "docker":
            return SimpleNamespace(returncode=1, stdout="", stderr="no matching distribution")
        if cmd[0] == "gitleaks":
            return SimpleNamespace(returncode=1, stdout="", stderr="leak:aws-access-token")
        return real_run(cmd, **kwargs)

    subprocess.run = dispatched_fake_run
    return real_run


def _run_all_scenarios(tmp_dir: Path) -> dict:
    import scenarios.compromised_ci_step as ccs
    import scenarios.leaked_secret as ls
    import scenarios.malicious_dependency as md
    import scenarios.typosquatting
    from scenarios.replay import replay

    requirements_file = tmp_dir / "requirements.txt"
    requirements_file.write_text("fastapi==0.120.0\n")
    md._REQUIREMENTS_FILE = requirements_file

    workflow_file = tmp_dir / "ci.yml"
    workflow_file.write_text(_SAMPLE_WORKFLOW)
    ccs._WORKFLOW_FILE = workflow_file

    real_mkdtemp = ls.tempfile.mkdtemp
    ls.tempfile.mkdtemp = lambda *a, **k: real_mkdtemp(*a, dir=str(tmp_dir), **k)

    results = {}
    for scenario_id in _SCENARIO_IDS:
        result = replay(scenario_id)
        results[scenario_id] = result
        print(f"  {scenario_id:<24} -> {result.status.value:<8} {result.message}")

    return results


def main() -> int:
    tmp_dir = Path(tempfile.mkdtemp(prefix="bantis-m2-baseline-"))

    os.environ["BANTIS_ENV"] = "range-local"
    os.environ["DETECTION_ENGINE_URL"] = _DETECTION_ENGINE_URL

    server = thread = None
    real_subprocess_run = None
    try:
        print("Starting a live detection-engine...")
        server, thread, engine = _start_detection_engine(tmp_dir)

        real_subprocess_run = _mock_external_tools()

        from logging_config import configure_logging

        configure_logging()

        print(f"\nRunning {len(_SCENARIO_IDS)} M2 scenarios in sequence:")
        _run_all_scenarios(tmp_dir)

    finally:
        if real_subprocess_run is not None:
            subprocess.run = real_subprocess_run
        if server is not None:
            server.should_exit = True
            thread.join(timeout=5)
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())