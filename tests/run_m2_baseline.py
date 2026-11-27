from __future__ import annotations

import argparse
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "detection-engine"))
sys.path.insert(0, str(_REPO_ROOT / "attack-sim"))
sys.path.insert(0, str(_REPO_ROOT / "gap-detector"))

_PORT = 18767
_DETECTION_ENGINE_URL = f"http://127.0.0.1:{_PORT}"

_SCENARIO_IDS = ["malicious-dependency", "leaked-secret", "compromised-ci-step", "typosquatting"]
_EXPECTED_PATTERNS = ["composite-dependency-secret", "same-source-burst"]

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
    # The baseline runs one batch correlation after all four scenarios, so the
    # numbers are comparable run to run; the live scheduler would race it.
    os.environ["CORRELATION_INTERVAL_SECONDS"] = "0"

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


def _run_gap_detector(history: Path, output: Path, deadline: datetime) -> int:
    """Check producer evidence after batch correlation, before API shutdown."""
    from gap_detector.cli import main as gap_detector_main

    return gap_detector_main([
        "--history", str(history), "--output", str(output),
        "--detection-url", _DETECTION_ENGINE_URL,
        "--deadline", deadline.isoformat(),
    ])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the full M2 baseline and post-run gap check.")
    parser.add_argument("--output-dir", type=Path, help="Parent directory for retained per-run evidence")
    args = parser.parse_args(argv)
    if args.output_dir is not None:
        args.output_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir = Path(tempfile.mkdtemp(prefix="bantis-m2-evidence-", dir=args.output_dir))
    history = evidence_dir / "attack.log"
    gap_report = evidence_dir / "gaps.json"
    print(f"M2 evidence directory: {evidence_dir}")
    tmp_dir = Path(tempfile.mkdtemp(prefix="bantis-m2-baseline-"))
    failures: list[str] = []

    os.environ["BANTIS_ENV"] = "range-local"
    os.environ["DETECTION_ENGINE_URL"] = _DETECTION_ENGINE_URL

    server = thread = engine = None
    real_subprocess_run = None
    history_handler = None
    try:
        print("Starting a live detection-engine...")
        server, thread, engine = _start_detection_engine(tmp_dir)

        real_subprocess_run = _mock_external_tools()

        from logging_config import JSONFormatter, configure_logging

        configure_logging()
        history_handler = logging.FileHandler(history, encoding="utf-8")
        history_handler.setFormatter(JSONFormatter())
        logging.getLogger().addHandler(history_handler)

        print(f"\nRunning {len(_SCENARIO_IDS)} M2 scenarios in sequence:")
        results = _run_all_scenarios(tmp_dir)
        for scenario_id, result in results.items():
            if result.status.value == "error":
                failures.append(f"scenario execution error: {scenario_id}")

        from sqlalchemy.orm import Session

        from app.correlation import run_correlation
        from app.event_models import EventORM
        from app.scorecard import generate_scorecard

        with Session(engine) as session:
            stored_events = session.query(EventORM).filter_by(source="attack-sim").all()
            print(f"\n{len(stored_events)}/{len(_SCENARIO_IDS)} scenario events reached the detection-engine")

            reported_scenarios = {e.details.get("scenario") for e in stored_events}
            missing = set(_SCENARIO_IDS) - reported_scenarios
            if missing:
                failures.append(f"no event reached the detection-engine for: {sorted(missing)}")

            incidents = run_correlation(session)

            print(f"\n{len(incidents)} incident(s) formed:")
            for incident in incidents:
                print(f"  - {incident.pattern} (severity={incident.severity}, confidence={incident.confidence})")
                print(f"    {incident.summary}")

            scorecard = generate_scorecard(stored_events, incidents, expected_patterns=_EXPECTED_PATTERNS)
            print("\n" + scorecard.report())

            if scorecard.detection_rate < 1.0:
                failures.append(
                    f"detection rate {scorecard.detection_rate * 100:.1f}% "
                    f"({scorecard.detected_count}/{scorecard.expected_count})"
                )
            if scorecard.false_positive_count > 0:
                failures.append(
                    f"{scorecard.false_positive_count} unexpected incident(s): {scorecard.unexpected_patterns}"
                )

        # The fixed deadline closes this batch after its committed correlation
        # pass. Keep producer evidence even when forwarding failed.
        deadline = datetime.now(timezone.utc)
        history_handler.flush()
        print("\nRunning post-run gap detector...")
        gap_status = _run_gap_detector(history, gap_report, deadline)
        if gap_status == 1:
            failures.append(f"post-run gap detector found gaps or late detections; see {gap_report}")
        elif gap_status != 0:
            failures.append(f"post-run gap detector check incomplete (exit {gap_status}); see {history}")

    finally:
        if history_handler is not None:
            logging.getLogger().removeHandler(history_handler)
            history_handler.close()
        if real_subprocess_run is not None:
            subprocess.run = real_subprocess_run
        if server is not None:
            server.should_exit = True
            thread.join(timeout=5)
        shutil.rmtree(tmp_dir, ignore_errors=True)

    print("\n" + "=" * 72)
    if failures:
        print(f"M2 BASELINE FAILED ({len(failures)} issue(s)):")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(
        "M2 BASELINE PASSED: all four scenarios reached the detection-engine "
        "and both existing correlation rules fired as documented; post-run gap check passed."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())