"""Full-batch post-run checks without executing attacks or Git commands."""

import importlib.util
import json
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def baseline(monkeypatch, detection_stack):
    spec = importlib.util.spec_from_file_location(
        "m2_baseline", Path(__file__).with_name("run_m2_baseline.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "_DETECTION_ENGINE_URL", detection_stack.url)
    monkeypatch.setattr(module, "_start_detection_engine", lambda _: (
        SimpleNamespace(should_exit=False), SimpleNamespace(join=lambda **_: None),
        detection_stack.engine,
    ))
    monkeypatch.setattr(module, "_mock_external_tools", lambda: module.subprocess.run)
    return module


@pytest.mark.parametrize("mode", ["covered", "lost", "incomplete", "invalid"])
def test_full_batch_checks_producer_evidence_before_shutdown(baseline, tmp_path, monkeypatch, mode):
    from logging_config import DetectionEngineHandler
    from scenarios.base import Scenario, ScenarioResult, ScenarioStatus

    emitted = []

    def run_scenarios(_):
        results = {}
        for name in baseline._SCENARIO_IDS:
            result = ScenarioResult(
                ScenarioStatus.ERROR if mode == "invalid" else ScenarioStatus.FAILURE,
                "Controlled scenario result",
            )
            scenario = SimpleNamespace(name=name, mitre_technique="T1195.002")
            Scenario.log_result(scenario, result)
            emitted.append(name)
            results[name] = result
        return results

    monkeypatch.setattr(baseline, "_run_all_scenarios", run_scenarios)
    if mode == "lost":
        # Preserve producer evidence while dropping every forwarded event.
        monkeypatch.setattr(DetectionEngineHandler, "emit", lambda *_: None)

    real_hook = baseline._run_gap_detector
    calls = []

    def hook(history, output, deadline):
        assert emitted == baseline._SCENARIO_IDS
        assert history.read_text().endswith("\n")
        calls.append(deadline)
        if mode == "incomplete":
            monkeypatch.setattr(baseline, "_DETECTION_ENGINE_URL", "http://127.0.0.1:0")
        return real_hook(history, output, deadline)

    monkeypatch.setattr(baseline, "_run_gap_detector", hook)
    assert baseline.main(["--output-dir", str(tmp_path)]) == (0 if mode == "covered" else 1)
    assert len(calls) == 1
    evidence = list(tmp_path.glob("bantis-m2-evidence-*"))
    assert len(evidence) == 1
    history = evidence[0] / "attack.log"
    report_path = evidence[0] / "gaps.json"
    records = [json.loads(line) for line in history.read_text().splitlines()]
    events = [item for item in records if item.get("event_type") == "attack_scenario_run"]
    assert len(events) == 4
    assert not any(isinstance(handler, logging.FileHandler) and handler.baseFilename == str(history)
                   for handler in logging.getLogger().handlers)
    if mode == "incomplete":
        assert not report_path.exists()
        return
    report = json.loads(report_path.read_text())
    assert report["complete"] is True
    assert report["source"]["deadline"] == calls[0].isoformat()
    assert report["counts"]["pending"] == 0
    expected_state = {"covered": "detected", "lost": "gap", "invalid": "invalid"}[mode]
    assert report["counts"][expected_state] == 4
    assert {run["event_id"] for run in report["runs"]} == {event["event_id"] for event in events}
    assert (evidence[0] / "gaps.json.review.sqlite3").exists()


def test_interrupted_batch_skips_hook_and_closes_history(baseline, tmp_path, monkeypatch):
    def interrupted(_):
        raise RuntimeError("batch interrupted")

    def unexpected_hook(*_):
        pytest.fail("post-run hook must not run for an interrupted batch")

    monkeypatch.setattr(baseline, "_run_all_scenarios", interrupted)
    monkeypatch.setattr(baseline, "_run_gap_detector", unexpected_hook)
    with pytest.raises(RuntimeError, match="batch interrupted"):
        baseline.main(["--output-dir", str(tmp_path)])
    evidence = next(tmp_path.glob("bantis-m2-evidence-*"))
    assert (evidence / "attack.log").exists()
    assert not (evidence / "gaps.json").exists()
    assert not any(isinstance(handler, logging.FileHandler) and
                   handler.baseFilename == str(evidence / "attack.log")
                   for handler in logging.getLogger().handlers)