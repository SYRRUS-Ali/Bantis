import logging
import subprocess
import tempfile

import pytest

import scenarios.typosquatting as ts
from scenarios.base import ScenarioStatus


@pytest.fixture(autouse=True)
def scratch_dirs_under_tmp_path(tmp_path, monkeypatch):
    real_mkdtemp = tempfile.mkdtemp

    def fake_mkdtemp(*args, **kwargs):
        kwargs["dir"] = str(tmp_path)
        return real_mkdtemp(*args, **kwargs)

    monkeypatch.setattr(ts.tempfile, "mkdtemp", fake_mkdtemp)


def test_run_installs_the_fake_package_into_an_isolated_target():
    scenario = ts.TyposquattingScenario()
    result = scenario.run()

    assert result.status == ScenarioStatus.SUCCESS
    assert result.details["tool_returncode"] == 0
    assert result.details["artifact"] == "redsi==0.0.1"

    scenario.cleanup()


def test_run_twice_without_cleanup_is_rejected():
    scenario = ts.TyposquattingScenario()
    scenario.run()
    second = scenario.run()

    assert second.status == ScenarioStatus.ERROR
    assert "run cleanup" in second.message

    scenario.cleanup()


def test_run_returns_error_when_install_times_out(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=1)

    monkeypatch.setattr(ts.subprocess, "run", fake_run)

    scenario = ts.TyposquattingScenario()
    result = scenario.run()

    assert result.status == ScenarioStatus.ERROR
    scenario.cleanup()


def test_log_result_emits_schema_shaped_event(caplog: pytest.LogCaptureFixture):
    scenario = ts.TyposquattingScenario()
    result = scenario.run()

    with caplog.at_level(logging.INFO, logger="attack_sim"):
        scenario.log_result(result)
    scenario.cleanup()

    record = caplog.records[0]
    assert record.source == "attack-sim"
    assert record.event_type == "attack_scenario_run"
    assert record.details["scenario"] == "typosquatting"
    assert record.details["mitre_technique"] == "T1195.001"
    assert record.details["status"] == "success"
    assert record.details["impersonates"] == "redis"


def test_scenario_run_is_deterministic_across_repeated_runs():
    outcomes = []
    for _ in range(3):
        scenario = ts.TyposquattingScenario()
        result = scenario.run()
        outcomes.append((result.status, result.details["tool_returncode"]))
        scenario.cleanup()

    assert len(set(outcomes)) == 1