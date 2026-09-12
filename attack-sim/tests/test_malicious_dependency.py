import logging
import subprocess
from types import SimpleNamespace

import pytest

import scenarios.malicious_dependency as md
from scenarios.base import ScenarioStatus


@pytest.fixture
def requirements_file(tmp_path, monkeypatch):
    path = tmp_path / "requirements.txt"
    path.write_text("fastapi==0.120.0\n")
    monkeypatch.setattr(md, "_REQUIREMENTS_FILE", path)
    return path


def _stub_build(returncode: int, stdout: str = "", stderr: str = ""):
    def _run(*args, **kwargs):
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

    return _run


def test_run_injects_line_before_building(requirements_file, monkeypatch):
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["content_during_build"] = requirements_file.read_text()
        return SimpleNamespace(returncode=1, stdout="", stderr="no matching distribution")

    monkeypatch.setattr(md.subprocess, "run", fake_run)

    md.MaliciousDependencyScenario().run()

    assert md._INJECTED_LINE in seen["content_during_build"]


def test_run_appends_a_new_line_even_without_a_trailing_newline(requirements_file, monkeypatch):
    requirements_file.write_text("fastapi==0.120.0")  # no trailing newline
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["content_during_build"] = requirements_file.read_text()
        return SimpleNamespace(returncode=1, stdout="", stderr="no matching distribution")

    monkeypatch.setattr(md.subprocess, "run", fake_run)

    md.MaliciousDependencyScenario().run()

    lines = seen["content_during_build"].splitlines()
    assert lines[0] == "fastapi==0.120.0"
    assert lines[1] == md._INJECTED_LINE.rstrip("\n")


def test_run_returns_failure_when_build_rejects_package(requirements_file, monkeypatch):
    monkeypatch.setattr(md.subprocess, "run", _stub_build(returncode=1, stderr="no matching distribution"))

    result = md.MaliciousDependencyScenario().run()

    assert result.status == ScenarioStatus.FAILURE
    assert result.details["build_returncode"] == 1
    assert "no matching distribution" in result.details["build_output_tail"]


def test_run_returns_success_when_build_unexpectedly_passes(requirements_file, monkeypatch):
    monkeypatch.setattr(md.subprocess, "run", _stub_build(returncode=0))

    result = md.MaliciousDependencyScenario().run()

    assert result.status == ScenarioStatus.SUCCESS


def test_run_returns_error_when_docker_is_missing(requirements_file, monkeypatch):
    def fake_run(*args, **kwargs):
        raise FileNotFoundError("docker")

    monkeypatch.setattr(md.subprocess, "run", fake_run)

    result = md.MaliciousDependencyScenario().run()

    assert result.status == ScenarioStatus.ERROR


def test_run_returns_error_when_build_times_out(requirements_file, monkeypatch):
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="docker compose build api", timeout=1)

    monkeypatch.setattr(md.subprocess, "run", fake_run)

    result = md.MaliciousDependencyScenario().run()

    assert result.status == ScenarioStatus.ERROR


def test_run_twice_without_cleanup_is_rejected(requirements_file, monkeypatch):
    monkeypatch.setattr(md.subprocess, "run", _stub_build(returncode=1))

    scenario = md.MaliciousDependencyScenario()
    scenario.run()
    second = scenario.run()

    assert second.status == ScenarioStatus.ERROR
    assert "already contains" in second.message


def test_log_result_emits_schema_shaped_event(requirements_file, monkeypatch, caplog: pytest.LogCaptureFixture):
    monkeypatch.setattr(md.subprocess, "run", _stub_build(returncode=1, stderr="no matching distribution"))

    scenario = md.MaliciousDependencyScenario()
    result = scenario.run()

    with caplog.at_level(logging.INFO, logger="attack_sim"):
        scenario.log_result(result)
    scenario.cleanup()

    record = caplog.records[0]
    assert record.source == "attack-sim"
    assert record.event_type == "attack_scenario_run"
    assert record.details["scenario"] == "malicious-dependency"
    assert record.details["mitre_technique"] == "T1195.001"
    assert record.details["status"] == "failure"
    assert record.details["build_returncode"] == 1


def test_cleanup_restores_original_content(requirements_file, monkeypatch):
    original = requirements_file.read_text()
    monkeypatch.setattr(md.subprocess, "run", _stub_build(returncode=1))

    scenario = md.MaliciousDependencyScenario()
    scenario.run()
    assert requirements_file.read_text() != original

    scenario.cleanup()

    assert requirements_file.read_text() == original


def test_cleanup_rebuilds_after_a_successful_run(requirements_file, monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(md.subprocess, "run", fake_run)

    scenario = md.MaliciousDependencyScenario()
    scenario.run()
    assert len(calls) == 1

    scenario.cleanup()

    assert len(calls) == 2
    assert calls[1] == ["docker", "compose", "build", "api"]
    assert requirements_file.read_text() == "fastapi==0.120.0\n"


def test_cleanup_does_not_rebuild_after_a_failed_run(requirements_file, monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=1, stdout="", stderr="no matching distribution")

    monkeypatch.setattr(md.subprocess, "run", fake_run)

    scenario = md.MaliciousDependencyScenario()
    scenario.run()
    scenario.cleanup()

    assert len(calls) == 1


def test_cleanup_rebuild_failure_does_not_raise(requirements_file, monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if len(calls) == 1:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=1)

    monkeypatch.setattr(md.subprocess, "run", fake_run)

    scenario = md.MaliciousDependencyScenario()
    scenario.run()
    scenario.cleanup()

    assert requirements_file.read_text() == "fastapi==0.120.0\n"


def test_cleanup_without_run_does_not_touch_a_clean_file(requirements_file):
    original = requirements_file.read_text()

    md.MaliciousDependencyScenario().cleanup()

    assert requirements_file.read_text() == original


def test_cleanup_recovers_a_dirty_file_left_by_a_previous_uncleaned_run(requirements_file):
    dirty = requirements_file.read_text() + md._INJECTED_LINE
    requirements_file.write_text(dirty)

    md.MaliciousDependencyScenario().cleanup()

    assert md._INJECTED_LINE not in requirements_file.read_text()


def test_scenario_run_is_deterministic_across_repeated_runs(requirements_file, monkeypatch):
    monkeypatch.setattr(md.subprocess, "run", _stub_build(returncode=1, stderr="no matching distribution"))

    outcomes = []
    for _ in range(3):
        scenario = md.MaliciousDependencyScenario()
        result = scenario.run()
        outcomes.append((result.status, result.message, result.details["build_returncode"]))
        scenario.cleanup()

    assert len(set(outcomes)) == 1