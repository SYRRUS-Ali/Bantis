import subprocess
from types import SimpleNamespace

import pytest

import scenarios.malicious_dependency as md
from scenarios.base import ScenarioStatus


@pytest.fixture
def requirements_file(tmp_path, monkeypatch):
    """Points the scenario at a throwaway file instead of the real
    range/api/requirements.txt, so these tests never touch the repo."""
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
    """Regression test: range/api/requirements.txt doesn't end with a
    trailing newline, and the first version of this scenario appended
    directly onto the last line instead of starting a new one, producing
    an invalid requirement string. Caught by running the real scenario
    against the real file three times — see the malicious-dependency
    scenario commit history."""
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
