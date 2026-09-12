import logging
import subprocess
import tempfile
from types import SimpleNamespace

import pytest

import scenarios.leaked_secret as ls
from scenarios.base import ScenarioStatus


@pytest.fixture(autouse=True)
def scratch_dirs_under_tmp_path(tmp_path, monkeypatch):
    real_mkdtemp = tempfile.mkdtemp

    def fake_mkdtemp(*args, **kwargs):
        kwargs["dir"] = str(tmp_path)
        return real_mkdtemp(*args, **kwargs)

    monkeypatch.setattr(ls.tempfile, "mkdtemp", fake_mkdtemp)


@pytest.fixture
def fake_gitleaks(monkeypatch):
    real_run = subprocess.run
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[0] == "gitleaks":
            return SimpleNamespace(returncode=1, stdout="", stderr="leak:aws-access-token")
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(ls.subprocess, "run", fake_run)
    return calls


def _stub_gitleaks(monkeypatch, returncode: int, stdout: str = "", stderr: str = ""):
    real_run = subprocess.run

    def fake_run(cmd, **kwargs):
        if cmd[0] == "gitleaks":
            return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(ls.subprocess, "run", fake_run)


def test_run_commits_the_fake_secret_into_a_scratch_repo(fake_gitleaks):
    scenario = ls.LeakedSecretScenario()
    scenario.run()

    log = subprocess.run(
        ["git", "log", "-p"], cwd=scenario._workdir, capture_output=True, text=True, check=False,
    )
    assert ls._FAKE_AWS_ACCESS_KEY_ID in log.stdout

    scenario.cleanup()


def test_run_does_not_touch_the_real_repository(fake_gitleaks):
    repo_root_before = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False,
    ).stdout

    scenario = ls.LeakedSecretScenario()
    scenario.run()

    repo_root_after = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False,
    ).stdout
    assert repo_root_before == repo_root_after
    assert str(scenario._workdir).startswith("/tmp") or "bantis-leaked-secret-" in str(scenario._workdir)

    scenario.cleanup()


def test_run_returns_failure_when_gitleaks_catches_the_secret(monkeypatch):
    _stub_gitleaks(monkeypatch, returncode=1, stderr="leak:aws-access-token")

    result = ls.LeakedSecretScenario().run()

    assert result.status == ScenarioStatus.FAILURE
    assert result.details["gitleaks_returncode"] == 1
    assert "aws-access-token" in result.details["gitleaks_output_tail"]


def test_run_returns_success_when_gitleaks_misses_the_secret(monkeypatch):
    _stub_gitleaks(monkeypatch, returncode=0)

    result = ls.LeakedSecretScenario().run()

    assert result.status == ScenarioStatus.SUCCESS


def test_run_returns_error_on_unexpected_gitleaks_exit_code(monkeypatch):
    _stub_gitleaks(monkeypatch, returncode=2, stderr="config error")

    result = ls.LeakedSecretScenario().run()

    assert result.status == ScenarioStatus.ERROR
    assert result.details["gitleaks_returncode"] == 2


def test_run_returns_error_when_gitleaks_is_missing(monkeypatch):
    real_run = subprocess.run

    def fake_run(cmd, **kwargs):
        if cmd[0] == "gitleaks":
            raise FileNotFoundError("gitleaks")
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(ls.subprocess, "run", fake_run)

    result = ls.LeakedSecretScenario().run()

    assert result.status == ScenarioStatus.ERROR
    assert "not available" in result.message


def test_run_returns_error_when_gitleaks_times_out(monkeypatch):
    real_run = subprocess.run

    def fake_run(cmd, **kwargs):
        if cmd[0] == "gitleaks":
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=1)
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(ls.subprocess, "run", fake_run)

    result = ls.LeakedSecretScenario().run()

    assert result.status == ScenarioStatus.ERROR


def test_run_twice_without_cleanup_is_rejected(fake_gitleaks):
    scenario = ls.LeakedSecretScenario()
    scenario.run()
    second = scenario.run()

    assert second.status == ScenarioStatus.ERROR
    assert "run cleanup" in second.message

    scenario.cleanup()


def test_log_result_emits_schema_shaped_event(monkeypatch, caplog: pytest.LogCaptureFixture):
    _stub_gitleaks(monkeypatch, returncode=1, stderr="leak:aws-access-token")

    scenario = ls.LeakedSecretScenario()
    result = scenario.run()

    with caplog.at_level(logging.INFO, logger="attack_sim"):
        scenario.log_result(result)
    scenario.cleanup()

    record = caplog.records[0]
    assert record.source == "attack-sim"
    assert record.event_type == "attack_scenario_run"
    assert record.details["scenario"] == "leaked-secret"
    assert record.details["mitre_technique"] == "T1552.001"
    assert record.details["status"] == "failure"
    assert record.details["gitleaks_returncode"] == 1


def test_cleanup_removes_the_scratch_repo(fake_gitleaks):
    scenario = ls.LeakedSecretScenario()
    scenario.run()
    workdir = scenario._workdir
    assert workdir.is_dir()

    scenario.cleanup()

    assert not workdir.exists()
    assert scenario._workdir is None


def test_cleanup_without_run_does_not_raise():
    ls.LeakedSecretScenario().cleanup()


def test_scenario_run_is_deterministic_across_repeated_runs(monkeypatch):
    _stub_gitleaks(monkeypatch, returncode=1, stderr="leak:aws-access-token")

    outcomes = []
    for _ in range(3):
        scenario = ls.LeakedSecretScenario()
        result = scenario.run()
        outcomes.append((result.status, result.message, result.details["gitleaks_returncode"]))
        scenario.cleanup()

    assert len(set(outcomes)) == 1