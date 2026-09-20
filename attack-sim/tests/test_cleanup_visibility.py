import logging
import shutil
import tempfile
from types import SimpleNamespace

import pytest

import cli
import scenarios.leaked_secret as ls
import scenarios.malicious_dependency as md
import scenarios.typosquatting as tsq


@pytest.fixture(autouse=True)
def scratch_dirs_under_tmp_path(tmp_path, monkeypatch):
    real_mkdtemp = tempfile.mkdtemp

    def fake_mkdtemp(*args, **kwargs):
        kwargs["dir"] = str(tmp_path)
        return real_mkdtemp(*args, **kwargs)

    monkeypatch.setattr(ls.tempfile, "mkdtemp", fake_mkdtemp)


def _stub_gitleaks_catches_it(monkeypatch):
    real_run = ls.subprocess.run

    def fake_run(cmd, **kwargs):
        if cmd[0] == "gitleaks":
            return SimpleNamespace(returncode=1, stdout="", stderr="leak:aws-access-token")
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(ls.subprocess, "run", fake_run)


def test_leaked_secret_cleanup_surfaces_a_failed_removal(monkeypatch, caplog: pytest.LogCaptureFixture):
    _stub_gitleaks_catches_it(monkeypatch)
    monkeypatch.setattr(ls.shutil, "rmtree", lambda path: (_ for _ in ()).throw(OSError("device busy")))

    scenario = ls.LeakedSecretScenario()
    scenario.run()

    with caplog.at_level(logging.WARNING, logger="attack_sim"), pytest.raises(OSError, match="device busy"):
        scenario.cleanup()

    assert "still contains the fake secret" in caplog.records[0].message
    assert scenario._workdir is None


def test_leaked_secret_cleanup_still_succeeds_normally(monkeypatch):
    _stub_gitleaks_catches_it(monkeypatch)

    scenario = ls.LeakedSecretScenario()
    scenario.run()
    scenario.cleanup()


def test_typosquatting_cleanup_surfaces_a_failed_removal(tmp_path, monkeypatch, caplog: pytest.LogCaptureFixture):
    real_mkdtemp = tsq.tempfile.mkdtemp
    monkeypatch.setattr(tsq.tempfile, "mkdtemp", lambda *a, **k: real_mkdtemp(*a, dir=str(tmp_path), **k))
    monkeypatch.setattr(tsq.shutil, "rmtree", lambda path: (_ for _ in ()).throw(OSError("permission denied")))

    scenario = tsq.TyposquattingScenario()
    scenario.run()

    with caplog.at_level(logging.WARNING, logger="attack_sim"), pytest.raises(OSError, match="permission denied"):
        scenario.cleanup()

    assert "still contains the typosquatted package" in caplog.records[0].message


def test_cli_cleanup_reports_a_failed_removal_cleanly_instead_of_a_traceback(monkeypatch, capsys):
    monkeypatch.setattr(ls.shutil, "rmtree", lambda path: (_ for _ in ()).throw(OSError("device busy")))
    _stub_gitleaks_catches_it(monkeypatch)

    scenario = ls.LeakedSecretScenario()
    scenario.run()
    monkeypatch.setattr(
        cli, "available",
        lambda: {"leaked-secret": lambda: scenario},
    )

    exit_code = cli.main(["cleanup", "leaked-secret"])

    assert exit_code == 1
    assert "device busy" in capsys.readouterr().err

    monkeypatch.setattr(ls.shutil, "rmtree", shutil.rmtree)
    scenario.cleanup()


def test_malicious_dependency_rebuild_failure_is_logged_not_silent(
    tmp_path, monkeypatch, caplog: pytest.LogCaptureFixture
):
    requirements_file = tmp_path / "requirements.txt"
    requirements_file.write_text("fastapi==0.120.0\n")
    monkeypatch.setattr(md, "_REQUIREMENTS_FILE", requirements_file)

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if len(calls) == 1:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="daemon not reachable")

    monkeypatch.setattr(md.subprocess, "run", fake_run)

    scenario = md.MaliciousDependencyScenario()
    scenario.run()

    with caplog.at_level(logging.WARNING, logger="attack_sim"):
        scenario.cleanup()

    assert len(calls) == 2
    assert "may still be poisoned" in caplog.records[0].message
    assert requirements_file.read_text() == "fastapi==0.120.0\n"


def test_malicious_dependency_rebuild_success_logs_nothing(tmp_path, monkeypatch, caplog: pytest.LogCaptureFixture):
    requirements_file = tmp_path / "requirements.txt"
    requirements_file.write_text("fastapi==0.120.0\n")
    monkeypatch.setattr(md, "_REQUIREMENTS_FILE", requirements_file)
    monkeypatch.setattr(
        md.subprocess, "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )

    scenario = md.MaliciousDependencyScenario()
    scenario.run()

    with caplog.at_level(logging.WARNING, logger="attack_sim"):
        scenario.cleanup()

    assert caplog.records == []