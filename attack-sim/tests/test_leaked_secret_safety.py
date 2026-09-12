import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace

import scenarios.leaked_secret as ls

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _stub_gitleaks(monkeypatch, returncode: int = 1):
    real_run = subprocess.run

    def fake_run(cmd, **kwargs):
        if cmd[0] == "gitleaks":
            return SimpleNamespace(returncode=returncode, stdout="", stderr="leak:aws-access-token")
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(ls.subprocess, "run", fake_run)


def test_fake_secret_constants_are_clearly_marked_and_non_functional():
    assert "FAKE" in ls._FAKE_AWS_ACCESS_KEY_ID
    assert "FAKE" in ls._FAKE_AWS_SECRET_ACCESS_KEY
    assert "DO-NOT-USE" in ls._FAKE_AWS_SECRET_ACCESS_KEY
    assert ls._FAKE_AWS_ACCESS_KEY_ID.startswith("AKIA")
    assert len(ls._FAKE_AWS_ACCESS_KEY_ID) == 20


def test_scratch_repo_never_lives_inside_the_real_project(monkeypatch):
    _stub_gitleaks(monkeypatch)

    scenario = ls.LeakedSecretScenario()
    scenario.run()

    workdir = scenario._workdir.resolve()
    assert Path(tempfile.gettempdir()) in workdir.parents
    assert _REPO_ROOT not in workdir.parents and workdir != _REPO_ROOT

    scenario.cleanup()


def test_cleanup_leaves_no_trace_of_the_secret_on_disk(monkeypatch):
    _stub_gitleaks(monkeypatch)

    scenario = ls.LeakedSecretScenario()
    scenario.run()
    leaked_file = scenario._workdir / ls._LEAKED_FILE_NAME
    assert ls._FAKE_AWS_ACCESS_KEY_ID in leaked_file.read_text()

    scenario.cleanup()

    assert not leaked_file.exists()
    assert scenario._workdir is None