from types import SimpleNamespace

import scenarios.compromised_ci_step as ccs
import scenarios.leaked_secret as ls
import scenarios.malicious_dependency as md
import scenarios.typosquatting as tsq
from scenarios.replay import replay

_SAMPLE_WORKFLOW = """\
name: Range CI/CD Pipeline

jobs:
  build:
    name: Build Docker Image
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v7
"""


def _replay_three_times(scenario_id: str) -> list[tuple]:
    outcomes = []
    for _ in range(3):
        result = replay(scenario_id)
        outcomes.append((result.status, result.message))
    return outcomes


def test_malicious_dependency_replay_is_deterministic(tmp_path, monkeypatch):
    requirements_file = tmp_path / "requirements.txt"
    requirements_file.write_text("fastapi==0.120.0\n")
    monkeypatch.setattr(md, "_REQUIREMENTS_FILE", requirements_file)
    monkeypatch.setattr(
        md.subprocess, "run",
        lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="no matching distribution"),
    )

    outcomes = _replay_three_times("malicious-dependency")

    assert len(set(outcomes)) == 1
    assert requirements_file.read_text() == "fastapi==0.120.0\n"


def test_leaked_secret_replay_is_deterministic(monkeypatch):
    real_run = ls.subprocess.run

    def fake_run(cmd, **kwargs):
        if cmd[0] == "gitleaks":
            return SimpleNamespace(returncode=1, stdout="", stderr="leak:aws-access-token")
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(ls.subprocess, "run", fake_run)

    outcomes = _replay_three_times("leaked-secret")

    assert len(set(outcomes)) == 1


def test_compromised_ci_step_replay_is_deterministic(tmp_path, monkeypatch):
    workflow_file = tmp_path / "ci.yml"
    workflow_file.write_text(_SAMPLE_WORKFLOW)
    monkeypatch.setattr(ccs, "_WORKFLOW_FILE", workflow_file)

    outcomes = _replay_three_times("compromised-ci-step")

    assert len(set(outcomes)) == 1
    assert workflow_file.read_text() == _SAMPLE_WORKFLOW


def test_typosquatting_replay_is_deterministic(tmp_path, monkeypatch):
    real_mkdtemp = tsq.tempfile.mkdtemp

    def fake_mkdtemp(*args, **kwargs):
        kwargs["dir"] = str(tmp_path)
        return real_mkdtemp(*args, **kwargs)

    monkeypatch.setattr(tsq.tempfile, "mkdtemp", fake_mkdtemp)

    outcomes = _replay_three_times("typosquatting")

    assert len(set(outcomes)) == 1