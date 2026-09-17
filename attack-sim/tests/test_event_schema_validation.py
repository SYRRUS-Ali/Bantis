import logging
import uuid
from types import SimpleNamespace

import pytest

import scenarios.compromised_ci_step as ccs
import scenarios.leaked_secret as ls
import scenarios.malicious_dependency as md
import scenarios.noop
import scenarios.typosquatting as tsq
from scenarios.replay import available, replay

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


def _setup_malicious_dependency(tmp_path, monkeypatch):
    requirements_file = tmp_path / "requirements.txt"
    requirements_file.write_text("fastapi==0.120.0\n")
    monkeypatch.setattr(md, "_REQUIREMENTS_FILE", requirements_file)
    monkeypatch.setattr(
        md.subprocess, "run",
        lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="no matching distribution"),
    )


def _setup_leaked_secret(tmp_path, monkeypatch):
    real_run = ls.subprocess.run

    def fake_run(cmd, **kwargs):
        if cmd[0] == "gitleaks":
            return SimpleNamespace(returncode=1, stdout="", stderr="leak:aws-access-token")
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(ls.subprocess, "run", fake_run)


def _setup_compromised_ci_step(tmp_path, monkeypatch):
    workflow_file = tmp_path / "ci.yml"
    workflow_file.write_text(_SAMPLE_WORKFLOW)
    monkeypatch.setattr(ccs, "_WORKFLOW_FILE", workflow_file)


def _setup_typosquatting(tmp_path, monkeypatch):
    real_mkdtemp = tsq.tempfile.mkdtemp

    def fake_mkdtemp(*args, **kwargs):
        kwargs["dir"] = str(tmp_path)
        return real_mkdtemp(*args, **kwargs)

    monkeypatch.setattr(tsq.tempfile, "mkdtemp", fake_mkdtemp)


def _setup_noop(tmp_path, monkeypatch):
    pass


_SETUP_BY_SCENARIO_ID = {
    "malicious-dependency": _setup_malicious_dependency,
    "leaked-secret": _setup_leaked_secret,
    "compromised-ci-step": _setup_compromised_ci_step,
    "typosquatting": _setup_typosquatting,
    "noop": _setup_noop,
}


def _assert_matches_schema(scenario_id, scenario_cls, record):
    assert record.source == "attack-sim"
    assert record.event_type == "attack_scenario_run"
    uuid.UUID(record.event_id)

    details = record.details
    assert details["scenario"] == scenario_cls.name == scenario_id
    assert details["mitre_technique"] == scenario_cls.mitre_technique
    assert details["status"] in {"success", "failure", "error"}

    has_returncode = "tool_returncode" in details
    has_output_tail = "tool_output_tail" in details
    assert has_returncode == has_output_tail, (
        f"{scenario_id}: tool_returncode and tool_output_tail must appear together, per docs/event-schema.md"
    )
    if has_returncode:
        assert isinstance(details["tool_returncode"], int)
        assert isinstance(details["tool_output_tail"], str)

    if scenario_cls.mitre_technique != "N/A":
        assert "artifact" in details, f"{scenario_id}: real attack scenarios must report an artifact"
        assert isinstance(details["artifact"], str) and details["artifact"]


def test_every_registered_scenario_emits_a_schema_compliant_event(
    tmp_path, monkeypatch, caplog: pytest.LogCaptureFixture
):
    registered = available()
    assert set(registered) >= {
        "malicious-dependency", "leaked-secret", "compromised-ci-step",
        "typosquatting", "noop",
    }

    for scenario_id, scenario_cls in registered.items():
        _SETUP_BY_SCENARIO_ID[scenario_id](tmp_path, monkeypatch)

        with caplog.at_level(logging.INFO, logger="attack_sim"):
            replay(scenario_id)

        _assert_matches_schema(scenario_id, scenario_cls, caplog.records[-1])