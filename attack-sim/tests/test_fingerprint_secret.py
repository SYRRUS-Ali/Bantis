import subprocess
from types import SimpleNamespace

import pytest

import scenarios.leaked_secret as ls
from fingerprint_utils import fingerprint
from scenarios.base import ScenarioStatus

_EXPECTED_FINGERPRINT = (
    ("artifact", "str"),
    ("tool_output_tail", "str"),
    ("tool_returncode", "int"),
)


@pytest.mark.fingerprint
def test_leaked_secret_fingerprint_is_stable(monkeypatch):
    real_run = subprocess.run

    def fake_run(cmd, **kwargs):
        if cmd[0] == "gitleaks":
            return SimpleNamespace(returncode=1, stdout="", stderr="leak:aws-access-token")
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(ls.subprocess, "run", fake_run)

    scenario = ls.LeakedSecretScenario()
    result = scenario.run()

    assert result.status == ScenarioStatus.FAILURE
    assert fingerprint(result.details) == _EXPECTED_FINGERPRINT

    scenario.cleanup()