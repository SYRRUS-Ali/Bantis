import pytest

import scenarios.compromised_ci_step as ccs
import scenarios.typosquatting as tsq
from fingerprint_utils import fingerprint
from scenarios.base import ScenarioStatus

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

_CI_STEP_EXPECTED_FINGERPRINT = (
    ("artifact", "str"),
    ("path", "str"),
)

_TYPOSQUATTING_EXPECTED_FINGERPRINT = (
    ("artifact", "str"),
    ("impersonates", "str"),
    ("install_target", "str"),
    ("tool_output_tail", "str"),
    ("tool_returncode", "int"),
    ("wheel_path", "str"),
)


@pytest.mark.fingerprint
def test_compromised_ci_step_fingerprint_is_stable(tmp_path, monkeypatch):
    workflow_file = tmp_path / "ci.yml"
    workflow_file.write_text(_SAMPLE_WORKFLOW)
    monkeypatch.setattr(ccs, "_WORKFLOW_FILE", workflow_file)

    scenario = ccs.CompromisedCiStepScenario()
    result = scenario.run()

    assert result.status == ScenarioStatus.SUCCESS
    assert fingerprint(result.details) == _CI_STEP_EXPECTED_FINGERPRINT

    scenario.cleanup()


@pytest.mark.fingerprint
def test_typosquatting_fingerprint_is_stable(tmp_path, monkeypatch):
    real_mkdtemp = tsq.tempfile.mkdtemp

    def fake_mkdtemp(*args, **kwargs):
        kwargs["dir"] = str(tmp_path)
        return real_mkdtemp(*args, **kwargs)

    monkeypatch.setattr(tsq.tempfile, "mkdtemp", fake_mkdtemp)

    scenario = tsq.TyposquattingScenario()
    result = scenario.run()

    assert result.status == ScenarioStatus.SUCCESS
    assert fingerprint(result.details) == _TYPOSQUATTING_EXPECTED_FINGERPRINT

    scenario.cleanup()