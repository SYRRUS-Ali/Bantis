import logging

import pytest

import scenarios.compromised_ci_step as ccs
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

      - name: Build image
        run: docker build .
"""


@pytest.fixture
def workflow_file(tmp_path, monkeypatch):
    path = tmp_path / "ci.yml"
    path.write_text(_SAMPLE_WORKFLOW)
    monkeypatch.setattr(ccs, "_WORKFLOW_FILE", path)
    return path


def test_run_injects_step_as_the_first_step_of_the_first_job(workflow_file):
    result = ccs.CompromisedCiStepScenario().run()

    content = workflow_file.read_text()
    assert result.status == ScenarioStatus.SUCCESS
    assert ccs._STEP_MARKER in content

    steps_index = content.index("steps:")
    injected_index = content.index(ccs._STEP_MARKER)
    checkout_index = content.index("Checkout code")
    assert steps_index < injected_index < checkout_index

    ccs.CompromisedCiStepScenario().cleanup()


def test_run_returns_error_when_workflow_file_is_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(ccs, "_WORKFLOW_FILE", tmp_path / "nope.yml")

    result = ccs.CompromisedCiStepScenario().run()

    assert result.status == ScenarioStatus.ERROR


def test_run_returns_error_when_no_steps_block_exists(tmp_path, monkeypatch):
    path = tmp_path / "ci.yml"
    path.write_text("name: a workflow with no jobs\n")
    monkeypatch.setattr(ccs, "_WORKFLOW_FILE", path)

    result = ccs.CompromisedCiStepScenario().run()

    assert result.status == ScenarioStatus.ERROR
    assert "steps:" in result.message


def test_run_twice_without_cleanup_is_rejected(workflow_file):
    scenario = ccs.CompromisedCiStepScenario()
    scenario.run()
    second = scenario.run()

    assert second.status == ScenarioStatus.ERROR
    assert "already contains" in second.message

    scenario.cleanup()


def test_log_result_emits_schema_shaped_event(workflow_file, caplog: pytest.LogCaptureFixture):
    scenario = ccs.CompromisedCiStepScenario()
    result = scenario.run()

    with caplog.at_level(logging.INFO, logger="attack_sim"):
        scenario.log_result(result)
    scenario.cleanup()

    record = caplog.records[0]
    assert record.source == "attack-sim"
    assert record.event_type == "attack_scenario_run"
    assert record.details["scenario"] == "compromised-ci-step"
    assert record.details["mitre_technique"] == "T1195.002"
    assert record.details["status"] == "success"