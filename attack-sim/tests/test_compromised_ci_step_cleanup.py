import pytest

import scenarios.compromised_ci_step as ccs

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


def test_cleanup_restores_the_workflow_byte_for_byte(workflow_file):
    original = workflow_file.read_text()
    scenario = ccs.CompromisedCiStepScenario()
    scenario.run()
    assert workflow_file.read_text() != original

    scenario.cleanup()

    assert workflow_file.read_text() == original


def test_cleanup_without_run_does_not_touch_a_clean_file(workflow_file):
    original = workflow_file.read_text()

    ccs.CompromisedCiStepScenario().cleanup()

    assert workflow_file.read_text() == original


def test_scenario_run_is_deterministic_across_repeated_runs(workflow_file):
    outcomes = []
    for _ in range(3):
        scenario = ccs.CompromisedCiStepScenario()
        result = scenario.run()
        outcomes.append((result.status, result.message))
        scenario.cleanup()

    assert len(set(outcomes)) == 1
    assert workflow_file.read_text() == _SAMPLE_WORKFLOW