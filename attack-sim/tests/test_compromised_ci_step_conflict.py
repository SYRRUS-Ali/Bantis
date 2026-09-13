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


def test_run_rejects_a_second_injection_instead_of_stacking_a_duplicate(workflow_file):
    first = ccs.CompromisedCiStepScenario()
    first.run()

    second = ccs.CompromisedCiStepScenario()
    result = second.run()

    assert result.status == ScenarioStatus.ERROR
    assert workflow_file.read_text().count(ccs._STEP_MARKER) == 1

    first.cleanup()


def test_cleanup_recovers_a_workflow_left_dirty_by_an_uncleaned_prior_run(workflow_file):
    orphaned = ccs.CompromisedCiStepScenario()
    orphaned.run()
    assert ccs._STEP_MARKER in workflow_file.read_text()

    fresh = ccs.CompromisedCiStepScenario()
    fresh.cleanup()

    assert workflow_file.read_text() == _SAMPLE_WORKFLOW


def test_cleanup_fallback_does_not_touch_an_already_clean_file(workflow_file):
    original = workflow_file.read_text()

    ccs.CompromisedCiStepScenario().cleanup()

    assert workflow_file.read_text() == original