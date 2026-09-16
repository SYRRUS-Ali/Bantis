import cli
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
"""


def test_cleanup_recovers_a_scenario_left_dirty_without_running_it_first(tmp_path, monkeypatch):
    workflow_file = tmp_path / "ci.yml"
    workflow_file.write_text(_SAMPLE_WORKFLOW)
    monkeypatch.setattr(ccs, "_WORKFLOW_FILE", workflow_file)

    orphaned = ccs.CompromisedCiStepScenario()
    orphaned.run()
    assert ccs._STEP_MARKER in workflow_file.read_text()

    exit_code = cli.main(["cleanup", "compromised-ci-step"])

    assert exit_code == 0
    assert workflow_file.read_text() == _SAMPLE_WORKFLOW


def test_cleanup_on_a_scenario_with_nothing_to_clean_does_not_raise(capsys):
    exit_code = cli.main(["cleanup", "noop"])

    assert exit_code == 0
    assert "cleanup complete" in capsys.readouterr().out


def test_cleanup_unknown_scenario_prints_error_and_returns_exit_code_one(capsys):
    exit_code = cli.main(["cleanup", "does-not-exist"])

    assert exit_code == 1
    assert "unknown scenario_id" in capsys.readouterr().err