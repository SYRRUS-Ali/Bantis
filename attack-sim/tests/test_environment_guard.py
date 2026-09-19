import cli
import pytest
import scenarios.compromised_ci_step  # noqa: F401 -- registers via replay.register
import scenarios.leaked_secret  # noqa: F401
import scenarios.malicious_dependency  # noqa: F401
import scenarios.noop  # noqa: F401
import scenarios.typosquatting  # noqa: F401
from scenarios.base import ScenarioEnvironmentError
from scenarios.replay import available


@pytest.mark.parametrize("scenario_id, scenario_cls", sorted(available().items()))
def test_scenario_refuses_to_instantiate_without_the_env_var(scenario_id, scenario_cls, monkeypatch):
    monkeypatch.delenv("BANTIS_ENV", raising=False)

    with pytest.raises(ScenarioEnvironmentError, match="BANTIS_ENV"):
        scenario_cls()


@pytest.mark.parametrize("scenario_id, scenario_cls", sorted(available().items()))
def test_scenario_refuses_to_instantiate_with_the_wrong_value(scenario_id, scenario_cls, monkeypatch):
    monkeypatch.setenv("BANTIS_ENV", "production")

    with pytest.raises(ScenarioEnvironmentError, match="production"):
        scenario_cls()


@pytest.mark.parametrize("scenario_id, scenario_cls", sorted(available().items()))
def test_scenario_instantiates_fine_with_the_correct_value(scenario_id, scenario_cls, monkeypatch):
    monkeypatch.setenv("BANTIS_ENV", "range-local")

    scenario_cls()  # must not raise


def test_cli_list_works_without_the_env_var(monkeypatch, capsys):
    monkeypatch.delenv("BANTIS_ENV", raising=False)

    exit_code = cli.main(["list"])

    assert exit_code == 0
    assert "noop" in capsys.readouterr().out


def test_cli_run_fails_cleanly_without_the_env_var(monkeypatch, capsys):
    monkeypatch.delenv("BANTIS_ENV", raising=False)

    exit_code = cli.main(["run", "noop"])

    assert exit_code == 1
    assert "BANTIS_ENV" in capsys.readouterr().err


def test_cli_cleanup_fails_cleanly_without_the_env_var(monkeypatch, capsys):
    monkeypatch.delenv("BANTIS_ENV", raising=False)

    exit_code = cli.main(["cleanup", "noop"])

    assert exit_code == 1
    assert "BANTIS_ENV" in capsys.readouterr().err


def test_cli_run_succeeds_with_the_env_var_set(monkeypatch, capsys):
    monkeypatch.setenv("BANTIS_ENV", "range-local")

    exit_code = cli.main(["run", "noop"])

    assert exit_code == 0
    assert "success" in capsys.readouterr().out