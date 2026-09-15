import pytest

from scenarios.base import Scenario, ScenarioResult, ScenarioStatus
from scenarios.replay import _REGISTRY, register, replay


@pytest.fixture
def registered():
    registered_names = []

    def _register(scenario_cls):
        register(scenario_cls)
        registered_names.append(scenario_cls.name)
        return scenario_cls

    yield _register

    for name in registered_names:
        _REGISTRY.pop(name, None)


def test_replay_runs_log_result_and_cleanup_in_order(registered):
    calls = []

    @registered
    class _OrderTrackingScenario(Scenario):
        name = "test-order-tracking"
        mitre_technique = "N/A"

        def run(self):
            calls.append("run")
            return ScenarioResult(status=ScenarioStatus.SUCCESS, message="ok")

        def log_result(self, result):
            calls.append("log_result")

        def cleanup(self):
            calls.append("cleanup")

    result = replay("test-order-tracking")

    assert calls == ["run", "log_result", "cleanup"]
    assert result.status == ScenarioStatus.SUCCESS


def test_replay_still_cleans_up_when_run_raises(registered):
    calls = []

    @registered
    class _RaisingScenario(Scenario):
        name = "test-raising"
        mitre_technique = "N/A"

        def run(self):
            calls.append("run")
            raise RuntimeError("boom")

        def cleanup(self):
            calls.append("cleanup")

    with pytest.raises(RuntimeError):
        replay("test-raising")

    assert calls == ["run", "cleanup"]


def test_replay_raises_a_helpful_error_for_an_unknown_scenario_id():
    with pytest.raises(KeyError, match="unknown-scenario-xyz"):
        replay("unknown-scenario-xyz")


def test_register_returns_the_class_unchanged(registered):
    class _PlainScenario(Scenario):
        name = "test-plain"
        mitre_technique = "N/A"

        def run(self):
            return ScenarioResult(status=ScenarioStatus.SUCCESS, message="ok")

        def cleanup(self):
            pass

    returned = registered(_PlainScenario)

    assert returned is _PlainScenario