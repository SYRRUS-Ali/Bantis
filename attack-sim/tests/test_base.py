import json
import logging

import pytest

from scenarios.base import Scenario, ScenarioResult, ScenarioStatus
from scenarios.noop import NoopScenario


def test_scenario_is_abstract() -> None:
    with pytest.raises(TypeError):
        Scenario()


def test_incomplete_scenario_cannot_be_instantiated() -> None:
    class MissingCleanup(Scenario):
        name = "incomplete"
        mitre_technique = "N/A"

        def run(self) -> ScenarioResult:
            return ScenarioResult(status=ScenarioStatus.SUCCESS, message="n/a")

    with pytest.raises(TypeError):
        MissingCleanup()


def test_noop_run_returns_success() -> None:
    result = NoopScenario().run()
    assert result.status == ScenarioStatus.SUCCESS
    assert result.message


def test_noop_cleanup_does_not_raise() -> None:
    NoopScenario().cleanup()


def test_log_result_emits_schema_shaped_event(caplog: pytest.LogCaptureFixture) -> None:
    scenario = NoopScenario()
    result = scenario.run()

    with caplog.at_level(logging.INFO, logger="attack_sim"):
        scenario.log_result(result)

    assert len(caplog.records) == 1
    record = caplog.records[0]

    assert record.source == "attack-sim"
    assert record.event_type == "attack_scenario_run"
    assert record.event_id
    assert record.details == {
        "scenario": "noop",
        "mitre_technique": "N/A",
        "status": "success",
    }


def test_log_result_is_json_serializable() -> None:
    """Guards against a future ScenarioResult.details value (e.g. a set,
    or an object without a str()) that would break the JSON formatter used
    in production, even though this test doesn't configure that formatter
    itself."""
    scenario = NoopScenario()
    result = scenario.run()
    payload = {
        "scenario": scenario.name,
        "mitre_technique": scenario.mitre_technique,
        "status": result.status.value,
        **result.details,
    }
    json.dumps(payload)
