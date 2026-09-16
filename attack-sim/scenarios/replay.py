from __future__ import annotations

from typing import TypeVar

from scenarios.base import Scenario, ScenarioResult

_ScenarioT = TypeVar("_ScenarioT", bound=type[Scenario])

_REGISTRY: dict[str, type[Scenario]] = {}


def register(scenario_cls: _ScenarioT) -> _ScenarioT:
    _REGISTRY[scenario_cls.name] = scenario_cls
    return scenario_cls


def available() -> dict[str, type[Scenario]]:
    return dict(_REGISTRY)


def replay(scenario_id: str) -> ScenarioResult:
    try:
        scenario_cls = _REGISTRY[scenario_id]
    except KeyError:
        raise KeyError(
            f"unknown scenario_id {scenario_id!r} — registered: {sorted(_REGISTRY)}"
        ) from None

    scenario = scenario_cls()
    try:
        result = scenario.run()
        scenario.log_result(result)
        return result
    finally:
        scenario.cleanup()