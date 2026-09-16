from __future__ import annotations

from scenarios.base import Scenario, ScenarioResult, ScenarioStatus
from scenarios.replay import register


@register
class NoopScenario(Scenario):
    name = "noop"
    mitre_technique = "N/A"

    def run(self) -> ScenarioResult:
        return ScenarioResult(
            status=ScenarioStatus.SUCCESS,
            message="no-op scenario executed",
        )

    def cleanup(self) -> None:
        """Nothing to revert — run() doesn't touch any state."""
