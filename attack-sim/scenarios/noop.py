"""A no-op scenario used to test the attack-sim interface itself.

Runs no real attack — it exists purely so the Scenario interface, its
logging, and its test suite have something concrete to exercise without
needing a real target or a real MITRE technique.
"""

from __future__ import annotations

from scenarios.base import Scenario, ScenarioResult, ScenarioStatus


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
