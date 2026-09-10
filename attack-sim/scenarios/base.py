"""Generic interface every attack-sim scenario implements.

See docs/scenarios-plan.md for the scenarios this supports and
docs/event-schema.md for the event envelope log_result() emits.
"""

from __future__ import annotations

import logging
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("attack_sim")


class ScenarioStatus(str, Enum):
    """Outcome of a scenario's run() — not whether run() raised, but whether
    the simulated attack achieved what it set out to do."""

    SUCCESS = "success"
    FAILURE = "failure"
    ERROR = "error"


@dataclass
class ScenarioResult:
    """What run() returns, and what log_result() reports."""

    status: ScenarioStatus
    message: str
    details: dict = field(default_factory=dict)


class Scenario(ABC):
    """Base class for every attack simulation scenario.

    Subclasses set `name` and `mitre_technique`, and implement `run()` and
    `cleanup()`. `log_result()` is provided here rather than per-scenario,
    so every scenario emits its event in exactly the same shape.
    """

    name: str
    mitre_technique: str

    @abstractmethod
    def run(self) -> ScenarioResult:
        """Execute the scenario against the target.

        Must not raise for an expected/simulated failure — return a
        ScenarioResult with status=FAILURE or ERROR instead. Only raise for
        a genuine bug in the scenario itself.
        """

    @abstractmethod
    def cleanup(self) -> None:
        """Revert any state run() changed. Called even after a failed run."""

    def log_result(self, result: ScenarioResult) -> None:
        """Emit a structured event for this scenario's outcome.

        Matches the envelope in docs/event-schema.md: source="attack-sim",
        event_type="attack_scenario_run", with scenario-specific fields
        under `details`.
        """
        logger.info(
            result.message,
            extra={
                "event_id": str(uuid.uuid4()),
                "source": "attack-sim",
                "event_type": "attack_scenario_run",
                "details": {
                    "scenario": self.name,
                    "mitre_technique": self.mitre_technique,
                    "status": result.status.value,
                    **result.details,
                },
            },
        )
