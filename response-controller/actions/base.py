from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from pydantic import BaseModel, ConfigDict

from models import JsonScalar, Proposal


class ActionParams(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class NoParams(ActionParams):
    pass


class Halted(RuntimeError):
    """The kill switch was engaged between steps of a running action."""


class StepGuard(ABC):
    @abstractmethod
    def check(self) -> None:
        """Raise Halted unless execution may continue. Call immediately
        before every step that has an external effect."""


class ActionResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    detail: dict[str, JsonScalar] = {}


class Action(ABC):
    type: ClassVar[str]
    params_model: ClassVar[type[ActionParams]] = NoParams

    @property
    def automatic_scope(self) -> str | None:
        """Fixed deployment target, if this implementation supports automation."""
        return None

    def parse_params(self, proposal: Proposal) -> ActionParams:
        return self.params_model.model_validate(proposal.params)

    def prepare_rollback(self, proposal: Proposal, params: ActionParams) -> ActionResult | None:
        """Read-only state to persist before execution; None means irreversible."""
        return None

    def reversal(self, proposal: Proposal, state: ActionResult) -> Action:
        """Build a compensating action from the recorded state, without effects."""
        raise ValueError(f"{self.type!r} does not support rollback")

    def execute_prepared(self, proposal: Proposal, params: ActionParams, guard: StepGuard,
                         state: ActionResult | None) -> ActionResult:
        """Execute with the durable snapshot; implementations can reject intervening drift."""
        return self.execute(proposal, params, guard)

    @abstractmethod
    def preconditions(self, proposal: Proposal, params: ActionParams) -> list[str]:
        """Why the action can't run right now; empty when it can. Read-only."""

    @abstractmethod
    def plan(self, proposal: Proposal, params: ActionParams) -> str:
        """What execute() would do, in one line, for dry runs and approvers.
        Read-only."""

    @abstractmethod
    def execute(self, proposal: Proposal, params: ActionParams, guard: StepGuard) -> ActionResult:
        """Do it. Idempotent: running twice for one action_id is harmless.
        Call guard.check() before each step with an external effect."""

    @abstractmethod
    def verify(self, proposal: Proposal, params: ActionParams, result: ActionResult) -> bool:
        """Whether the intended effect is now actually in place. Read-only."""