from __future__ import annotations

import re

from actions.base import Action, ActionParams, ActionResult, NoParams
from github_client import GitHubVariables
from models import Proposal

HOLD_VARIABLE = "BANTIS_PROMOTION_HOLD"
HOLD_MARKER = "bantis-hold"
_SAFE_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def hold_value(proposal: Proposal) -> str:
    return f"{HOLD_MARKER} incident={proposal.incident_id} action={proposal.action_id}"


def _unconfigured(client: GitHubVariables | None) -> list[str]:
    if client is None:
        return ["GitHub credentials for promotion holds are not configured"]
    return []


class HoldPromotion(Action):
    type = "hold_promotion"
    params_model = NoParams

    def __init__(self, client: GitHubVariables | None) -> None:
        self._client = client

    @property
    def automatic_scope(self) -> str | None:
        return self._client.repo if self._client is not None else None

    def preconditions(self, proposal, params):
        problems = _unconfigured(self._client)
        for label, value in (("incident_id", proposal.incident_id), ("action_id", proposal.action_id)):
            if not _SAFE_ID.match(value):
                problems.append(f"{label} is not a plain identifier")
        if problems:
            return problems
        current = self._client.get(HOLD_VARIABLE)
        if current is not None and current != hold_value(proposal):
            # Design limit: at most one active hold. The existing one stays.
            return [f"a promotion hold is already active ({current[:120]})"]
        return []

    def plan(self, proposal, params):
        return (
            f"set {HOLD_VARIABLE} on {self._client.repo} so promote-latest skips "
            f"(quarantine for incident {proposal.incident_id})"
        )

    def execute(self, proposal, params, guard):
        value = hold_value(proposal)
        guard.check()
        current = self._client.get(HOLD_VARIABLE)
        if current is not None:
            return ActionResult(detail={"created": False, "existing": current[:120]})
        guard.check()
        created = self._client.create(HOLD_VARIABLE, value)
        return ActionResult(detail={"created": created})

    def verify(self, proposal, params, result):
        current = self._client.get(HOLD_VARIABLE)
        return current is not None and current.startswith(HOLD_MARKER)

    def prepare_rollback(self, proposal, params):
        before = self._client.get(HOLD_VARIABLE)
        return _snapshot(self._client, before, hold_value(proposal) if before is None else before)

    def reversal(self, proposal, state):
        return RestorePromotionHold(self._client, state)

    def execute_prepared(self, proposal, params, guard, state):
        guard.check()
        _check_snapshot(self._client, state)
        return self.execute(proposal, params, guard)


class LiftPromotionHold(Action):
    type = "lift_promotion_hold"
    params_model = NoParams

    def __init__(self, client: GitHubVariables | None) -> None:
        self._client = client

    def preconditions(self, proposal, params):
        problems = _unconfigured(self._client)
        if problems:
            return problems
        if self._client.get(HOLD_VARIABLE) is None:
            return ["no promotion hold is active"]
        return []

    def plan(self, proposal, params):
        current = self._client.get(HOLD_VARIABLE)
        return f"delete {HOLD_VARIABLE} on {self._client.repo} so promotions resume (was: {(current or '')[:120]})"

    def execute(self, proposal, params, guard):
        guard.check()
        deleted = self._client.delete(HOLD_VARIABLE)
        return ActionResult(detail={"deleted": deleted})

    def verify(self, proposal, params, result):
        return self._client.get(HOLD_VARIABLE) is None

    def prepare_rollback(self, proposal, params):
        return _snapshot(self._client, self._client.get(HOLD_VARIABLE), None)

    def reversal(self, proposal, state):
        return RestorePromotionHold(self._client, state)

    def execute_prepared(self, proposal, params, guard, state):
        guard.check()
        _check_snapshot(self._client, state)
        return self.execute(proposal, params, guard)


class PromotionRollbackState(ActionParams):
    target: str
    before: str | None
    after: str | None


def _snapshot(client, before, after):
    state = PromotionRollbackState(target=client.target, before=before, after=after)
    return ActionResult(detail=state.model_dump())


def _check_snapshot(client, state):
    saved = PromotionRollbackState.model_validate(state.detail)
    if client.target != saved.target or client.get(HOLD_VARIABLE) != saved.before:
        raise ValueError("promotion hold changed after rollback state was captured; not acting")


class RestorePromotionHold(Action):
    """Compensation bound to an audited target, previous value and expected value."""

    type = "rollback_action"

    def __init__(self, client, state):
        self._client = client
        self._state = PromotionRollbackState.model_validate(state.detail)

    def preconditions(self, proposal, params):
        problems = _unconfigured(self._client)
        if problems:
            return problems
        if self._client.target != self._state.target:
            return ["rollback target differs from the recorded execution target"]
        current = self._client.get(HOLD_VARIABLE)
        if current not in (self._state.before, self._state.after):
            return ["promotion hold changed since execution; review the target manually"]
        return []

    def plan(self, proposal, params):
        operation = "remove" if self._state.before is None else "restore the previous value of"
        return f"{operation} {HOLD_VARIABLE} on {self._state.target} (rollback)"

    def execute(self, proposal, params, guard):
        guard.check()
        problems = self.preconditions(proposal, params)
        if problems:
            raise ValueError("; ".join(problems))
        current = self._client.get(HOLD_VARIABLE)
        if current == self._state.before:
            return ActionResult(detail={"restored": True, "changed": False})
        if current != self._state.after:
            raise ValueError("promotion hold changed before rollback")
        guard.check()
        if self._state.before is None:
            self._client.delete(HOLD_VARIABLE)
        else:
            self._client.create(HOLD_VARIABLE, self._state.before)
        return ActionResult(detail={"restored": True, "changed": True})

    def verify(self, proposal, params, result):
        return self._client.get(HOLD_VARIABLE) == self._state.before

    def prepare_rollback(self, proposal, params):
        return _snapshot(self._client, self._client.get(HOLD_VARIABLE), self._state.before)

    def reversal(self, proposal, state):
        return RestorePromotionHold(self._client, state)

    def execute_prepared(self, proposal, params, guard, state):
        guard.check()
        _check_snapshot(self._client, state)
        return self.execute(proposal, params, guard)