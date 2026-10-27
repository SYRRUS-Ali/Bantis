from __future__ import annotations

import re

from actions.base import Action, ActionResult, NoParams
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