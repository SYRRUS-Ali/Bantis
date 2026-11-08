"""Audited compensating actions, using the pre-execution snapshot as authority."""

from pydantic import Field

from actions.base import Action, ActionParams, ActionResult
from models import Proposal


class RollbackParams(ActionParams):
    original_action_id: str = Field(min_length=1)
    snapshot_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


def rollback_source(store, action_id, snapshot_hash=None):
    history = store.history(action_id)
    executing = next((e for e in history if e["event"] == "executing"), None)
    if executing is None:
        raise ValueError("action has no recorded execution to roll back")
    original = Proposal.model_validate(executing["proposal"])
    if original.action_id != action_id or original.proposal_hash != executing["proposal_hash"]:
        raise ValueError("recorded execution does not match its proposal")
    snapshot = next((e for e in history if e["event"] == "rollback_prepared"
                     and e.get("attempt_id") == executing["attempt_id"]), None)
    if snapshot is None:
        raise ValueError("action has no recorded rollback state; legacy or irreversible action requires manual recovery")
    if snapshot["proposal_hash"] != original.proposal_hash:
        raise ValueError("rollback state does not match the executed proposal")
    if snapshot_hash is not None and snapshot["entry_hash"] != snapshot_hash:
        raise ValueError("rollback snapshot hash does not match")
    return original, ActionResult.model_validate(snapshot["state"]), snapshot["entry_hash"]


class RollbackAction(Action):
    type = "rollback_action"
    params_model = RollbackParams

    def __init__(self, registry, store):
        self._registry, self._store = registry, store

    def _resolve(self, proposal, params):
        original, state, _ = rollback_source(self._store, params.original_action_id, params.snapshot_hash)
        if not any(e["event"] == "rollback_requested" and e["rollback_id"] == proposal.action_id
                   for e in self._store.history(original.action_id)):
            raise ValueError("rollback must be queued through the rollback review flow")
        if proposal.incident_id != original.incident_id:
            raise ValueError("rollback incident does not match the original action")
        if proposal.required_approvals < original.required_approvals:
            raise ValueError("rollback cannot reduce the original approval requirement")
        action = self._registry.get(original.type)
        if action is None:
            raise ValueError("the original action implementation is unavailable")
        return action.reversal(original, state)

    def preconditions(self, proposal, params):
        return self._resolve(proposal, params).preconditions(proposal, None)

    def plan(self, proposal, params):
        return self._resolve(proposal, params).plan(proposal, None)

    def execute(self, proposal, params, guard):
        result = self._resolve(proposal, params).execute(proposal, None, guard)
        return ActionResult(detail={**result.detail, "rollback_of": params.original_action_id})

    def execute_prepared(self, proposal, params, guard, state):
        result = self._resolve(proposal, params).execute_prepared(proposal, None, guard, state)
        return ActionResult(detail={**result.detail, "rollback_of": params.original_action_id})

    def verify(self, proposal, params, result):
        return self._resolve(proposal, params).verify(proposal, None, result)

    def prepare_rollback(self, proposal, params):
        return self._resolve(proposal, params).prepare_rollback(proposal, None)

    def reversal(self, proposal, state):
        return self._resolve(proposal, self.parse_params(proposal)).reversal(proposal, state)