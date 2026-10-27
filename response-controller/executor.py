"""Decides whether a proposal may run, and runs it -- in this order, each
step able to stop it:

1. the type is in the catalog and has an implementation
2. the action is enabled in configuration (G5)
3. the parameters validate strictly against the action's own model
4. it hasn't already been executed (action_id is the idempotency key)
5. it hasn't expired
6. approvals presented match this exact proposal's hash
7. the kill switch allows it (fail closed)
8. enough distinct approvers, if the tier -- or auto-off -- requires them
9. the action's preconditions hold
10. dry run stops here, recording the plan
11. "executing" is recorded first: if it can't be recorded, it doesn't run
12. execute, with the kill switch re-checked before every step
13. verify the effect; a failure trips the kill switch
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Protocol

from pydantic import ValidationError

from actions.base import ActionParams, Halted, StepGuard
from catalog import CATALOG, Tier
from config import ControllerConfig
from kill_switch import Level, read_state, trip
from models import Approval, Outcome, Proposal, Status
from registry import ActionRegistry

logger = logging.getLogger("response_controller.executor")


class Recorder(Protocol):
    """Where every outcome goes. The hash-chained, anchored action log
    (gate G2) implements this; until then MemoryRecorder does, for tests."""

    def record(self, entry: dict) -> None: ...

    def already_executed(self, action_id: str) -> bool: ...


class MemoryRecorder:
    def __init__(self) -> None:
        self.entries: list[dict] = []

    def record(self, entry: dict) -> None:
        self.entries.append(entry)

    def already_executed(self, action_id: str) -> bool:
        return any(e["action_id"] == action_id and e["event"] == "executing" for e in self.entries)


class _SwitchGuard(StepGuard):
    def __init__(self, config: ControllerConfig, needs_auto: bool) -> None:
        self._config = config
        self._needs_auto = needs_auto

    def check(self) -> None:
        state = read_state(self._config.state_dir)
        if not state.execution_allowed or (self._needs_auto and not state.auto_allowed):
            raise Halted("; ".join(state.reasons))


class Executor:
    def __init__(self, registry: ActionRegistry, config: ControllerConfig, recorder: Recorder) -> None:
        self._registry = registry
        self._config = config
        self._recorder = recorder

    def run(self, proposal: Proposal, approvals: list[Approval] | tuple[Approval, ...] = (), now: datetime | None = None) -> Outcome:
        now = now or datetime.now(UTC)
        outcome = self._decide_and_run(proposal, list(approvals), now)
        self._record(proposal, "outcome", outcome.model_dump(mode="json"), must_succeed=False)
        return outcome

    def _decide_and_run(self, proposal: Proposal, approvals: list[Approval], now: datetime) -> Outcome:
        def done(status: Status, *reasons: str, **extra) -> Outcome:
            return Outcome(action_id=proposal.action_id, type=proposal.type, status=status, reasons=list(reasons), **extra)

        tier = CATALOG.get(proposal.type)
        if tier is None:
            return done(Status.REFUSED, f"{proposal.type!r} is not in the action catalog")
        action = self._registry.get(proposal.type)
        if action is None:
            return done(Status.REFUSED, f"{proposal.type!r} has no implementation")
        if proposal.type not in self._config.enabled_actions:
            return done(Status.REFUSED, f"{proposal.type!r} is not enabled")
        try:
            params = action.parse_params(proposal)
        except ValidationError as exc:
            return done(Status.REFUSED, f"invalid parameters: {exc.errors()[0]['msg']}")
        if self._recorder.already_executed(proposal.action_id):
            return done(Status.REFUSED, f"{proposal.action_id} was already executed")
        if proposal.is_expired(now):
            return done(Status.EXPIRED, f"expired at {proposal.expires_at.isoformat()}")

        mismatched = [a for a in approvals if not a.matches(proposal)]
        if mismatched:
            # An approval for something else -- or for this action before it
            # changed. Never "close enough".
            return done(Status.REFUSED, "an approval does not match this proposal's hash; re-approval required")
        valid = [a for a in approvals if proposal.created_at <= a.approved_at < proposal.expires_at]
        approvers = {a.approver for a in valid}

        state = read_state(self._config.state_dir)
        if not state.execution_allowed:
            return done(Status.INVALIDATED, *state.reasons)
        needs_approval = tier == Tier.APPROVAL or not state.auto_allowed
        if needs_approval and len(approvers) < proposal.required_approvals:
            why = "approval required" if tier == Tier.APPROVAL else "auto-execution is off; approval required"
            return done(Status.AWAITING_APPROVAL, f"{why}: {len(approvers)} of {proposal.required_approvals}")

        try:
            problems = action.preconditions(proposal, params)
            plan = None if problems else action.plan(proposal, params)
        except Exception as exc:
            logger.exception("checking %s (%s) raised", proposal.action_id, proposal.type)
            return done(Status.INVALIDATED, f"could not check preconditions: {type(exc).__name__}: {exc}")
        if problems:
            return done(Status.INVALIDATED, *problems)

        if self._config.dry_run:
            return done(Status.DRY_RUN, plan=plan)

        if not self._record(proposal, "executing", {"plan": plan, "approvers": sorted(approvers)}, must_succeed=True):
            return done(Status.REFUSED, "could not record the action before executing; not acting", plan=plan)

        return self._execute(proposal, action, params, plan, needs_auto=not needs_approval, done=done)

    def _execute(self, proposal, action, params: ActionParams, plan: str, needs_auto: bool, done) -> Outcome:
        guard = _SwitchGuard(self._config, needs_auto)
        try:
            guard.check()
            result = action.execute(proposal, params, guard)
        except Halted as exc:
            return done(Status.INVALIDATED, f"halted by the kill switch: {exc}", plan=plan)
        except Exception as exc:
            logger.exception("action %s (%s) failed", proposal.action_id, proposal.type)
            self._trip(f"{proposal.type} {proposal.action_id} raised {type(exc).__name__}")
            return done(Status.FAILED, f"{type(exc).__name__}: {exc}", plan=plan)

        try:
            verified = action.verify(proposal, params, result)
        except Exception as exc:
            verified = False
            logger.exception("verifying %s failed", proposal.action_id)
            reason = f"post-check raised {type(exc).__name__}: {exc}"
        else:
            reason = "post-check: the intended effect is not in place"
        if not verified:
            self._trip(f"{proposal.type} {proposal.action_id}: {reason}")
            return done(Status.FAILED, reason, plan=plan, detail=result.detail)
        return done(Status.SUCCEEDED, plan=plan, detail=result.detail)

    def _record(self, proposal: Proposal, event: str, body: dict, must_succeed: bool) -> bool:
        entry = {
            "action_id": proposal.action_id,
            "event": event,
            "proposal": proposal.model_dump(mode="json"),
            "proposal_hash": proposal.proposal_hash,
            **body,
        }
        try:
            self._recorder.record(entry)
            return True
        except Exception:
            logger.exception("could not record %s for %s", event, proposal.action_id)
            self._trip(f"the action log could not be written ({event} {proposal.action_id})")
            return False

    def _trip(self, reason: str) -> None:
        try:
            trip(self._config.state_dir, Level.EXECUTION_OFF, reason)
        except Exception:
            # The switch can't be written either. read_state() fails closed on
            # an unreadable tripwire file, but not on one that was never written,
            # so say so as loudly as possible.
            logger.critical("TRIPWIRE COULD NOT ENGAGE: %s", reason)