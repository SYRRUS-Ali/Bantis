"""Decides whether a proposal may run, and runs it -- in this order, each
step able to stop it:

1. the type is in the catalog and has an implementation
2. the action is enabled in configuration (G5)
3. the parameters validate strictly against the action's own model
4. it hasn't already been executed (action_id is the idempotency key)
5. it hasn't expired
6. approvals presented match this exact proposal's hash
7. the kill switch allows it (fail closed)
8. enough distinct approvers, unless the proposal matches the explicit automatic scope
9. the action's preconditions hold
10. dry run stops here, recording the plan
11. reserve an automatic slot if needed, then record "executing" before any effect
12. execute, with the kill switch re-checked before every step
13. verify the effect; a failure trips the kill switch
"""

from __future__ import annotations

import logging
import os
import pwd
import threading
import uuid
from datetime import UTC, datetime
from typing import Protocol

from pydantic import ValidationError

from actions.base import ActionParams, Halted, StepGuard
from automatic import AutomaticDuplicate, AutomaticLimit, check_reservation
from catalog import CATALOG, Tier
from config import ControllerConfig
from kill_switch import Level, read_state, trip
from models import Approval, Outcome, Proposal, Status
from registry import ActionRegistry

logger = logging.getLogger("response_controller.executor")


class Recorder(Protocol):
    """Durable audit sink; MemoryRecorder is only for tests."""

    def record(self, entry: dict) -> None: ...

    def already_executed(self, action_id: str) -> bool: ...

    def reserve_automatic(self, entry: dict, maximum: int) -> None: ...


class MemoryRecorder:
    def __init__(self) -> None:
        self.entries: list[dict] = []
        self._automatic_lock = threading.Lock()

    def record(self, entry: dict) -> None:
        self.entries.append(entry)

    def already_executed(self, action_id: str) -> bool:
        return any(e["action_id"] == action_id and e["event"] == "executing" for e in self.entries)

    def reserve_automatic(self, entry: dict, maximum: int) -> None:
        with self._automatic_lock:
            check_reservation(self.entries, entry, maximum)
            self.record(entry)


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

    def run(self, proposal: Proposal, approvals: list[Approval] | tuple[Approval, ...] = (),
            now: datetime | None = None, *, actor: str = "policy") -> Outcome:
        if not actor.strip():
            raise ValueError("initiating actor is required")
        now = now or datetime.now(UTC)
        attempt_id = uuid.uuid4().hex
        executor_identity = pwd.getpwuid(os.getuid()).pw_name

        def record(event: str, body: dict) -> bool:
            return self._record(proposal, event, {
                **body, "actor": executor_identity, "initiated_by": actor,
                "at": datetime.now(UTC).isoformat(), "attempt_id": attempt_id,
            })

        if not record("requested", {"approvals": [a.model_dump(mode="json") for a in approvals]}):
            return Outcome(action_id=proposal.action_id, type=proposal.type, status=Status.REFUSED,
                           reasons=["could not record the action request; not acting"])
        outcome = self._decide_and_run(proposal, list(approvals), now, record)
        if not record("outcome", outcome.model_dump(mode="json")):
            # An external effect cannot be rolled back by a failed audit write.
            # Report uncertainty and stop subsequent execution through the tripwire.
            return outcome.model_copy(update={"status": Status.FAILED,
                "reasons": [*outcome.reasons, "could not record the final outcome; investigate the action log and target"]})
        return outcome

    def _decide_and_run(self, proposal: Proposal, approvals: list[Approval], now: datetime, record) -> Outcome:
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
        auto_eligible = (
            tier == Tier.AUTO
            and proposal.type == self._config.automatic_action
            and action.automatic_scope == self._config.automatic_repo
            and proposal.policy_rule == self._config.automatic_policy_rule
            and proposal.required_approvals == 1
        )
        needs_approval = bool(approvals) or not auto_eligible or not state.auto_allowed
        if needs_approval and len(approvers) < proposal.required_approvals:
            why = "approval required" if state.auto_allowed else "auto-execution is off; approval required"
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

        if not needs_approval:
            try:
                reserved = record("automatic_reserved", {"reserved_at": now.isoformat(),
                                  "scope": action.automatic_scope,
                                  "policy_rule": self._config.automatic_policy_rule,
                                  "maximum_per_hour": self._config.automatic_max_per_hour})
            except AutomaticDuplicate as exc:
                return done(Status.INVALIDATED, str(exc), plan=plan)
            except AutomaticLimit as exc:
                self._trip(str(exc), proposal, level=Level.AUTO_OFF)
                return done(Status.AWAITING_APPROVAL, str(exc), plan=plan)
            if not reserved:
                return done(Status.REFUSED, "could not reserve an automatic attempt; not acting", plan=plan)

        if not record("executing", {"plan": plan, "approvers": sorted(approvers)}):
            return done(Status.REFUSED, "could not record the action before executing; not acting", plan=plan)

        return self._execute(proposal, action, params, plan, needs_auto=not needs_approval, done=done, record=record)

    def _execute(self, proposal, action, params: ActionParams, plan: str, needs_auto: bool, done, record) -> Outcome:
        guard = _SwitchGuard(self._config, needs_auto)
        try:
            guard.check()
            rollback_state = action.prepare_rollback(proposal, params)
            if rollback_state is not None and not record("rollback_prepared", {"state": rollback_state.model_dump(mode="json")}):
                return done(Status.REFUSED, "could not record rollback state; not acting", plan=plan)
            guard.check()
            result = action.execute_prepared(proposal, params, guard, rollback_state)
        except Halted as exc:
            return done(Status.INVALIDATED, f"halted by the kill switch: {exc}", plan=plan)
        except Exception as exc:
            logger.exception("action %s (%s) failed", proposal.action_id, proposal.type)
            self._trip(f"{proposal.type} {proposal.action_id} raised {type(exc).__name__}", proposal)
            return done(Status.FAILED, f"{type(exc).__name__}: {exc}", plan=plan)

        if not record("executed", {"detail": result.detail}):
            return done(Status.FAILED, "could not record the execution result; investigate target state", plan=plan)
        if not record("verification_started", {}):
            return done(Status.FAILED, "could not record verification; investigate target state", plan=plan)
        try:
            verified = action.verify(proposal, params, result)
        except Exception as exc:
            verified = False
            logger.exception("verifying %s failed", proposal.action_id)
            reason = f"post-check raised {type(exc).__name__}: {exc}"
        else:
            reason = "post-check: the intended effect is not in place"
        if not record("verified", {"verified": verified, "reason": None if verified else reason}):
            return done(Status.FAILED, "could not record verification result; investigate target state", plan=plan)
        if not verified:
            self._trip(f"{proposal.type} {proposal.action_id}: {reason}", proposal)
            return done(Status.FAILED, reason, plan=plan, detail=result.detail)
        return done(Status.SUCCEEDED, plan=plan, detail=result.detail)

    def _record(self, proposal: Proposal, event: str, body: dict) -> bool:
        entry = {
            "action_id": proposal.action_id,
            "event": event,
            "proposal": proposal.model_dump(mode="json"),
            "proposal_hash": proposal.proposal_hash,
            "incident_id": proposal.incident_id,
            "type": proposal.type,
            **body,
        }
        try:
            if event == "automatic_reserved":
                self._recorder.reserve_automatic(entry, self._config.automatic_max_per_hour)
            else:
                self._recorder.record(entry)
            return True
        except (AutomaticLimit, AutomaticDuplicate):
            raise
        except Exception:
            logger.exception("could not record %s for %s", event, proposal.action_id)
            self._trip(f"the action log could not be written ({event} {proposal.action_id})", proposal)
            return False

    def _trip(self, reason: str, proposal: Proposal, *, level: Level = Level.EXECUTION_OFF) -> None:
        try:
            trip(self._config.state_dir, level, reason)
            try:
                self._recorder.record({
                    "action_id": proposal.action_id, "incident_id": proposal.incident_id,
                    "type": proposal.type, "proposal_hash": proposal.proposal_hash,
                    "event": "kill_switch_tripped", "actor": pwd.getpwuid(os.getuid()).pw_name,
                    "at": datetime.now(UTC).isoformat(), "level": level.value,
                    "reason": reason,
                })
            except Exception:
                logger.error("kill switch engaged; could not audit tripwire: %s", reason)
        except Exception:
            # The switch can't be written either. read_state() fails closed on
            # an unreadable tripwire file, but not on one that was never written,
            # so say so as loudly as possible.
            logger.critical("TRIPWIRE COULD NOT ENGAGE: %s", reason)