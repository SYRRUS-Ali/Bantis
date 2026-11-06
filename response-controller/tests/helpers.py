from datetime import UTC, datetime, timedelta

from actions.base import Action, ActionParams, ActionResult
from config import ControllerConfig
from executor import Executor, MemoryRecorder
from kill_switch import Level, engage
from models import Approval, Proposal
from registry import ActionRegistry

T0 = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)


class HoldParams(ActionParams):
    variable: str


class FakeAction(Action):
    """A stand-in with observable side effects, under a catalog type."""

    params_model = HoldParams

    def __init__(self, action_type="hold_promotion", steps=2):
        self.type = action_type
        self.steps = steps
        self.done_steps: list[int] = []
        self.blockers: list[str] = []
        self.effect_in_place = True
        self.raise_on_step: int | None = None
        self.on_step = None

    @property
    def automatic_scope(self):
        return "test/repo"

    def preconditions(self, proposal, params):
        return list(self.blockers)

    def plan(self, proposal, params):
        return f"set {params.variable}"

    def execute(self, proposal, params, guard):
        for n in range(1, self.steps + 1):
            guard.check()
            if self.raise_on_step == n:
                raise RuntimeError("remote API error")
            self.done_steps.append(n)
            if self.on_step:
                self.on_step(n)
        return ActionResult(detail={"steps": len(self.done_steps)})

    def verify(self, proposal, params, result):
        return self.effect_in_place


def clear_switch(state_dir):
    engage(state_dir, Level.CLEAR, "test setup", "test")


def proposal(action_type="hold_promotion", **overrides):
    fields = {
        "incident_id": "inc-1",
        "type": action_type,
        "params": {"variable": "BANTIS_PROMOTION_HOLD"},
        "policy_rule": "A3:test",
        "created_at": T0,
        "expires_at": T0 + timedelta(hours=1),
    }
    fields.update(overrides)
    return Proposal(**fields)


def approve(p, approver="operator", at=None, prefix_len=12):
    return Approval(action_id=p.action_id, approver=approver, hash_prefix=p.proposal_hash[:prefix_len], approved_at=at or T0 + timedelta(minutes=5))


def make(tmp_path, actions=(), enabled=None, dry_run=False, recorder=None, automatic=True, automatic_policy_rule="A3:test"):
    registry = ActionRegistry()
    for a in actions:
        registry.register(a)
    enabled = frozenset(enabled if enabled is not None else [a.type for a in actions])
    selected = next((a for a in actions if a.type == "hold_promotion"), None)
    auto_action = "hold_promotion" if automatic and selected is not None and selected.type in enabled else ""
    config = ControllerConfig(
        state_dir=tmp_path,
        enabled_actions=enabled,
        automatic_action=auto_action,
        automatic_repo=(selected.automatic_scope or "test/repo") if auto_action else "",
        automatic_policy_rule=automatic_policy_rule,
        dry_run=dry_run,
    )
    recorder = recorder or MemoryRecorder()
    return Executor(registry, config, recorder), recorder