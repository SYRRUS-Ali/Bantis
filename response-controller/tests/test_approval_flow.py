from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from helpers import T0, FakeAction, clear_switch, proposal
from pydantic import ValidationError

from approval_flow import ApprovalFlow, ReviewError, ReviewStore
from config import ControllerConfig
from executor import Executor
from kill_switch import Level, engage
from models import Status
from registry import ActionRegistry

NOW = T0 + timedelta(minutes=10)


def build(tmp_path, action, *, dry_run=False):
    registry = ActionRegistry()
    registry.register(action)
    store = ReviewStore(tmp_path / "reviews.sqlite3")
    config = ControllerConfig(tmp_path, frozenset({action.type}), dry_run)
    return ApprovalFlow(store, Executor(registry, config, store), registry)


@pytest.fixture
def review(tmp_path):
    clear_switch(tmp_path)
    action = FakeAction("rollback_latest")
    flow = build(tmp_path, action)
    p = flow.submit(proposal(action.type), now=NOW)
    yield flow, action, p
    flow.store.close()


def test_submission_waits_then_approval_executes_exactly_once(review):
    flow, action, p = review
    assert flow.store.pending(NOW) == [p]
    assert action.done_steps == []
    outcome = flow.approve(p.action_id, p.proposal_hash[:12], "alice", now=NOW)
    assert outcome.status == Status.SUCCEEDED
    assert action.done_steps == [1, 2]
    assert flow.store.get(p.action_id)[1] == "succeeded"
    assert [e["event"] for e in flow.store.history(p.action_id)] == ["proposed", "approved", "executing", "outcome"]
    with pytest.raises(ReviewError, match="closed"):
        flow.approve(p.action_id, p.proposal_hash[:12], "alice", now=NOW)
    assert action.done_steps == [1, 2]


def test_pending_and_decisions_survive_restarts(tmp_path):
    clear_switch(tmp_path)
    action = FakeAction("rollback_latest")
    flow = build(tmp_path, action)
    p = flow.submit(proposal(action.type, required_approvals=2), now=NOW)
    assert flow.approve(p.action_id, p.proposal_hash, "alice", now=NOW).status == Status.AWAITING_APPROVAL
    flow.store.close()
    reopened = build(tmp_path, action)
    try:
        assert reopened.store.pending(NOW) == [p]
        with pytest.raises(ReviewError, match="already approved"):
            reopened.approve(p.action_id, p.proposal_hash, "alice", now=NOW)
        assert reopened.approve(p.action_id, p.proposal_hash, "bob", now=NOW).status == Status.SUCCEEDED
    finally:
        reopened.store.close()


def test_modifying_invalidates_old_approvals_and_preserves_scope(review):
    flow, action, original = review
    # Start with a proposal carrying a two-person approval requirement.
    p = flow.submit(proposal(action.type, required_approvals=2), now=NOW)
    flow.approve(p.action_id, p.proposal_hash, "alice", now=NOW)
    replacement = flow.modify(p.action_id, p.proposal_hash, "alice", {"variable": "OTHER"}, "correct target", now=NOW)
    assert replacement.action_id != p.action_id
    assert replacement.params == {"variable": "OTHER"}
    assert replacement.incident_id == p.incident_id
    assert replacement.type == p.type
    assert replacement.expires_at == p.expires_at
    assert replacement.required_approvals == 2
    assert flow.store.get(p.action_id)[1] == "modified"
    assert action.done_steps == []
    with pytest.raises(ReviewError, match="closed"):
        flow.approve(p.action_id, p.proposal_hash, "bob", now=NOW)
    with pytest.raises(ReviewError, match="hash"):
        flow.approve(replacement.action_id, p.proposal_hash, "bob", now=NOW)
    assert flow.approve(replacement.action_id, replacement.proposal_hash, "bob", now=NOW).status == Status.AWAITING_APPROVAL
    assert flow.approve(replacement.action_id, replacement.proposal_hash, "alice", now=NOW).status == Status.SUCCEEDED
    assert flow.executor.run(p, now=NOW).status == Status.REFUSED
    assert original in flow.store.pending(NOW)


def test_invalid_modification_does_not_close_original(review):
    flow, _action, p = review
    with pytest.raises(ValidationError):
        flow.modify(p.action_id, p.proposal_hash, "alice", {"variable": 7}, "fix", now=NOW)
    assert flow.store.pending(NOW) == [p]
    assert len(flow.store.history(p.action_id)) == 1


def test_dismissal_is_terminal_and_recorded(review):
    flow, action, p = review
    flow.dismiss(p.action_id, p.proposal_hash, "alice", "false positive", now=NOW)
    assert flow.store.get(p.action_id)[1] == "dismissed"
    assert flow.store.pending(NOW) == []
    assert flow.store.history(p.action_id)[-1]["reason"] == "false positive"
    with pytest.raises(ReviewError, match="closed"):
        flow.approve(p.action_id, p.proposal_hash, "bob", now=NOW)
    # Even direct executor use with this recorder cannot replay a closed proposal.
    assert flow.executor.run(p, now=NOW).status == Status.REFUSED
    assert action.done_steps == []


@pytest.mark.parametrize("decision", ["approve", "modify", "dismiss"])
def test_stale_hash_or_expiry_blocks_every_decision(review, decision):
    flow, action, p = review
    extras = {"modify": ({"variable": "OTHER"}, "fix"), "dismiss": ("ignore",), "approve": ()}[decision]
    method = getattr(flow, decision)
    with pytest.raises(ReviewError, match="hash"):
        method(p.action_id, "0" * 12, "alice", *extras, now=NOW)
    with pytest.raises(ReviewError, match="window"):
        method(p.action_id, p.proposal_hash, "alice", *extras, now=p.expires_at)
    assert flow.store.pending(p.expires_at) == []
    assert action.done_steps == []


@pytest.mark.parametrize("decision", ["modify", "dismiss"])
def test_modification_and_dismissal_require_a_reason(review, decision):
    flow, _action, p = review
    extras = ({"variable": "OTHER"}, "  ") if decision == "modify" else ("  ",)
    with pytest.raises(ReviewError, match="reason"):
        getattr(flow, decision)(p.action_id, p.proposal_hash, "alice", *extras, now=NOW)
    assert flow.store.pending(NOW) == [p]


def test_approval_respects_kill_switch(review, tmp_path):
    flow, action, p = review
    engage(tmp_path, Level.EXECUTION_OFF, "investigating", "operator")
    assert flow.approve(p.action_id, p.proposal_hash, "alice", now=NOW).status == Status.INVALIDATED
    assert action.done_steps == []


def test_auto_tier_still_waits_for_all_manual_approvals(tmp_path):
    clear_switch(tmp_path)
    action = FakeAction()
    flow = build(tmp_path, action)
    try:
        p = flow.submit(proposal(required_approvals=2), now=NOW)
        assert flow.approve(p.action_id, p.proposal_hash, "alice", now=NOW).status == Status.AWAITING_APPROVAL
        assert action.done_steps == []
        assert flow.approve(p.action_id, p.proposal_hash, "bob", now=NOW).status == Status.SUCCEEDED
    finally:
        flow.store.close()


def test_dry_run_records_plan_without_acting(tmp_path):
    clear_switch(tmp_path)
    action = FakeAction("rollback_latest")
    flow = build(tmp_path, action, dry_run=True)
    try:
        p = flow.submit(proposal(action.type), now=NOW)
        outcome = flow.approve(p.action_id, p.proposal_hash, "alice", now=NOW)
        assert outcome.status == Status.DRY_RUN and outcome.plan
        assert action.done_steps == []
    finally:
        flow.store.close()


def test_crash_after_executing_marker_cannot_replay(tmp_path):
    clear_switch(tmp_path)
    action = FakeAction("rollback_latest")
    flow = build(tmp_path, action)
    p = flow.submit(proposal(action.type), now=NOW)
    flow.store.record({"action_id": p.action_id, "event": "executing"})
    flow.store.close()
    reopened = build(tmp_path, action)
    try:
        assert reopened.store.pending(NOW) == []
        assert reopened.store.get(p.action_id)[1] == "executing"
        with pytest.raises(ReviewError, match="closed"):
            reopened.approve(p.action_id, p.proposal_hash, "alice", now=NOW)
        assert action.done_steps == []
    finally:
        reopened.store.close()


def test_concurrent_approvals_execute_once(review, tmp_path):
    _flow, action, p = review

    def approve(actor):
        other = build(tmp_path, action)
        try:
            return other.approve(p.action_id, p.proposal_hash, actor, now=NOW).status
        except ReviewError:
            return "closed"
        finally:
            other.store.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(approve, ["alice", "bob"]))
    assert sorted(results) == ["closed", "succeeded"]
    assert action.done_steps == [1, 2]


def test_failed_audit_write_does_not_execute_or_store_approval(review, monkeypatch):
    flow, action, p = review

    def fail(entry):
        raise OSError("disk full")

    monkeypatch.setattr(flow.store, "record", fail)
    with pytest.raises(OSError, match="disk full"):
        flow.approve(p.action_id, p.proposal_hash, "alice", now=NOW)
    assert flow.store.db.execute("SELECT COUNT(*) FROM approvals").fetchone()[0] == 0
    assert action.done_steps == []