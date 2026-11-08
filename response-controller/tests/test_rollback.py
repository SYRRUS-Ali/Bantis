from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace

import pytest
from fake_github import TOKEN, FakeGitHub
from helpers import T0, clear_switch, proposal

from actions.promotion_hold import HOLD_VARIABLE, hold_value
from approval_flow import ApprovalFlow, ReviewError, ReviewStore
from config import ControllerConfig
from executor import Executor
from kill_switch import TRIPWIRE_FILE, Level, engage, read_state
from models import Proposal, Status
from wiring import build_registry

NOW = T0 + timedelta(minutes=10)


@pytest.fixture
def stack(tmp_path):
    github = FakeGitHub()
    env = {"RESPONSE_GITHUB_REPO": github.repo, "RESPONSE_GITHUB_TOKEN_PROMOTION": TOKEN,
           "RESPONSE_GITHUB_API_URL": github.url}
    clear_switch(tmp_path)
    config = ControllerConfig(state_dir=tmp_path, dry_run=False,
                              enabled_actions=frozenset({"hold_promotion", "lift_promotion_hold", "rollback_action"}),
                              automatic_action="hold_promotion", automatic_repo=github.repo)
    with closing(ReviewStore(tmp_path / "reviews.sqlite3")) as store:
        registry = build_registry(env, store=store)
        executor = Executor(registry, config, store)
        flow = ApprovalFlow(store, executor, registry)
        yield SimpleNamespace(github=github, env=env, store=store, registry=registry,
                              executor=executor, flow=flow, config=config)
    github.close()


def execute(stack, action_type="hold_promotion", **overrides):
    source = proposal(action_type, params={}, policy_rule="A3:composite-success", **overrides)
    stack.flow.submit(source, now=NOW)
    if action_type == "hold_promotion":
        outcome = stack.flow.run_automatic(source.action_id, now=NOW)
    else:
        outcome = stack.flow.approve(source.action_id, source.proposal_hash[:12], "alice", now=NOW)
    assert outcome.status == Status.SUCCEEDED, outcome.reasons
    return source


def request(stack, source, **overrides):
    return stack.flow.rollback(source.action_id, source.proposal_hash[:12], "alice", "false positive",
                               now=overrides.pop("now", NOW), **overrides)


def approve(stack, rollback, *, now=NOW):
    return stack.flow.approve(rollback.action_id, rollback.proposal_hash[:12], "bob", now=now)


@pytest.mark.parametrize("action_type", ["hold_promotion", "lift_promotion_hold"])
def test_rollback_restores_exact_prior_state_and_is_audited(stack, action_type):
    before = None if action_type == "hold_promotion" else "bantis-hold incident=older action=act_old"
    if before is not None:
        stack.github.variables[HOLD_VARIABLE] = before
    source = execute(stack, action_type)
    writes = len(stack.github.writes())
    rollback = request(stack, source)
    assert len(stack.github.writes()) == writes
    assert stack.flow.run_automatic(rollback.action_id, now=NOW).status == Status.AWAITING_APPROVAL
    assert len(stack.github.writes()) == writes
    outcome = approve(stack, rollback)
    assert outcome.status == Status.SUCCEEDED, outcome.reasons
    assert outcome.detail["rollback_of"] == source.action_id
    assert stack.github.variables.get(HOLD_VARIABLE) == before
    assert len(stack.github.writes()) == writes + 1
    history = stack.store.history(rollback.action_id)
    assert history[0]["rollback_of"] == source.action_id
    assert history[0]["reason"] == "false positive"
    assert next(e for e in history if e["event"] == "verified")["verified"] is True
    assert TOKEN not in str(stack.store.audit())
    stack.store.verify()


def test_snapshot_is_durable_before_any_external_effect(stack):
    client = stack.registry.get("hold_promotion")._client
    create = client.create

    def checked_create(name, value):
        snapshot = next(e for e in stack.store.audit() if e["event"] == "rollback_prepared")
        assert snapshot["state"]["detail"]["before"] is None
        assert snapshot["state"]["detail"]["target"] == client.target
        return create(name, value)

    client.create = checked_create
    execute(stack)


def test_snapshot_write_failure_prevents_the_effect(stack, monkeypatch):
    record = stack.store.record

    def broken(entry):
        if entry["event"] == "rollback_prepared":
            raise OSError("disk full")
        return record(entry)

    monkeypatch.setattr(stack.store, "record", broken)
    source = proposal(params={}, policy_rule="A3:composite-success")
    stack.flow.submit(source, now=NOW)
    outcome = stack.flow.run_automatic(source.action_id, now=NOW)
    assert outcome.status == Status.REFUSED
    assert stack.github.writes() == []
    assert read_state(stack.config.state_dir).level == Level.EXECUTION_OFF


def test_failed_partial_execution_can_be_rolled_back(stack, monkeypatch):
    action = stack.registry.get("hold_promotion")
    run = action.execute

    def partial(*args):
        run(*args)
        raise RuntimeError("connection lost after writing")

    monkeypatch.setattr(action, "execute", partial)
    source = proposal(params={}, policy_rule="A3:composite-success")
    stack.flow.submit(source, now=NOW)
    assert stack.flow.run_automatic(source.action_id, now=NOW).status == Status.FAILED
    assert stack.github.variables[HOLD_VARIABLE] == hold_value(source)
    # Simulate an operator restoring execution permission after investigating.
    (stack.config.state_dir / TRIPWIRE_FILE).unlink()
    clear_switch(stack.config.state_dir)
    assert approve(stack, request(stack, source)).status == Status.SUCCEEDED
    assert stack.github.variables == {}


def test_restarts_and_repeated_requests_never_replay_a_rollback(stack):
    source = execute(stack)
    rollback = request(stack, source)
    assert request(stack, source).action_id == rollback.action_id
    with closing(ReviewStore(stack.config.state_dir / "reviews.sqlite3")) as restarted:
        registry = build_registry(stack.env, store=restarted)
        flow = ApprovalFlow(restarted, Executor(registry, stack.config, restarted), registry)
        assert flow.approve(rollback.action_id, rollback.proposal_hash[:12], "bob", now=NOW).status == Status.SUCCEEDED
        writes = len(stack.github.writes())
        with pytest.raises(ReviewError, match="closed"):
            flow.approve(rollback.action_id, rollback.proposal_hash[:12], "bob", now=NOW)
        with pytest.raises(ReviewError, match="already attempted"):
            request(stack, source)
        assert len(stack.github.writes()) == writes


@pytest.mark.parametrize("mode", ["dry_run", "disabled", "kill", "drift", "target"])
def test_rollback_respects_execution_guards(stack, mode):
    source = execute(stack)
    rollback = request(stack, source)
    config = stack.config
    expected = Status.INVALIDATED
    if mode == "dry_run":
        config = replace(config, dry_run=True)
        expected = Status.DRY_RUN
    elif mode == "disabled":
        config = replace(config, enabled_actions=frozenset({"hold_promotion"}))
        expected = Status.REFUSED
    elif mode == "kill":
        engage(config.state_dir, Level.EXECUTION_OFF, "stop", "operator")
    elif mode == "drift":
        stack.github.variables[HOLD_VARIABLE] = "another operator's hold"
    else:
        client = stack.registry.get("hold_promotion")._client
        client.repo = "different/repository"
    stack.flow.executor = Executor(stack.registry, config, stack.store)
    writes = len(stack.github.writes())
    outcome = approve(stack, rollback)
    assert outcome.status == expected, outcome.reasons
    assert len(stack.github.writes()) == writes


def test_expired_original_can_be_rolled_back_with_a_fresh_review_window(stack):
    source = execute(stack)
    later = NOW + timedelta(days=2)
    rollback = request(stack, source, now=later)
    assert rollback.created_at == later
    assert approve(stack, rollback, now=later).status == Status.SUCCEEDED


def test_no_effect_when_the_target_was_already_restored(stack):
    source = execute(stack)
    rollback = request(stack, source)
    stack.github.variables.clear()
    writes = len(stack.github.writes())
    assert approve(stack, rollback).status == Status.SUCCEEDED
    assert len(stack.github.writes()) == writes


def test_a_failed_rollback_trips_the_switch(stack):
    source = execute(stack)
    rollback = request(stack, source)
    stack.github.drop_deletes = True
    assert approve(stack, rollback).status == Status.FAILED
    assert read_state(stack.config.state_dir).level == Level.EXECUTION_OFF
    with pytest.raises(ReviewError, match="already attempted"):
        request(stack, source)


def test_legacy_or_unexecuted_actions_cannot_be_rolled_back(stack):
    source = proposal(params={})
    stack.flow.submit(source, now=NOW)
    with pytest.raises(ValueError, match="no recorded execution"):
        request(stack, source)
    stack.store.record({"action_id": source.action_id, "event": "executing", "attempt_id": "legacy",
                        "proposal": source.model_dump(mode="json"), "proposal_hash": source.proposal_hash})
    with pytest.raises(ValueError, match="no recorded rollback state"):
        request(stack, source)


def test_mismatched_hash_or_corrupt_audit_cannot_queue_a_rollback(stack):
    source = execute(stack)
    with pytest.raises(ReviewError, match="hash does not match"):
        stack.flow.rollback(source.action_id, "0" * 12, "alice", "test", now=NOW)
    stack.store.db.execute("UPDATE events SET payload = '{}' WHERE sequence = 1")
    with pytest.raises(ReviewError, match="integrity"):
        request(stack, source)


def test_manual_proposal_cannot_bypass_rollback_deduplication(stack):
    source = execute(stack)
    rollback = request(stack, source)
    assert approve(stack, rollback).status == Status.SUCCEEDED
    forged = Proposal(incident_id=source.incident_id, type="rollback_action", params=rollback.params,
                      policy_rule="B:manual", created_at=T0, expires_at=T0 + timedelta(hours=1))
    stack.flow.submit(forged, now=NOW)
    writes = len(stack.github.writes())
    assert approve(stack, forged).status == Status.INVALIDATED
    assert len(stack.github.writes()) == writes


def test_rollback_of_a_rollback_restores_the_original_effect(stack):
    source = execute(stack)
    rollback = request(stack, source)
    assert approve(stack, rollback).status == Status.SUCCEEDED
    redo = request(stack, rollback)
    assert approve(stack, redo).status == Status.SUCCEEDED
    assert stack.github.variables[HOLD_VARIABLE] == hold_value(source)


def test_rollback_keeps_the_original_number_of_approvals(stack):
    source = proposal(params={}, required_approvals=2)
    stack.flow.submit(source, now=NOW)
    assert stack.flow.approve(source.action_id, source.proposal_hash[:12], "alice", now=NOW).status == Status.AWAITING_APPROVAL
    assert stack.flow.approve(source.action_id, source.proposal_hash[:12], "bob", now=NOW).status == Status.SUCCEEDED
    rollback = request(stack, source)
    assert rollback.required_approvals == 2
    assert approve(stack, rollback).status == Status.AWAITING_APPROVAL
    assert stack.github.variables[HOLD_VARIABLE] == hold_value(source)
    assert stack.flow.approve(rollback.action_id, rollback.proposal_hash[:12], "carol", now=NOW).status == Status.SUCCEEDED


@pytest.mark.parametrize("closed", ["dismissed", "expired", "dry_run"])
def test_unexecuted_rollback_can_be_requested_again(stack, closed):
    source = execute(stack)
    rollback = request(stack, source)
    later = NOW
    if closed == "dismissed":
        stack.flow.dismiss(rollback.action_id, rollback.proposal_hash[:12], "alice", "reconsider", now=NOW)
    elif closed == "expired":
        later = NOW + timedelta(hours=2)
    else:
        stack.flow.executor = Executor(stack.registry, replace(stack.config, dry_run=True), stack.store)
        assert approve(stack, rollback).status == Status.DRY_RUN
    replacement = request(stack, source, now=later)
    assert replacement.action_id != rollback.action_id
    assert len(stack.github.writes()) == 1


def test_rollback_proposals_cannot_change_their_source(stack):
    rollback = request(stack, execute(stack))
    with pytest.raises(ReviewError, match="cannot be modified"):
        stack.flow.modify(rollback.action_id, rollback.proposal_hash[:12], "alice", rollback.params,
                          "change source", now=NOW)


@pytest.mark.parametrize("action_type", ["hold_promotion", "lift_promotion_hold"])
def test_state_drift_after_snapshot_blocks_the_original_write(stack, monkeypatch, action_type):
    if action_type == "lift_promotion_hold":
        stack.github.variables[HOLD_VARIABLE] = "original hold"
    source = proposal(action_type, params={})
    stack.flow.submit(source, now=NOW)
    record = stack.store.record

    def mutate_after_snapshot(entry):
        record(entry)
        if entry["event"] == "rollback_prepared":
            stack.github.variables[HOLD_VARIABLE] = "a different hold"

    monkeypatch.setattr(stack.store, "record", mutate_after_snapshot)
    assert stack.flow.approve(source.action_id, source.proposal_hash[:12], "alice", now=NOW).status == Status.FAILED
    assert stack.github.variables[HOLD_VARIABLE] == "a different hold"
    assert stack.github.writes() == []


def test_state_drift_after_rollback_snapshot_blocks_compensation(stack, monkeypatch):
    rollback = request(stack, execute(stack))
    record = stack.store.record

    def mutate_after_snapshot(entry):
        record(entry)
        if entry["event"] == "rollback_prepared":
            stack.github.variables[HOLD_VARIABLE] = "a different hold"

    monkeypatch.setattr(stack.store, "record", mutate_after_snapshot)
    writes = len(stack.github.writes())
    assert approve(stack, rollback).status == Status.FAILED
    assert stack.github.variables[HOLD_VARIABLE] == "a different hold"
    assert len(stack.github.writes()) == writes


def test_concurrent_requests_queue_only_one_rollback(stack):
    source = execute(stack)

    def queue(actor):
        with closing(ReviewStore(stack.config.state_dir / "reviews.sqlite3")) as store:
            registry = build_registry(stack.env, store=store)
            flow = ApprovalFlow(store, Executor(registry, stack.config, store), registry)
            return flow.rollback(source.action_id, source.proposal_hash[:12], actor, "reviewed", now=NOW).action_id

    with ThreadPoolExecutor(max_workers=2) as pool:
        ids = list(pool.map(queue, ["alice", "bob"]))
    assert ids[0] == ids[1]
    assert len(stack.github.writes()) == 1