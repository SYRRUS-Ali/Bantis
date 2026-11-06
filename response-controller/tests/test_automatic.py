from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import timedelta

import pytest
from helpers import FakeAction, approve, clear_switch, make, proposal
from test_executor import NOW

from approval_flow import ApprovalFlow, ReviewError, ReviewStore
from automatic import AutomaticDuplicate, AutomaticLimit
from config import ConfigError, ControllerConfig, from_env
from executor import Executor
from kill_switch import Level, engage, read_state
from models import Status
from registry import ActionRegistry


def build(state_dir, *, maximum=5, action=None, dry_run=False, automatic=True):
    action = action or FakeAction()
    registry = ActionRegistry()
    registry.register(action)
    config = ControllerConfig(
        state_dir=state_dir, enabled_actions=frozenset({action.type}), dry_run=dry_run,
        automatic_action="hold_promotion" if automatic else "",
        automatic_repo="test/repo" if automatic else "", automatic_policy_rule="A3:test",
        automatic_max_per_hour=maximum,
    )
    store = ReviewStore(state_dir / "reviews.sqlite3")
    return Executor(registry, config, store), store, action, registry


def test_automatic_execution_is_disabled_by_default(tmp_path):
    clear_switch(tmp_path)
    executor, recorder = make(tmp_path, [FakeAction()], automatic=False)
    p = proposal()
    assert executor.run(p, now=NOW).status == Status.AWAITING_APPROVAL
    assert not any(e["event"] == "executing" for e in recorder.entries)
    assert executor.run(p, [approve(p)], now=NOW).status == Status.SUCCEEDED


def test_environment_enables_exactly_one_scoped_action(tmp_path):
    config = from_env({"BANTIS_STATE_DIR": str(tmp_path), "RESPONSE_ENABLED_ACTIONS": "hold_promotion",
                       "RESPONSE_AUTO_ACTION": "hold_promotion", "RESPONSE_AUTO_REPO": "test/repo"})
    assert config.automatic_action == "hold_promotion" and config.automatic_repo == "test/repo"
    assert config.automatic_policy_rule == "A3:composite-success" and config.dry_run
    assert config.automatic_max_per_hour == 5


@pytest.mark.parametrize("settings", [
    {"RESPONSE_AUTO_ACTION": "block_client_ip"},
    {"RESPONSE_AUTO_ACTION": "hold_promotion,notify_channel"},
    {"RESPONSE_AUTO_ACTION": "notify_channel"},
    {"RESPONSE_AUTO_REPO": ""},
    {"RESPONSE_AUTO_REPO": "owner/*"},
    {"RESPONSE_AUTO_REPO": "owner/repo/extra"},
    {"RESPONSE_ENABLED_ACTIONS": ""},
    {"RESPONSE_AUTO_POLICY_RULE": " "},
    {"RESPONSE_AUTO_MAX_PER_HOUR": "0"},
    {"RESPONSE_AUTO_MAX_PER_HOUR": "6"},
    {"RESPONSE_AUTO_MAX_PER_HOUR": "unlimited"},
    {"RESPONSE_AUTO_MAX_PER_HOUR": "1.5"},
    {"RESPONSE_AUTO_ACTION": ""},
])
def test_invalid_automatic_configuration_fails_closed(tmp_path, settings):
    env = {"BANTIS_STATE_DIR": str(tmp_path), "RESPONSE_ENABLED_ACTIONS": "hold_promotion",
           "RESPONSE_AUTO_ACTION": "hold_promotion", "RESPONSE_AUTO_REPO": "test/repo", **settings}
    with pytest.raises(ConfigError):
        from_env(env)


@pytest.mark.parametrize("changed", [
    {"automatic_repo": "other/repo"}, {"automatic_policy_rule": "another-rule"},
])
def test_out_of_scope_proposals_require_approval(tmp_path, changed):
    clear_switch(tmp_path)
    executor, store, action, registry = build(tmp_path)
    with closing(store):
        executor = Executor(registry, replace(executor._config, **changed), store)
        assert executor.run(proposal(), now=NOW).status == Status.AWAITING_APPROVAL
        assert action.done_steps == []
        assert not any(e["event"] == "automatic_reserved" for e in store.audit())


@pytest.mark.parametrize("action_type", ["notify_channel", "preserve_evidence", "block_client_ip", "lift_promotion_hold"])
def test_other_enabled_actions_still_require_manual_approval(tmp_path, action_type):
    clear_switch(tmp_path)
    selected, other = FakeAction(), FakeAction(action_type)
    executor, _ = make(tmp_path, [selected, other])
    assert executor.run(proposal(action_type), now=NOW).status == Status.AWAITING_APPROVAL
    assert other.done_steps == []


def test_partial_manual_approvals_cannot_fall_back_to_automatic_mode(tmp_path):
    clear_switch(tmp_path)
    executor, _ = make(tmp_path, [FakeAction()])
    p = proposal(required_approvals=2)
    assert executor.run(p, [approve(p)], now=NOW).status == Status.AWAITING_APPROVAL
    assert executor.run(p, now=NOW).status == Status.AWAITING_APPROVAL


def test_automatic_reservations_survive_restart_and_prevent_incident_replays(tmp_path):
    clear_switch(tmp_path)
    executor, store, action, _ = build(tmp_path)
    with closing(store):
        p = proposal()
        assert executor.run(p, now=NOW).status == Status.SUCCEEDED
        reservation = next(e for e in store.audit() if e["event"] == "automatic_reserved")
        assert reservation["scope"] == "test/repo"
        assert reservation["proposal_hash"] == p.proposal_hash
    executor, store, action, _ = build(tmp_path)
    with closing(store):
        assert executor.run(proposal(), now=NOW).status == Status.INVALIDATED
        assert action.done_steps == []
        assert read_state(tmp_path).level == Level.CLEAR


def test_hourly_limit_survives_restart_and_trips_auto_off(tmp_path):
    clear_switch(tmp_path)
    executor, store, _, _ = build(tmp_path, maximum=1)
    with closing(store):
        assert executor.run(proposal(incident_id="first"), now=NOW).status == Status.SUCCEEDED
    executor, store, action, _ = build(tmp_path, maximum=1)
    with closing(store):
        p = proposal(incident_id="second")
        outcome = executor.run(p, now=NOW)
        assert outcome.status == Status.AWAITING_APPROVAL and "limit reached" in outcome.reasons[0]
        assert action.done_steps == []
        assert read_state(tmp_path).level == Level.AUTO_OFF
        assert any(e["event"] == "kill_switch_tripped" and e["level"] == "auto-off" for e in store.audit())
        assert executor.run(p, [approve(p)], now=NOW).status == Status.SUCCEEDED


def reservation(number, *, when=NOW, incident=None):
    return {"event": "automatic_reserved", "action_id": f"act_{number}",
            "incident_id": incident or f"inc_{number}", "reserved_at": when.isoformat()}


def test_budget_uses_a_rolling_hour_and_counts_future_reservations(tmp_path):
    with closing(ReviewStore(tmp_path / "reviews.sqlite3")) as store:
        store.reserve_automatic(reservation(1), 1)
        with pytest.raises(AutomaticLimit):
            store.reserve_automatic(reservation(2, when=NOW + timedelta(minutes=59)), 1)
        with pytest.raises(AutomaticLimit):
            store.reserve_automatic(reservation(2, when=NOW - timedelta(minutes=10)), 1)
        store.reserve_automatic(reservation(2, when=NOW + timedelta(hours=1)), 1)
        assert len(store.audit()) == 2


@pytest.mark.parametrize("same_incident", [False, True])
def test_concurrent_connections_cannot_overbook_the_budget_or_incident(tmp_path, same_incident):
    path = tmp_path / "reviews.sqlite3"
    with closing(ReviewStore(path)):
        pass

    def reserve(number):
        with closing(ReviewStore(path)) as store:
            try:
                store.reserve_automatic(reservation(number, incident="shared" if same_incident else None), 1)
                return "reserved"
            except (AutomaticLimit, AutomaticDuplicate):
                return "blocked"

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(reserve, range(8)))
    assert results.count("reserved") == 1
    with closing(ReviewStore(path)) as store:
        assert store.verify()["count"] == 1


def test_dry_run_does_not_consume_an_automatic_slot(tmp_path):
    clear_switch(tmp_path)
    executor, store, action, _ = build(tmp_path, dry_run=True)
    with closing(store):
        assert executor.run(proposal(), now=NOW).status == Status.DRY_RUN
        assert not any(e["event"] == "automatic_reserved" for e in store.audit())
        assert action.done_steps == []


def test_failed_reservation_prevents_execution_and_trips_the_switch(tmp_path, monkeypatch):
    clear_switch(tmp_path)
    executor, store, action, _ = build(tmp_path)
    with closing(store):
        def fail(*args):
            raise OSError("disk full")
        monkeypatch.setattr(store, "reserve_automatic", fail)
        assert executor.run(proposal(), now=NOW).status == Status.REFUSED
        assert action.done_steps == []
        assert read_state(tmp_path).level == Level.EXECUTION_OFF


def test_crash_after_reservation_never_retries_the_incident(tmp_path):
    clear_switch(tmp_path)
    p = proposal()
    executor, store, _, _ = build(tmp_path)
    with closing(store):
        store.reserve_automatic({**reservation(1, incident=p.incident_id), "action_id": p.action_id}, 5)
    executor, store, action, _ = build(tmp_path)
    with closing(store):
        assert executor.run(p, now=NOW).status == Status.INVALIDATED
        assert action.done_steps == []


@pytest.mark.parametrize("level", [Level.AUTO_OFF, Level.EXECUTION_OFF])
def test_kill_switch_prevents_automatic_reservation(tmp_path, level):
    engage(tmp_path, level, "drill", "operator")
    executor, store, action, _ = build(tmp_path)
    with closing(store):
        assert executor.run(proposal(), now=NOW).status in {Status.AWAITING_APPROVAL, Status.INVALIDATED}
        assert not any(e["event"] == "automatic_reserved" for e in store.audit())
        assert action.done_steps == []


def test_automatic_flow_does_not_reuse_pending_manual_approvals(tmp_path):
    clear_switch(tmp_path)
    executor, store, action, registry = build(tmp_path)
    with closing(store):
        flow = ApprovalFlow(store, executor, registry)
        p = flow.submit(proposal(required_approvals=2), now=NOW)
        flow.approve(p.action_id, p.proposal_hash, "alice", now=NOW)
        with pytest.raises(ReviewError, match="manual approvals"):
            flow.run_automatic(p.action_id, now=NOW)
        assert action.done_steps == []


def test_concurrent_runners_execute_only_one_action_with_a_one_attempt_budget(tmp_path):
    clear_switch(tmp_path)
    action = FakeAction()
    executor, store, _, registry = build(tmp_path, maximum=1, action=action)
    with closing(store):
        flow = ApprovalFlow(store, executor, registry)
        proposals = [flow.submit(proposal(incident_id=f"inc-{n}"), now=NOW) for n in range(4)]

    def run(p):
        executor, store, _, registry = build(tmp_path, maximum=1, action=action)
        with closing(store):
            return ApprovalFlow(store, executor, registry).run_automatic(p.action_id, now=NOW).status

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(run, proposals))
    assert results.count(Status.SUCCEEDED) == 1
    assert results.count(Status.AWAITING_APPROVAL) == 3
    assert action.done_steps == [1, 2]


def test_sixth_automatic_attempt_exceeds_the_hard_hourly_cap(tmp_path):
    clear_switch(tmp_path)
    executor, store, action, _ = build(tmp_path)
    with closing(store):
        for n in range(5):
            assert executor.run(proposal(incident_id=f"inc-{n}"), now=NOW).status == Status.SUCCEEDED
        assert executor.run(proposal(incident_id="sixth"), now=NOW).status == Status.AWAITING_APPROVAL
        assert len(action.done_steps) == 10
        assert read_state(tmp_path).level == Level.AUTO_OFF


def test_precondition_failure_does_not_consume_an_automatic_slot(tmp_path):
    clear_switch(tmp_path)
    executor, store, action, _ = build(tmp_path)
    action.blockers = ["an existing promotion hold is active"]
    with closing(store):
        assert executor.run(proposal(), now=NOW).status == Status.INVALIDATED
        assert not any(e["event"] == "automatic_reserved" for e in store.audit())
        assert action.done_steps == []