from datetime import timedelta

import pytest
from helpers import T0, FakeAction, approve, clear_switch, make, proposal

from catalog import CATALOG
from kill_switch import Level, engage, read_state
from models import Status

NOW = T0 + timedelta(minutes=10)


@pytest.fixture
def clear(tmp_path):
    clear_switch(tmp_path)
    return tmp_path


def test_an_enabled_auto_action_runs_and_is_verified(clear):
    action = FakeAction()
    executor, recorder = make(clear, [action])

    outcome = executor.run(proposal(), now=NOW)

    assert outcome.status == Status.SUCCEEDED
    assert action.done_steps == [1, 2]
    assert [e["event"] for e in recorder.entries] == ["executing", "outcome"]


# ---- refused before anything else is considered ------------------------------


def test_a_type_outside_the_catalog_is_refused(clear):
    executor, _ = make(clear)
    outcome = executor.run(proposal("run_command"), now=NOW)
    assert outcome.status == Status.REFUSED and "catalog" in outcome.reasons[0]


def test_a_catalog_type_without_an_implementation_is_refused(clear):
    executor, _ = make(clear, enabled=["notify_channel"])
    assert executor.run(proposal("notify_channel"), now=NOW).status == Status.REFUSED


def test_a_registered_action_that_is_not_enabled_is_refused(clear):
    action = FakeAction()
    executor, _ = make(clear, [action], enabled=[])
    outcome = executor.run(proposal(), now=NOW)
    assert outcome.status == Status.REFUSED and "not enabled" in outcome.reasons[0]
    assert action.done_steps == []


@pytest.mark.parametrize("params", [{}, {"variable": 1}, {"variable": "X", "also": "this"}])
def test_parameters_that_dont_fit_the_action_exactly_are_refused(clear, params):
    action = FakeAction()
    executor, _ = make(clear, [action])
    assert executor.run(proposal(params=params), now=NOW).status == Status.REFUSED
    assert action.done_steps == []


def test_an_action_id_runs_at_most_once(clear):
    action = FakeAction()
    executor, _ = make(clear, [action])
    p = proposal()
    executor.run(p, now=NOW)
    second = executor.run(p, now=NOW)
    assert second.status == Status.REFUSED and "already executed" in second.reasons[0]
    assert action.done_steps == [1, 2]


def test_an_expired_proposal_never_runs(clear):
    action = FakeAction()
    executor, _ = make(clear, [action])
    assert executor.run(proposal(), now=T0 + timedelta(hours=1)).status == Status.EXPIRED
    assert action.done_steps == []


# ---- approvals ------------------------------------------------------------------


def test_an_approval_tier_action_waits_for_approval(clear):
    action = FakeAction("rollback_latest")
    executor, _ = make(clear, [action])
    p = proposal("rollback_latest")

    assert executor.run(p, now=NOW).status == Status.AWAITING_APPROVAL
    assert action.done_steps == []
    assert executor.run(p, [approve(p)], now=NOW).status == Status.SUCCEEDED


def test_approving_x_can_never_execute_a_changed_x(clear):
    action = FakeAction("rollback_latest")
    executor, _ = make(clear, [action])
    p = proposal("rollback_latest")
    approval = approve(p)
    changed = p.model_copy(update={"params": {"variable": "SOMETHING_ELSE"}})

    outcome = executor.run(changed, [approval], now=NOW)

    assert outcome.status == Status.REFUSED and "hash" in outcome.reasons[0]
    assert action.done_steps == []


def test_an_approval_for_another_action_is_refused_not_ignored(clear):
    action = FakeAction("rollback_latest")
    executor, _ = make(clear, [action])
    p, other = proposal("rollback_latest"), proposal("rollback_latest")
    assert executor.run(p, [approve(p), approve(other)], now=NOW).status == Status.REFUSED


@pytest.mark.parametrize("at", [T0 - timedelta(minutes=1), T0 + timedelta(hours=1)])
def test_an_approval_outside_the_proposals_window_does_not_count(clear, at):
    action = FakeAction("rollback_latest")
    executor, _ = make(clear, [action])
    p = proposal("rollback_latest")
    assert executor.run(p, [approve(p, at=at)], now=NOW).status == Status.AWAITING_APPROVAL


def test_two_person_rule_needs_two_different_approvers(clear):
    action = FakeAction("rollback_latest")
    executor, _ = make(clear, [action])
    p = proposal("rollback_latest", required_approvals=2)

    assert executor.run(p, [approve(p, "alice"), approve(p, "alice")], now=NOW).status == Status.AWAITING_APPROVAL
    assert executor.run(p, [approve(p, "alice"), approve(p, "bob")], now=NOW).status == Status.SUCCEEDED


# ---- the kill switch ------------------------------------------------------------


@pytest.mark.parametrize("action_type", sorted(CATALOG))
def test_execution_off_blocks_every_action_even_approved(tmp_path, action_type):
    engage(tmp_path, Level.EXECUTION_OFF, "drill", "op")
    action = FakeAction(action_type)
    executor, _ = make(tmp_path, [action])
    p = proposal(action_type)

    assert executor.run(p, [approve(p)], now=NOW).status == Status.INVALIDATED
    assert action.done_steps == []


def test_auto_off_turns_an_auto_action_into_one_that_needs_approval(tmp_path):
    engage(tmp_path, Level.AUTO_OFF, "policy misfiring", "op")
    action = FakeAction()
    executor, _ = make(tmp_path, [action])
    p = proposal()

    assert executor.run(p, now=NOW).status == Status.AWAITING_APPROVAL
    assert executor.run(p, [approve(p)], now=NOW).status == Status.SUCCEEDED


def test_a_missing_or_garbled_switch_blocks_execution(tmp_path):
    action = FakeAction()
    executor, _ = make(tmp_path, [action])  # no switch file at all
    assert executor.run(proposal(), now=NOW).status == Status.INVALIDATED
    (tmp_path / "kill-switch").write_text("garbage")
    assert executor.run(proposal(), now=NOW).status == Status.INVALIDATED
    assert action.done_steps == []


def test_engaging_mid_action_stops_the_next_step(clear):
    action = FakeAction(steps=3)
    action.on_step = lambda n: n == 1 and engage(clear, Level.EXECUTION_OFF, "stop now", "op")
    executor, _ = make(clear, [action])

    outcome = executor.run(proposal(), now=NOW)

    assert outcome.status == Status.INVALIDATED and "stop now" in outcome.reasons[0]
    assert action.done_steps == [1]


def test_auto_off_mid_action_stops_an_unapproved_auto_action(clear):
    action = FakeAction(steps=3)
    action.on_step = lambda n: n == 1 and engage(clear, Level.AUTO_OFF, "policy misfiring", "op")
    executor, _ = make(clear, [action])

    assert executor.run(proposal(), now=NOW).status == Status.INVALIDATED
    assert action.done_steps == [1]


# ---- failures trip the switch ---------------------------------------------------


def test_a_failed_post_check_trips_the_switch(clear):
    action = FakeAction()
    action.effect_in_place = False
    executor, _ = make(clear, [action])

    assert executor.run(proposal(), now=NOW).status == Status.FAILED
    assert read_state(clear).level == Level.EXECUTION_OFF
    assert executor.run(proposal(), now=NOW).status == Status.INVALIDATED  # nothing else runs


def test_an_action_that_raises_trips_the_switch(clear):
    action = FakeAction()
    action.raise_on_step = 2
    executor, _ = make(clear, [action])

    outcome = executor.run(proposal(), now=NOW)

    assert outcome.status == Status.FAILED and "remote API error" in outcome.reasons[0]
    assert read_state(clear).level == Level.EXECUTION_OFF


def test_unmet_preconditions_invalidate_without_acting(clear):
    action = FakeAction()
    action.blockers = ["the incident no longer exists"]
    executor, _ = make(clear, [action])

    outcome = executor.run(proposal(), now=NOW)

    assert outcome.status == Status.INVALIDATED and outcome.reasons == ["the incident no longer exists"]
    assert action.done_steps == []


class BrokenRecorder:
    def record(self, entry):
        raise OSError("disk full")

    def already_executed(self, action_id):
        return False


def test_if_it_cant_be_recorded_it_doesnt_run(clear):
    action = FakeAction()
    executor, _ = make(clear, [action], recorder=BrokenRecorder())

    outcome = executor.run(proposal(), now=NOW)

    assert outcome.status == Status.REFUSED and "could not record" in outcome.reasons[0]
    assert action.done_steps == []
    assert read_state(clear).level == Level.EXECUTION_OFF


# ---- dry run --------------------------------------------------------------------


def test_dry_run_records_the_plan_and_does_nothing(clear):
    action = FakeAction()
    executor, recorder = make(clear, [action], dry_run=True)

    p = proposal()
    outcome = executor.run(p, now=NOW)

    assert recorder.entries[0]["proposal_hash"] == p.proposal_hash
    assert outcome.status == Status.DRY_RUN and outcome.plan == "set BANTIS_PROMOTION_HOLD"
    assert action.done_steps == []
    assert [e["event"] for e in recorder.entries] == ["outcome"]


def test_dry_run_still_applies_every_check(tmp_path):
    engage(tmp_path, Level.EXECUTION_OFF, "drill", "op")
    executor, _ = make(tmp_path, [FakeAction()], dry_run=True)
    assert executor.run(proposal(), now=NOW).status == Status.INVALIDATED


def test_a_switch_engaged_after_the_checks_still_stops_an_action_that_never_checks_its_guard(clear):
    """The executor re-reads the switch itself right before execute(), so
    the window between the pre-run checks and the first step is covered
    even for an action that forgets to call guard.check()."""
    action = FakeAction()
    action.execute = lambda proposal, params, guard: action.done_steps.append("acted")
    action.preconditions = lambda proposal, params: engage(clear, Level.EXECUTION_OFF, "just now", "op") or []
    executor, _ = make(clear, [action])

    assert executor.run(proposal(), now=NOW).status == Status.INVALIDATED
    assert action.done_steps == []