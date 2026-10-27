import pytest
from fake_github import TOKEN, FakeGitHub
from helpers import approve, clear_switch, make, proposal
from test_executor import NOW

from actions.promotion_hold import (
    HOLD_MARKER,
    HOLD_VARIABLE,
    HoldPromotion,
    LiftPromotionHold,
    hold_value,
)
from executor import MemoryRecorder
from github_client import GitHubError, GitHubVariables
from kill_switch import Level, engage, read_state
from models import Status
from wiring import build_registry


@pytest.fixture
def github():
    fake = FakeGitHub()
    yield fake
    fake.close()


@pytest.fixture
def client(github):
    return GitHubVariables(github.repo, TOKEN, api_url=github.url)


@pytest.fixture
def clear(tmp_path):
    clear_switch(tmp_path)
    return tmp_path


def _hold(**kw):
    return proposal("hold_promotion", params={}, policy_rule="A3:composite-success", **kw)


def _lift():
    return proposal("lift_promotion_hold", params={}, policy_rule="B3:operator")


def _executor(state_dir, client, **kw):
    return make(state_dir, [HoldPromotion(client), LiftPromotionHold(client)], **kw)


# ---- quarantine ------------------------------------------------------------------


def test_quarantine_sets_the_hold_and_verifies_it(clear, github, client):
    executor, recorder = _executor(clear, client)
    p = _hold()

    outcome = executor.run(p, now=NOW)

    assert outcome.status == Status.SUCCEEDED, outcome.reasons
    assert github.variables == {HOLD_VARIABLE: hold_value(p)}
    assert github.variables[HOLD_VARIABLE] == f"{HOLD_MARKER} incident=inc-1 action={p.action_id}"
    assert [e["event"] for e in recorder.entries] == ["executing", "outcome"]


def test_quarantine_runs_without_approval_but_lifting_it_needs_one(clear, github, client):
    executor, _ = _executor(clear, client)
    executor.run(_hold(), now=NOW)
    lift = _lift()

    assert executor.run(lift, now=NOW).status == Status.AWAITING_APPROVAL
    assert HOLD_VARIABLE in github.variables
    assert executor.run(lift, [approve(lift)], now=NOW).status == Status.SUCCEEDED
    assert github.variables == {}


def test_a_second_hold_never_replaces_the_first(clear, github, client):
    github.variables[HOLD_VARIABLE] = "bantis-hold incident=older action=act_old"
    executor, _ = _executor(clear, client)

    outcome = executor.run(_hold(), now=NOW)

    assert outcome.status == Status.INVALIDATED and "already active" in outcome.reasons[0]
    assert github.variables[HOLD_VARIABLE] == "bantis-hold incident=older action=act_old"
    assert github.writes() == []


def test_a_hold_that_appears_mid_action_is_kept_not_overwritten(clear, github, client):
    executor, _ = _executor(clear, client)
    gets = []

    def someone_else_holds_after_the_precondition_check():
        gets.append(1)
        if len(gets) == 2:
            github.variables[HOLD_VARIABLE] = "bantis-hold incident=other action=act_other"

    github.on_get = someone_else_holds_after_the_precondition_check
    outcome = executor.run(_hold(), now=NOW)

    assert outcome.status == Status.SUCCEEDED  # the build is quarantined either way
    assert github.variables[HOLD_VARIABLE].endswith("act_other")
    assert github.writes() == []


def test_executing_twice_is_harmless(clear, github, client):
    action, p = HoldPromotion(client), _hold()

    class Guard:
        def check(self):
            pass

    action.execute(p, None, Guard())
    action.execute(p, None, Guard())

    assert github.variables == {HOLD_VARIABLE: hold_value(p)}
    assert len(github.writes()) == 1


def test_dry_run_only_reads(clear, github, client):
    executor, _ = _executor(clear, client, dry_run=True)

    outcome = executor.run(_hold(), now=NOW)

    assert outcome.status == Status.DRY_RUN and HOLD_VARIABLE in outcome.plan and github.repo in outcome.plan
    assert github.writes() == [] and github.variables == {}


def test_the_kill_switch_stops_it_before_any_request(tmp_path, github, client):
    engage(tmp_path, Level.EXECUTION_OFF, "drill", "op")
    executor, _ = _executor(tmp_path, client)

    assert executor.run(_hold(), now=NOW).status == Status.INVALIDATED
    assert github.requests == []


def test_parameters_cannot_choose_the_variable_or_repository(clear, github, client):
    executor, _ = _executor(clear, client)
    for params in ({"variable": "OTHER"}, {"repo": "attacker/repo"}, {"value": "x"}):
        assert executor.run(proposal("hold_promotion", params=params, policy_rule="A3:x"), now=NOW).status == Status.REFUSED
    assert github.requests == []


def test_an_incident_id_that_isnt_an_identifier_is_not_written(clear, github, client):
    executor, _ = _executor(clear, client)
    outcome = executor.run(_hold(incident_id="inc-1\nBANTIS_PROMOTION_HOLD="), now=NOW)
    assert outcome.status == Status.INVALIDATED
    assert github.writes() == []


# ---- failures --------------------------------------------------------------------


def test_github_unreachable_while_checking_invalidates_without_tripping(clear, github, client):
    github.fail["GET"] = 503
    executor, _ = _executor(clear, client)

    outcome = executor.run(_hold(), now=NOW)

    assert outcome.status == Status.INVALIDATED and "503" in outcome.reasons[0]
    assert read_state(clear).level == Level.CLEAR


def test_a_rejected_write_fails_and_trips_the_switch(clear, github, client):
    github.fail["POST"] = 403
    executor, _ = _executor(clear, client)

    outcome = executor.run(_hold(), now=NOW)

    assert outcome.status == Status.FAILED and "403" in outcome.reasons[0]
    assert read_state(clear).level == Level.EXECUTION_OFF


def test_a_hold_that_didnt_stick_fails_the_post_check_and_trips(clear, github, client):
    github.drop_writes = True
    executor, _ = _executor(clear, client)

    assert executor.run(_hold(), now=NOW).status == Status.FAILED
    assert read_state(clear).level == Level.EXECUTION_OFF


def test_the_token_never_appears_in_outcomes_records_or_errors(clear, github, client):
    github.fail["POST"] = 403
    recorder = MemoryRecorder()
    executor, _ = _executor(clear, client, recorder=recorder)

    outcome = executor.run(_hold(), now=NOW)

    assert TOKEN not in outcome.model_dump_json()
    assert TOKEN not in str(recorder.entries)
    assert TOKEN not in repr(client)
    with pytest.raises(GitHubError) as raised:
        client.create(HOLD_VARIABLE, "x")
    assert TOKEN not in str(raised.value)


# ---- the undo ----------------------------------------------------------------------


def test_lifting_when_nothing_is_held_does_nothing(clear, github, client):
    executor, _ = _executor(clear, client)
    lift = _lift()
    assert executor.run(lift, [approve(lift)], now=NOW).status == Status.INVALIDATED
    assert github.writes() == []


# ---- client and wiring ---------------------------------------------------------------


@pytest.mark.parametrize("url", ["http://api.github.com", "http://10.0.0.5:8080", "ftp://x"])
def test_the_token_is_never_sent_over_plain_http_off_this_machine(url):
    with pytest.raises(ValueError, match="https"):
        GitHubVariables("o/r", TOKEN, api_url=url)


@pytest.mark.parametrize("repo", ["", "noslash", "a/b/c", "o/r?x=1", "../etc"])
def test_the_repository_must_be_owner_slash_name(repo):
    with pytest.raises(ValueError):
        GitHubVariables(repo, TOKEN)


def test_variable_names_are_validated(client):
    with pytest.raises(ValueError):
        client.get("../../secrets")


def test_without_credentials_the_action_says_so_instead_of_acting(clear):
    from config import ControllerConfig
    from executor import Executor

    config = ControllerConfig(state_dir=clear, enabled_actions=frozenset({"hold_promotion"}), dry_run=False)
    executor = Executor(build_registry({}), config, MemoryRecorder())
    outcome = executor.run(_hold(), now=NOW)
    assert outcome.status == Status.INVALIDATED and "not configured" in outcome.reasons[0]


def test_a_lift_that_didnt_stick_fails_the_post_check_and_trips(clear, github, client):
    github.variables[HOLD_VARIABLE] = "bantis-hold incident=inc-1 action=act_x"
    github.drop_deletes = True
    executor, _ = _executor(clear, client)
    lift = _lift()

    assert executor.run(lift, [approve(lift)], now=NOW).status == Status.FAILED
    assert read_state(clear).level == Level.EXECUTION_OFF


def test_a_network_error_never_carries_the_token():
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]  # closed again on exit: nothing listens there
    client = GitHubVariables("o/r", TOKEN, api_url=f"http://127.0.0.1:{port}", timeout=2)

    with pytest.raises(GitHubError) as raised:
        client.get(HOLD_VARIABLE)

    assert raised.value.status == 0
    assert TOKEN not in str(raised.value)