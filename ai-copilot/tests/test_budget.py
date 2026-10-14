from datetime import datetime, timedelta, timezone

import pytest

from budget import TokenBudget, start_of_utc_day
from decision_log import DecisionLog, DecisionRecord, FollowupRecord, main
from models import AnalysisTrace, AttemptRecord, CopilotResponse, ProposedAction

_DAY = datetime(2026, 10, 14, tzinfo=timezone.utc)


def _attempt(n, input_tokens, output_tokens):
    return AttemptRecord(number=n, raw_output="x", input_tokens=input_tokens, output_tokens=output_tokens)


def _decision(incident_id, at, attempts):
    response = CopilotResponse(
        incident_id=incident_id, reasoning="r", confidence=0.5,
        proposed_action=ProposedAction(type="flag_for_review", description="d"), model="m", generated_at=at,
    )
    record = DecisionRecord.from_trace(incident_id, None, AnalysisTrace(response=response, attempts=attempts))
    return record.model_copy(update={"recorded_at": at})


def _followup(incident_id, at, attempts):
    return FollowupRecord(incident_id=incident_id, asked_at=at, question="q", answer="a", model="m", attempts=attempts)


@pytest.fixture
def log(tmp_path):
    return DecisionLog(tmp_path / "decisions.db")


# ---- Tracking ----------------------------------------------------------------


def test_usage_adds_up_analyses_and_followups(log):
    log.append(_decision("inc-1", _DAY + timedelta(hours=1), [_attempt(1, 1000, 200), _attempt(2, 1100, 150)]))
    log.append_followup(_followup("inc-1", _DAY + timedelta(hours=2), [_attempt(1, 800, 100)]))

    used = log.token_usage_between(_DAY, _DAY + timedelta(days=1))

    assert (used.input_tokens, used.output_tokens, used.calls) == (2900, 450, 3)
    assert used.total_tokens == 3350


def test_usage_respects_the_time_range(log):
    log.append(_decision("yesterday", _DAY - timedelta(minutes=1), [_attempt(1, 999, 1)]))
    log.append(_decision("today", _DAY, [_attempt(1, 100, 10)]))
    log.append(_decision("tomorrow", _DAY + timedelta(days=1), [_attempt(1, 999, 1)]))

    assert log.token_usage_between(_DAY, _DAY + timedelta(days=1)).total_tokens == 110


def test_an_attempt_without_usage_is_not_counted_as_a_billed_call(log):
    """A connection error never got a reply: no usage, not billed."""
    failed = AttemptRecord(number=1, raw_output="", error="provider error: refused")
    log.append(_decision("inc-1", _DAY, [failed]))

    used = log.token_usage_between(_DAY)

    assert (used.calls, used.total_tokens) == (0, 0)


def test_skips_and_no_call_decisions_cost_nothing(log):
    log.append(DecisionRecord.skipped("skipped", "not correlated").model_copy(update={"recorded_at": _DAY}))

    assert log.token_usage_between(_DAY).total_tokens == 0


def test_cli_usage_prints_daily_totals(log, tmp_path, capsys):
    now = datetime.now(timezone.utc)
    log.append(_decision("inc-1", now, [_attempt(1, 1234, 56)]))

    assert main(["--path", str(tmp_path / "decisions.db"), "usage", "--days", "2"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].split() == ["day", "(UTC)", "calls", "input", "output", "total"]
    assert lines[-1].split() == [now.date().isoformat(), "1", "1,234", "56", "1,290"]
    assert lines[-2].split()[1:] == ["0", "0", "0", "0"]


# ---- The guard ---------------------------------------------------------------


def test_the_budget_is_exhausted_at_the_limit(log):
    clock = lambda: _DAY + timedelta(hours=12)  # noqa: E731
    log.append(_decision("inc-1", _DAY + timedelta(hours=1), [_attempt(1, 900, 99)]))

    assert TokenBudget(1000, log, clock).status().exhausted is False
    assert TokenBudget(1000, log, clock).status().remaining == 1

    log.append_followup(_followup("inc-1", _DAY + timedelta(hours=2), [_attempt(1, 1, 0)]))

    status = TokenBudget(1000, log, clock).status()
    assert status.exhausted is True
    assert status.remaining == 0


def test_the_budget_resets_at_utc_midnight(log):
    log.append(_decision("inc-1", _DAY + timedelta(hours=23), [_attempt(1, 5000, 0)]))

    late = TokenBudget(1000, log, lambda: _DAY + timedelta(hours=23, minutes=59, seconds=30)).status()
    next_day = TokenBudget(1000, log, lambda: _DAY + timedelta(days=1, seconds=1)).status()

    assert late.exhausted is True
    assert late.resets_at == _DAY + timedelta(days=1)
    assert late.seconds_until_reset == 31
    assert next_day.exhausted is False
    assert next_day.used.total_tokens == 0


def test_no_budget_never_exhausts(log):
    log.append(_decision("inc-1", _DAY, [_attempt(1, 10**9, 0)]))

    status = TokenBudget(None, log, lambda: _DAY).status()

    assert status.exhausted is False
    assert status.remaining is None


@pytest.mark.parametrize("limit", [0, -5])
def test_a_nonsensical_budget_is_refused(limit):
    with pytest.raises(ValueError, match="at least 1"):
        TokenBudget(limit)


def test_without_a_log_usage_is_counted_in_memory():
    budget = TokenBudget(1000, None, lambda: _DAY)

    budget.record([_attempt(1, 600, 100), AttemptRecord(number=2, raw_output="", error="refused")])

    status = budget.status()
    assert (status.used.total_tokens, status.used.calls) == (700, 1)


def test_start_of_utc_day_converts_other_timezones():
    tokyo = timezone(timedelta(hours=9))

    assert start_of_utc_day(datetime(2026, 10, 15, 3, 0, tzinfo=tokyo)) == _DAY