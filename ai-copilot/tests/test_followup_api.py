from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from api import HISTORY_TURNS, create_app
from decision_log import DecisionLog, DecisionRecord
from models import (
    AnalysisTrace,
    AttemptRecord,
    CopilotRequest,
    CopilotResponse,
    EvidenceEntry,
    FollowupTrace,
    IncidentPayload,
    ProposedAction,
)
from providers.base import AIProvider

_TOKEN = "test-token-0123456789abcdef"
_AUTH = {"Authorization": f"Bearer {_TOKEN}"}
_NOW = datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc)


def _request(incident_id: str) -> CopilotRequest:
    return CopilotRequest(
        incident=IncidentPayload(
            incident_id=incident_id, created_at=_NOW, pattern="composite-dependency-secret", window_seconds=300,
            correlated_event_ids=["dep-1", "sec-1"], mitre_techniques=["T1195.001", "T1552.001"],
            severity="high", confidence=0.6, summary="malicious-dependency + leaked-secret within 300s",
        ),
        evidence_timeline=[
            EvidenceEntry(
                event_id="dep-1", timestamp=_NOW, source="attack-sim", event_type="attack_scenario_run",
                scenario="malicious-dependency", status="failure", mitre_technique="T1195.001",
                summary_fields={"artifact": "fake==0.0.0"},
            )
        ],
    )


def _analyzed(incident_id: str) -> DecisionRecord:
    response = CopilotResponse(
        incident_id=incident_id, reasoning="two defended attempts close together", confidence=0.7,
        proposed_action=ProposedAction(type="flag_for_review", description="Escalate."),
        model="claude-test", generated_at=_NOW,
    )
    trace = AnalysisTrace(response=response, attempts=[AttemptRecord(number=1, raw_output="{}")], system_prompt="p")
    return DecisionRecord.from_trace(incident_id, _request(incident_id), trace)


class FakeAsker(AIProvider):
    model = "fake-model"

    def __init__(self, fail: bool = False):
        self.calls = []
        self.fail = fail

    def analyze_traced(self, request):
        raise AssertionError("the follow-up API must never run a new analysis")

    def ask(self, request, analysis, history, question):
        self.calls.append({"request": request, "analysis": analysis, "history": history, "question": question})
        attempt = AttemptRecord(number=1, raw_output=f"answer to: {question}", input_tokens=500, output_tokens=40)
        if self.fail:
            return FollowupTrace(error="provider error: timed out", attempts=[attempt.model_copy(update={"raw_output": ""})])
        return FollowupTrace(answer=f"answer to: {question}", attempts=[attempt], system_prompt="followup prompt")


@pytest.fixture
def log(tmp_path):
    log = DecisionLog(tmp_path / "decisions.db")
    log.append(_analyzed("inc-1"))
    log.append(DecisionRecord.skipped("inc-skipped", "not correlated: 1 event(s)"))
    return log


@pytest.fixture
def provider():
    return FakeAsker()


@pytest.fixture
def client(log, provider):
    return TestClient(create_app(log, provider, _TOKEN))


def _ask(client, question, incident_id="inc-1", headers=_AUTH):
    return client.post(f"/incidents/{incident_id}/questions", json={"question": question}, headers=headers)


# ---- Authentication ------------------------------------------------------------


@pytest.mark.parametrize(
    "headers",
    [{}, {"Authorization": "Bearer wrong-token-0123456789"}, {"Authorization": _TOKEN}, {"Authorization": f"Basic {_TOKEN}"}],
    ids=["missing", "wrong-token", "no-bearer-prefix", "wrong-scheme"],
)
def test_every_question_route_requires_the_token(client, provider, headers):
    assert _ask(client, "why?", headers=headers).status_code == 401
    assert client.get("/incidents/inc-1/questions", headers=headers).status_code == 401
    assert provider.calls == []  # rejected before any paid call


def test_health_needs_no_token(client):
    assert client.get("/health").json() == {"status": "ok"}


@pytest.mark.parametrize("token", ["", "short"])
def test_the_app_refuses_a_missing_or_short_token(log, provider, token):
    with pytest.raises(ValueError, match="at least 16 characters"):
        create_app(log, provider, token)


# ---- Asking --------------------------------------------------------------------


def test_a_question_is_answered_and_recorded(client, log, provider):
    response = _ask(client, "Why flag this rather than notify?")

    assert response.status_code == 201
    body = response.json()
    assert body["answer"] == "answer to: Why flag this rather than notify?"
    assert body["model"] == "fake-model"
    assert set(body) == {"followup_id", "incident_id", "asked_at", "question", "answer", "model"}  # no action field

    [stored] = log.followups_for("inc-1")
    assert stored.question == "Why flag this rather than notify?"
    assert stored.attempts[0].output_tokens == 40
    assert stored.system_prompt == "followup prompt"
    assert log.verify() == []


def test_the_answer_is_grounded_only_in_the_recorded_request_and_analysis(client, log, provider):
    _ask(client, "What happened first?")

    [stored_decision] = log.for_incident("inc-1")
    call = provider.calls[0]
    assert call["request"] == stored_decision.record.request
    assert call["analysis"] == stored_decision.record.response


def test_asking_never_changes_the_recorded_decision(client, log):
    before = log.for_incident("inc-1")[0]

    _ask(client, "Should this be ignored instead?")

    after = log.for_incident("inc-1")
    assert len(after) == 1
    assert after[0].record_hash == before.record_hash


def test_earlier_answers_are_sent_as_history_capped(client, provider):
    for n in range(HISTORY_TURNS + 2):
        _ask(client, f"question {n}")

    last = provider.calls[-1]
    assert len(last["history"]) == HISTORY_TURNS
    assert last["history"][-1] == ("question 5", "answer to: question 5")
    assert provider.calls[1]["history"] == [("question 0", "answer to: question 0")]


def test_listing_returns_answered_questions_in_order(client):
    _ask(client, "first")
    _ask(client, "second")

    listed = client.get("/incidents/inc-1/questions", headers=_AUTH).json()

    assert [q["question"] for q in listed] == ["first", "second"]


# ---- Refusals ------------------------------------------------------------------


def test_an_unknown_incident_is_404(client, provider):
    assert _ask(client, "why?", incident_id="nope").status_code == 404
    assert client.get("/incidents/nope/questions", headers=_AUTH).status_code == 404
    assert provider.calls == []


def test_a_skipped_incident_has_nothing_to_ask_about(client, provider):
    response = _ask(client, "why?", incident_id="inc-skipped")

    assert response.status_code == 409
    assert "outcome: skipped" in response.json()["detail"]
    assert provider.calls == []


@pytest.mark.parametrize(
    "question",
    ["", "   ", "x" * 2001],
    ids=["empty", "whitespace", "too-long"],
)
def test_an_invalid_question_is_rejected(client, provider, question):
    assert _ask(client, question).status_code == 422
    assert provider.calls == []


@pytest.mark.parametrize(
    "question",
    [
        "Is AKIAFAKEBANTISATSIM1 the leaked key?",
        "Here's the key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
        "token ghp_0123456789abcdefghijklmnopqrstuvwxyzAB leaked?",
        "my key sk-ant-api03-abcdefghijklmnopqrstuvwx",
    ],
    ids=["aws-key", "private-key", "github-token", "anthropic-key"],
)
def test_a_question_containing_a_credential_is_never_sent(client, provider, log, question):
    response = _ask(client, question)

    assert response.status_code == 422
    assert "credentials are never sent" in response.text
    assert provider.calls == []
    assert log.followups_for("inc-1") == []


def test_the_hourly_question_limit_is_enforced(log, provider):
    client = TestClient(create_app(log, provider, _TOKEN, max_questions_per_hour=2))

    assert _ask(client, "one").status_code == 201
    assert _ask(client, "two").status_code == 201
    third = _ask(client, "three")

    assert third.status_code == 429
    assert third.headers["Retry-After"] == "60"
    assert len(provider.calls) == 2


def test_the_question_limit_survives_a_restart(log, provider):
    first = TestClient(create_app(log, provider, _TOKEN, max_questions_per_hour=1))
    assert _ask(first, "one").status_code == 201

    restarted = TestClient(create_app(DecisionLog(log._path), provider, _TOKEN, max_questions_per_hour=1))
    assert _ask(restarted, "two").status_code == 429


def test_a_provider_failure_is_502_and_still_recorded(log):
    provider = FakeAsker(fail=True)
    client = TestClient(create_app(log, provider, _TOKEN))

    response = _ask(client, "why?")

    assert response.status_code == 502
    [stored] = log.followups_for("inc-1")
    assert stored.answer is None and stored.error == "provider error: timed out"
    assert client.get("/incidents/inc-1/questions", headers=_AUTH).json() == []

# ---- Daily token budget ------------------------------------------------------


def _budget(log, limit, at=None):
    from budget import TokenBudget

    return TokenBudget(limit, log, (lambda: at) if at else TokenBudget.clock)


def test_an_exhausted_budget_returns_429_until_utc_midnight(log, provider):
    from datetime import timedelta

    from decision_log import FollowupRecord

    now = datetime.now(timezone.utc).replace(hour=23, minute=0, second=0, microsecond=0)
    log.append_followup(
        FollowupRecord(
            incident_id="inc-1", asked_at=now - timedelta(minutes=5), question="q", answer="a", model="m",
            attempts=[AttemptRecord(number=1, raw_output="a", input_tokens=900, output_tokens=100)],
        )
    )
    client = TestClient(create_app(log, provider, _TOKEN, budget=_budget(log, 1000, at=now)))

    response = _ask(client, "one more?")

    assert response.status_code == 429
    assert "daily token budget of 1,000 exhausted (1,000 used)" in response.json()["detail"]
    assert response.headers["Retry-After"] == str(60 * 60 + 1)
    assert provider.calls == []


def test_worker_spending_counts_against_the_question_budget(log, provider):
    """The decision log is shared: analyses and questions draw on one
    daily allowance. The fixture's analysis cost nothing (no usage), so add
    a costly one.
    """
    from decision_log import DecisionRecord as Record

    response = CopilotResponse(
        incident_id="inc-costly", reasoning="r", confidence=0.5,
        proposed_action=ProposedAction(type="flag_for_review", description="d"), model="m", generated_at=_NOW,
    )
    trace = AnalysisTrace(response=response, attempts=[AttemptRecord(number=1, raw_output="{}", input_tokens=4000, output_tokens=1000)])
    log.append(Record.from_trace("inc-costly", _request("inc-costly"), trace))
    client = TestClient(create_app(log, provider, _TOKEN, budget=_budget(log, 5000)))

    assert _ask(client, "why?").status_code == 429


def test_usage_reports_todays_spend_against_the_budget(log, provider):
    client = TestClient(create_app(log, provider, _TOKEN, budget=_budget(log, 10_000)))
    _ask(client, "first")  # FakeAsker: 500 input + 40 output

    body = client.get("/usage", headers=_AUTH).json()

    assert (body["calls"], body["input_tokens"], body["output_tokens"], body["total_tokens"]) == (1, 500, 40, 540)
    assert (body["limit"], body["remaining"]) == (10_000, 9_460)
    assert body["day"] == datetime.now(timezone.utc).date().isoformat()


def test_usage_requires_the_token(client):
    assert client.get("/usage").status_code == 401