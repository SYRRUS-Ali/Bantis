import json
import sqlite3
import threading
from datetime import datetime, timezone

import pytest

from decision_log import DecisionLog, DecisionRecord, main
from models import (
    AnalysisTrace,
    AttemptRecord,
    CopilotRequest,
    CopilotResponse,
    EvidenceEntry,
    IncidentPayload,
    ProposedAction,
)

_NOW = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)


def _request(incident_id="inc-1") -> CopilotRequest:
    return CopilotRequest(
        incident=IncidentPayload(
            incident_id=incident_id, created_at=_NOW, pattern="composite-dependency-secret", window_seconds=300,
            correlated_event_ids=["dep-1"], mitre_techniques=["T1195.001"], severity="high", confidence=0.6,
            summary="s",
        ),
        evidence_timeline=[
            EvidenceEntry(
                event_id="dep-1", timestamp=_NOW, source="attack-sim", event_type="attack_scenario_run",
                scenario="malicious-dependency", status="failure", mitre_technique="T1195.001",
                summary_fields={"artifact": "fake==0.0.0"},
            )
        ],
    )


def _record(incident_id="inc-1", action="flag_for_review") -> DecisionRecord:
    response = CopilotResponse(
        incident_id=incident_id, reasoning="two defended attempts", confidence=0.7,
        proposed_action=ProposedAction(type=action, description="d"), model="claude-test", generated_at=_NOW,
    )
    trace = AnalysisTrace(
        response=response,
        attempts=[
            AttemptRecord(number=1, raw_output="I think...", error="the response did not contain a JSON object",
                          stop_reason="end_turn", input_tokens=900, output_tokens=60),
            AttemptRecord(number=2, raw_output='{"reasoning": "two defended attempts"}', stop_reason="end_turn",
                          input_tokens=1000, output_tokens=80),
        ],
        system_prompt="You are Bantis's AI Copilot.",
    )
    return DecisionRecord.from_trace(incident_id, _request(incident_id), trace)


@pytest.fixture
def log(tmp_path):
    return DecisionLog(tmp_path / "decisions.db")


def _raw(log_path, sql, params=()):
    connection = sqlite3.connect(log_path)
    try:
        connection.execute(sql, params)
        connection.commit()
    finally:
        connection.close()


# ---- Recording ---------------------------------------------------------------


def test_a_decision_round_trips_with_every_attempt_and_the_exact_prompt(log):
    log.append(_record())

    [stored] = log.for_incident("inc-1")
    record = stored.record

    assert record.outcome == "flag_for_review"
    assert record.model == "claude-test"
    assert record.system_prompt == "You are Bantis's AI Copilot."
    assert record.request.incident.pattern == "composite-dependency-secret"
    assert [a.number for a in record.attempts] == [1, 2]
    assert record.attempts[0].error == "the response did not contain a JSON object"  # the rejected one is kept
    assert record.attempts[0].raw_output == "I think..."
    assert record.attempts[1].output_tokens == 80
    assert record.response.reasoning == "two defended attempts"


def test_decisions_survive_reopening_the_file(tmp_path):
    DecisionLog(tmp_path / "decisions.db").append(_record())

    reopened = DecisionLog(tmp_path / "decisions.db")

    assert reopened.has_incident("inc-1")
    assert len(reopened.for_incident("inc-1")) == 1


def test_has_incident_and_for_incident_are_scoped_to_one_incident(log):
    log.append(_record("inc-1"))
    log.append(_record("inc-2"))

    assert log.has_incident("inc-1") and log.has_incident("inc-2")
    assert not log.has_incident("inc-3")
    assert [d.record.incident_id for d in log.for_incident("inc-2")] == ["inc-2"]


def test_a_decision_without_a_provider_call_is_recorded_too(log):
    response = CopilotResponse.analysis_failed("inc-1", "none (not sent to a provider)", "events missing")
    log.append(DecisionRecord.without_provider_call("inc-1", None, response, "evidence incomplete"))

    [stored] = log.for_incident("inc-1")
    assert stored.record.outcome == "analysis_failed"
    assert stored.record.attempts == []
    assert stored.record.note == "evidence incomplete"


# ---- Integrity ---------------------------------------------------------------


def test_an_untouched_chain_verifies(log):
    for n in range(5):
        log.append(_record(f"inc-{n}"))

    assert log.verify() == []


def test_each_record_chains_from_the_one_before_it(log):
    first = log.append(_record("inc-1"))
    second = log.append(_record("inc-2"))

    assert first.prev_hash == "0" * 64
    assert second.prev_hash == first.record_hash


def test_editing_a_stored_decision_is_detected(log, tmp_path):
    """The case an audit log exists for: someone changes what the AI
    recommended after the fact (here, flag_for_review -> no_action_recommended).
    """
    log.append(_record("inc-1"))
    log.append(_record("inc-2"))
    path = tmp_path / "decisions.db"

    connection = sqlite3.connect(path)
    record_json = connection.execute("SELECT record_json FROM decisions WHERE seq = 1").fetchone()[0]
    connection.close()
    _raw(path, "UPDATE decisions SET record_json = ? WHERE seq = 1",
         (record_json.replace("flag_for_review", "no_action_recommended"),))

    problems = log.verify()

    assert problems == ["seq 1: content doesn't match its hash (the record was modified)"]


def test_deleting_a_decision_from_the_middle_is_detected(log, tmp_path):
    for n in range(3):
        log.append(_record(f"inc-{n}"))
    _raw(tmp_path / "decisions.db", "DELETE FROM decisions WHERE seq = 2")

    problems = log.verify()

    assert len(problems) == 1 and problems[0].startswith("seq 3: prev_hash doesn't match")


def test_deleting_the_newest_decision_is_not_detectable_by_the_chain_alone(log, tmp_path):
    """A documented limitation, pinned as a test so nobody assumes more
    protection than exists: removing the tail leaves a shorter chain
    that's still internally consistent. Detecting it needs the latest
    hash kept somewhere the attacker can't also write.
    """
    for n in range(3):
        log.append(_record(f"inc-{n}"))
    _raw(tmp_path / "decisions.db", "DELETE FROM decisions WHERE seq = 3")

    assert log.verify() == []


def test_concurrent_writers_never_fork_the_chain(tmp_path):
    """Two workers appending at once must not both chain from the same
    predecessor -- verify() would then report that as tampering. append()
    takes the write lock (BEGIN IMMEDIATE) before reading the tip.
    """
    path = tmp_path / "decisions.db"
    DecisionLog(path)
    barrier = threading.Barrier(8)
    errors = []

    def writer(n):
        log = DecisionLog(path)
        barrier.wait()
        try:
            for i in range(5):
                log.append(_record(f"inc-{n}-{i}"))
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    connection = sqlite3.connect(path)
    count = connection.execute("SELECT COUNT(*) FROM decisions").fetchone()[0]
    connection.close()
    assert count == 40
    assert DecisionLog(path).verify() == []


# ---- CLI ---------------------------------------------------------------------


def test_cli_show_prints_every_decision_for_an_incident(tmp_path, capsys):
    path = tmp_path / "decisions.db"
    DecisionLog(path).append(_record("inc-1"))

    assert main(["--path", str(path), "show", "inc-1"]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["record"]["incident_id"] == "inc-1"
    assert len(shown["record"]["attempts"]) == 2


def test_cli_show_fails_for_an_unknown_incident(tmp_path, capsys):
    assert main(["--path", str(tmp_path / "decisions.db"), "show", "nope"]) == 1


def test_cli_verify_exits_nonzero_when_tampered(tmp_path, capsys):
    path = tmp_path / "decisions.db"
    DecisionLog(path).append(_record("inc-1"))
    assert main(["--path", str(path), "verify"]) == 0

    _raw(path, "UPDATE decisions SET record_json = replace(record_json, 'claude-test', 'someone-else')")

    assert main(["--path", str(path), "verify"]) == 1
    assert "modified" in capsys.readouterr().out