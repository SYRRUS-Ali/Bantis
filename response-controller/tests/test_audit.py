import json
import os
import pwd
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta

import pytest
from helpers import T0, FakeAction, clear_switch, make, proposal

from approval_flow import ReviewError, ReviewStore
from cli import main
from kill_switch import Level, read_state
from models import Status

NOW = T0 + timedelta(minutes=10)


def test_execution_identity_time_and_attempt_are_preserved(tmp_path):
    clear_switch(tmp_path)
    action = FakeAction()
    executor, recorder = make(tmp_path, [action])
    p = proposal()
    before = datetime.now(UTC)
    assert executor.run(p, now=NOW, actor="alice").status == Status.SUCCEEDED
    after = datetime.now(UTC)
    entries = recorder.entries
    assert len({entry["attempt_id"] for entry in entries}) == 1
    times = [datetime.fromisoformat(entry["at"]) for entry in entries]
    assert before <= times[0] <= times[-1] <= after
    for entry in entries:
        assert entry["actor"] == pwd.getpwuid(os.getuid()).pw_name
        assert entry["initiated_by"] == "alice"
        assert entry["incident_id"] == p.incident_id
        assert entry["type"] == p.type
        assert entry["proposal_hash"] == p.proposal_hash
    assert next(e for e in entries if e["event"] == "verified")["verified"] is True
    executor.run(p, now=NOW, actor="bob")
    assert recorder.entries[-1]["status"] == "refused"
    assert recorder.entries[-1]["attempt_id"] != entries[0]["attempt_id"]


@pytest.mark.parametrize("failure", ["execution", "verification", "verification_exception", "halt"])
def test_failure_and_halt_are_audited(tmp_path, failure):
    from kill_switch import engage

    clear_switch(tmp_path)
    action = FakeAction()
    if failure == "execution":
        action.raise_on_step = 1
    elif failure == "verification":
        action.effect_in_place = False
    elif failure == "verification_exception":
        def broken(*args):
            raise RuntimeError("post-check unavailable")
        action.verify = broken
    else:
        action.on_step = lambda n: engage(tmp_path, Level.EXECUTION_OFF, "stop", "operator")
    executor, recorder = make(tmp_path, [action])
    result = executor.run(proposal(), now=NOW)
    assert result.status == (Status.INVALIDATED if failure == "halt" else Status.FAILED)
    assert recorder.entries[-1]["status"] == result.status
    assert recorder.entries[-1]["reasons"]
    if failure != "halt":
        assert any(e["event"] == "kill_switch_tripped" for e in recorder.entries)
    if failure.startswith("verification"):
        assert next(e for e in recorder.entries if e["event"] == "verified")["verified"] is False


@pytest.mark.parametrize("fail_event", ["requested", "executing", "executed", "verification_started", "verified", "outcome"])
def test_audit_write_failure_stops_or_reports_uncertain_effect(tmp_path, fail_event):
    clear_switch(tmp_path)
    action = FakeAction()
    executor, recorder = make(tmp_path, [action])
    original = recorder.record

    def record(entry):
        if entry["event"] == fail_event:
            raise OSError("disk full")
        original(entry)

    recorder.record = record
    result = executor.run(proposal(), now=NOW)
    assert result.status in {Status.REFUSED, Status.FAILED}
    assert read_state(tmp_path).level == Level.EXECUTION_OFF
    if fail_event in {"requested", "executing"}:
        assert action.done_steps == []
    else:
        assert action.done_steps == [1, 2]
    assert "could not record" in result.reasons[-1]


def event(number=1):
    return {"action_id": f"act_{number}", "event": "proposed", "actor": "alice",
            "at": datetime.now(UTC).isoformat()}


def test_journal_survives_restart_and_filters(tmp_path):
    path = tmp_path / "reviews.sqlite3"
    with closing(ReviewStore(path)) as store:
        store.record(event())
        store.record({**event(2), "actor": "service", "initiated_by": "bob"})
        checkpoint = store.verify()
    with closing(ReviewStore(path)) as store:
        assert store.verify(checkpoint["head"]) == checkpoint
        assert len(store.audit()) == 2
        assert len(store.audit(actor="bob")) == 1
        assert store.audit(actor="unknown") == []
        assert len(store.audit(action_id="act_1", actor="alice")) == 1
        assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("mutation", ["edit", "delete", "hash", "missing_hash"])
def test_corruption_is_detected_and_cannot_be_extended(tmp_path, mutation):
    path = tmp_path / "reviews.sqlite3"
    with closing(ReviewStore(path)) as store:
        for n in range(1, 4):
            store.record(event(n))
        sql = {
            "edit": "UPDATE events SET payload = '{}' WHERE sequence = 2",
            "delete": "DELETE FROM events WHERE sequence = 2",
            "hash": "UPDATE events SET previous_hash = 'bad' WHERE sequence = 2",
            "missing_hash": "UPDATE events SET entry_hash = NULL WHERE sequence = 2",
        }[mutation]
        store.db.execute(sql)
    with closing(ReviewStore(path)) as store:
        with pytest.raises(ReviewError, match="integrity"):
            store.verify()
        with pytest.raises(ReviewError, match="integrity"):
            store.record(event(4))
        with pytest.raises(ReviewError, match="integrity"):
            store.audit()


def test_trusted_checkpoint_detects_tail_deletion(tmp_path):
    with closing(ReviewStore(tmp_path / "reviews.sqlite3")) as store:
        store.record(event())
        checkpoint = store.verify()["head"]
        store.db.execute("DELETE FROM events")
        assert store.verify()["count"] == 0  # A chain alone cannot detect tail truncation.
        with pytest.raises(ReviewError, match="checkpoint"):
            store.verify(checkpoint)


def test_legacy_journal_is_baselined_without_inventing_identity_or_time(tmp_path):
    path = tmp_path / "reviews.sqlite3"
    payload = json.dumps({"action_id": "old", "event": "executing"})
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE events (sequence INTEGER PRIMARY KEY, payload TEXT NOT NULL)")
        db.execute("INSERT INTO events(payload) VALUES (?)", (payload,))
    with closing(ReviewStore(path)) as store:
        entry = store.audit()[0]
        assert "at" not in entry and "actor" not in entry
        assert store.already_executed("old")
        assert store.verify()["count"] == 1
        store.record(event())
        assert store.verify()["count"] == 2


def test_concurrent_journal_writers_do_not_fork_chain(tmp_path):
    path = tmp_path / "reviews.sqlite3"
    with closing(ReviewStore(path)):
        pass

    def append(number):
        with closing(ReviewStore(path)) as store:
            store.record(event(number))

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(append, range(20)))
    with closing(ReviewStore(path)) as store:
        assert store.verify()["count"] == 20


def test_cli_export_verify_and_checkpoint_failure(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("BANTIS_STATE_DIR", str(tmp_path))
    with closing(ReviewStore(tmp_path / "reviews.sqlite3")) as store:
        store.record(event())
    assert main(["audit", "--action-id", "act_1", "--actor", "alice"]) == 0
    exported = json.loads(capsys.readouterr().out)
    assert exported["sequence"] == 1 and exported["actor"] == "alice"
    assert main(["audit-verify"]) == 0
    checkpoint = json.loads(capsys.readouterr().out)
    assert main(["audit-verify", "--expected-head", checkpoint["head"]]) == 0
    capsys.readouterr()
    assert main(["audit-verify", "--expected-head", "0" * 64]) == 2
    assert "checkpoint" in capsys.readouterr().err


def test_kill_is_audited_and_still_works_with_a_broken_journal(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("BANTIS_STATE_DIR", str(tmp_path))
    assert main(["kill", "--reason", "drill"]) == 0
    with closing(ReviewStore(tmp_path / "reviews.sqlite3")) as store:
        assert store.audit()[0]["event"] == "kill_switch_engaged"
        store.db.execute("UPDATE events SET payload = '{}'")
    assert main(["kill", "--reason", "emergency", "--ai-off"]) == 1
    assert read_state(tmp_path).ai_off
    assert "Kill switch engaged; could not audit" in capsys.readouterr().err


def test_corrupt_journal_blocks_executor_and_trips_switch(tmp_path):
    clear_switch(tmp_path)
    action = FakeAction()
    with closing(ReviewStore(tmp_path / "reviews.sqlite3")) as store:
        store.record(event())
        store.db.execute("UPDATE events SET payload = '{}'")
        executor, _ = make(tmp_path, [action], recorder=store)
        result = executor.run(proposal(), now=NOW)
        assert result.status == Status.REFUSED
        assert action.done_steps == []
        assert read_state(tmp_path).level == Level.EXECUTION_OFF