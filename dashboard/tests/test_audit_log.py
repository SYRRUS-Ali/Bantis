import hashlib
import json
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

import httpx
import pytest
from bantis_dashboard import audit
from bantis_dashboard.audit import AuditReader
from bantis_dashboard.config import Settings
from bantis_dashboard.detection import UpstreamError
from bantis_dashboard.main import create_app
from fastapi.testclient import TestClient
from test_dashboard import ORIGIN, TOKEN, login

ROOT = Path(__file__).resolve().parents[2]


def append(path, number, **changes):
    entry = {
        "event": "outcome",
        "action_id": f"act_{number}",
        "actor": "executor",
        "initiated_by": "alice",
        "incident_id": f"inc_{number % 2}",
        "type": "notify_operator",
        "status": "dry_run",
        "at": "2026-11-10T12:00:00+03:00",
        "proposal_hash": "a" * 64,
        "reason": '<img src=x onerror="window.untrustedExecuted=true">',
        "proposal": {"params": {"token": "private-parameter"}},
        "context": {"raw_output": "private-provider-output"},
        "state": {"secret": "private-rollback-state"},
        **changes,
    }
    with closing(sqlite3.connect(path)) as db:
        db.execute(
            "CREATE TABLE IF NOT EXISTS events (sequence INTEGER PRIMARY KEY, payload TEXT NOT NULL, previous_hash TEXT, entry_hash TEXT)"
        )
        row = db.execute(
            "SELECT entry_hash FROM events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous = row[0] if row else "0" * 64
        payload = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(f"{number}\n{previous}\n{payload}".encode()).hexdigest()
        db.execute(
            "INSERT INTO events VALUES (?, ?, ?, ?)",
            (number, payload, previous, digest),
        )
        db.commit()
    return digest


@pytest.fixture
def journal(tmp_path):
    path = tmp_path / "reviews.sqlite3"
    for number in range(1, 24):
        append(path, number)
    return path


@pytest.fixture
def audit_stack(journal):
    app = create_app(
        Settings(token=TOKEN, origin=ORIGIN, audit_path=journal),
        transport=httpx.MockTransport(lambda request: httpx.Response(503)),
    )
    with TestClient(app) as client:
        yield client


def test_authenticated_read_only_boundary(audit_stack):
    client = audit_stack
    assert client.get("/audit-log").status_code == 200
    response = client.get("/api/audit-log")
    assert response.status_code == 401
    login(client)
    response = client.get("/api/audit-log")
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert client.post("/api/audit-log", json={}).status_code == 405
    assert client.delete("/api/audit-log").status_code == 405
    client.delete("/api/session")
    assert client.get("/api/audit-log").status_code == 401


def test_projection_order_and_no_writes(journal, audit_stack):
    before = journal.read_bytes()
    login(audit_stack)
    response = audit_stack.get("/api/audit-log")
    body = response.json()
    assert body["total"] == body["journal_total"] == 23
    assert [entry["sequence"] for entry in body["items"]] == list(range(23, 3, -1))
    assert body["items"][0]["at"] == "2026-11-10T09:00:00Z"
    assert body["integrity"] == "consistent"
    assert len(body["head"]) == 64
    assert "private-" not in response.text
    assert 'proposal"' not in response.text
    assert journal.read_bytes() == before
    assert not journal.with_suffix(".sqlite3.lock").exists()


def test_pagination_boundary_is_stable_across_new_entries(journal, audit_stack):
    login(audit_stack)
    first = audit_stack.get("/api/audit-log?limit=20").json()
    append(journal, 24)
    second = audit_stack.get(
        f"/api/audit-log?limit=20&offset=20&through_sequence={first['through_sequence']}"
    ).json()
    assert second["journal_total"] == 24
    assert second["total"] == 23
    assert [entry["sequence"] for entry in second["items"]] == [3, 2, 1]
    assert audit_stack.get("/api/audit-log").json()["items"][0]["sequence"] == 24


@pytest.mark.parametrize(
    "query,count",
    [
        ("actor=alice", 23),
        ("actor=executor", 23),
        ("actor=unknown", 0),
        ("event=outcome&status=dry_run", 23),
        ("action_id=act_7", 1),
        ("incident_id=inc_0", 11),
        ("event=proposed", 0),
        ("since=2026-11-10T09:00:00Z&until=2026-11-10T09:00:00Z", 23),
        ("since=2026-11-10T09:00:01Z", 0),
        ("actor=alice%27%20OR%201=1", 0),
    ],
)
def test_filters(audit_stack, query, count):
    login(audit_stack)
    response = audit_stack.get(f"/api/audit-log?{query}")
    assert response.status_code == 200
    assert response.json()["total"] == count


@pytest.mark.parametrize(
    "query",
    [
        "limit=0",
        "limit=101",
        "offset=-1",
        "offset=100001",
        "through_sequence=-1",
        "since=not-a-time",
        "actor=" + "x" * 513,
        "since=2026-11-11&until=2026-11-10",
    ],
)
def test_invalid_filters_are_rejected(audit_stack, query):
    login(audit_stack)
    assert audit_stack.get(f"/api/audit-log?{query}").status_code == 422


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE events SET payload = '{}' WHERE sequence = 2",
        "UPDATE events SET entry_hash = NULL WHERE sequence = 2",
        "UPDATE events SET previous_hash = 'wrong' WHERE sequence = 2",
        "DELETE FROM events WHERE sequence = 2",
    ],
)
def test_corruption_anywhere_blocks_filtered_results(journal, audit_stack, sql):
    with closing(sqlite3.connect(journal)) as db:
        db.execute(sql)
        db.commit()
    login(audit_stack)
    response = audit_stack.get("/api/audit-log?action_id=act_23&limit=1")
    assert response.status_code == 502
    assert "integrity check failed" in response.text
    assert "items" not in response.json()


def test_unconfigured_missing_and_legacy_journals_are_explicit(tmp_path):
    for path in (None, tmp_path / "missing.sqlite3"):
        with pytest.raises(UpstreamError) as error:
            AuditReader(path).page()
        assert error.value.status == 503
    assert not (tmp_path / "missing.sqlite3").exists()
    legacy = tmp_path / "legacy.sqlite3"
    with closing(sqlite3.connect(legacy)) as db:
        db.execute("CREATE TABLE events (sequence INTEGER PRIMARY KEY, payload TEXT)")
        db.commit()
    before = legacy.read_bytes()
    with pytest.raises(UpstreamError) as error:
        AuditReader(legacy).page()
    assert error.value.status == 503
    assert legacy.read_bytes() == before


def test_empty_journal_is_consistent(tmp_path):
    path = tmp_path / "empty.sqlite3"
    append(path, 1)
    with closing(sqlite3.connect(path)) as db:
        db.execute("DELETE FROM events")
        db.commit()
    page = AuditReader(path).page()
    assert page.total == page.journal_total == page.through_sequence == 0
    assert page.head == "0" * 64
    assert page.items == []


def test_limits_and_invalid_projection(journal, monkeypatch):
    monkeypatch.setattr(audit, "MAX_ENTRIES", 1)
    with pytest.raises(UpstreamError) as error:
        AuditReader(journal).page()
    assert error.value.status == 503
    monkeypatch.setattr(audit, "MAX_ENTRIES", 100_000)
    append(journal, 24, at="invalid-time")
    with pytest.raises(UpstreamError) as error:
        AuditReader(journal).page()
    assert error.value.status == 502
    assert "invalid-time" not in error.value.message


def test_reads_real_controller_journal_without_initializing_store(tmp_path):
    path = tmp_path / "real.sqlite3"
    script = """
import sys
from pathlib import Path
from approval_flow import ReviewStore
store = ReviewStore(Path(sys.argv[1]))
store.record({"action_id": "act_real", "event": "kill_switch_engaged", "actor": "operator", "at": "2026-11-10T09:00:00Z", "level": "execution-off", "ai_off": True, "reason": "Operator requested stop"})
print(store.verify()["head"])
store.close()
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(path)],
        cwd=ROOT / "response-controller",
        check=True,
        capture_output=True,
        text=True,
    )
    before = path.read_bytes()
    page = AuditReader(path).page()
    assert page.head == result.stdout.strip()
    assert page.items[0].details["ai_off"] is True
    assert page.items[0].event == "kill_switch_engaged"
    assert path.read_bytes() == before


@pytest.mark.parametrize("setting", ["MAX_PAYLOAD_BYTES", "MAX_JOURNAL_BYTES"])
def test_payload_read_limits_are_enforced(journal, monkeypatch, setting):
    monkeypatch.setattr(audit, setting, 1)
    with pytest.raises(UpstreamError) as error:
        AuditReader(journal).page()
    assert error.value.status == 503
    assert "read limit" in error.value.message


def test_concurrent_append_does_not_change_the_read_snapshot(journal, monkeypatch):
    with closing(sqlite3.connect(journal)) as db:
        db.execute("PRAGMA journal_mode=WAL")
    project = audit._project
    appended = False

    def project_and_append(*row):
        nonlocal appended
        if not appended:
            appended = True
            append(journal, 24)
        return project(*row)

    monkeypatch.setattr(audit, "_project", project_and_append)
    page = AuditReader(journal).page()
    assert page.journal_total == page.total == page.through_sequence == 23
    assert page.items[0].sequence == 23
    assert AuditReader(journal).page().journal_total == 24


def test_unconfigured_endpoint_keeps_dashboard_usable():
    app = create_app(
        Settings(token=TOKEN, origin=ORIGIN),
        transport=httpx.MockTransport(lambda request: httpx.Response(503)),
    )
    with TestClient(app) as client:
        login(client)
        response = client.get("/api/audit-log")
        assert response.status_code == 503
        assert "not configured" in response.text
        assert client.get("/api/session").status_code == 200
        assert client.get("/audit-log").status_code == 200