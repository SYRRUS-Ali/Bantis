import json
from datetime import datetime, timedelta, timezone
from io import BytesIO
from unittest.mock import patch

import pytest

from gap_detector import cli
from gap_detector.client import IncidentClient
from gap_detector.core import compare, read_history, utc

NOW = datetime(2026, 11, 25, 12, tzinfo=timezone.utc)


@pytest.fixture
def cli_clock(monkeypatch):
    class Clock:
        @staticmethod
        def now(tz):
            return NOW
    monkeypatch.setattr(cli, "datetime", Clock)


def event(event_id="run-1", *, status="success", scenario="typosquatting", age=400):
    return {"event_id": event_id, "timestamp": (NOW - timedelta(seconds=age)).isoformat(),
            "source": "attack-sim", "event_type": "attack_scenario_run",
            "details": {"scenario": scenario, "status": status, "tool_output_tail": "private"}}


def history(tmp_path, *events):
    path = tmp_path / "history.log"
    path.write_text("".join(json.dumps(item) + "\n" for item in events))
    return path


def incident(ids, *, name="incident-1", age=100):
    return {"incident_id": name, "created_at": (NOW - timedelta(seconds=age)).isoformat(),
            "correlated_event_ids": ids}


@pytest.mark.parametrize("status", ["success", "failure"])
def test_both_attack_outcomes_can_be_gaps(tmp_path, status):
    runs = read_history(history(tmp_path, event(status=status)))
    report = compare(runs, [], now=NOW)
    assert report["counts"]["gap"] == 1
    assert report["runs"][0]["gap_id"] == "gap:run-1"
    assert "private" not in json.dumps(report)


def test_exact_membership_multiple_runs_and_pending_error(tmp_path):
    path = history(tmp_path, event("a"), event("b"), event("c", age=10),
                   event("d", status="error"), event("a"))
    report = compare(read_history(path), [incident(["a", "b"])], now=NOW)
    assert report["counts"] == {"detected": 2, "gap": 0, "late_detection": 0, "pending": 1, "invalid": 1}
    assert all(item["incident_ids"] == ["incident-1"] for item in report["runs"] if item["event_id"] in {"a", "b"})


def test_unrelated_incident_and_deadline_boundary(tmp_path):
    runs = read_history(history(tmp_path, event(age=330)))
    report = compare(runs, [incident(["other-run"])], now=NOW)
    assert report["runs"][0]["state"] == "gap"
    report = compare(runs, [incident(["run-1"], age=0)], now=NOW)
    assert report["runs"][0]["state"] == "detected"


def test_late_detection_keeps_stable_gap_identity(tmp_path):
    runs = read_history(history(tmp_path, event()))
    before = compare(runs, [], now=NOW)
    after = compare(runs, [incident(["run-1"], age=10)], now=NOW)
    assert after["runs"][0]["state"] == "late_detection"
    assert before["runs"][0]["gap_id"] == after["runs"][0]["gap_id"]


def test_earliest_match_wins_and_future_incident_does_not_count(tmp_path):
    runs = read_history(history(tmp_path, event()))
    report = compare(runs, [incident(["run-1"], age=10), incident(["run-1"], name="early", age=200)], now=NOW)
    assert report["runs"][0]["state"] == "detected"
    assert report["runs"][0]["incident_ids"] == ["early", "incident-1"]
    assert compare(runs, [incident(["run-1"], age=-1)], now=NOW)["counts"]["gap"] == 1


def test_fixed_batch_deadline_and_timezones(tmp_path):
    runs = read_history(history(tmp_path, event()))
    assert compare(runs, [], now=NOW, deadline=NOW)["counts"]["gap"] == 1
    assert compare(runs, [], now=NOW, deadline=NOW + timedelta(seconds=1))["counts"]["pending"] == 1
    assert utc("2026-11-25T15:00:00+03:00") == NOW
    with pytest.raises(ValueError):
        utc("2026-11-25T12:00:00")


@pytest.mark.parametrize("change", [
    {"event_id": ""}, {"timestamp": "bad"}, {"details": []},
    {"details": {"scenario": "typosquatting", "status": "unknown"}},
])
def test_malformed_history_fails_instead_of_hiding_a_run(tmp_path, change):
    with pytest.raises(ValueError):
        read_history(history(tmp_path, {**event(), **change}))


def test_history_noise_duplicates_and_corruption(tmp_path):
    path = history(tmp_path, event(), event(), event("noop", scenario="noop"), {"message": "log"})
    with path.open("a") as stream:
        stream.write("success: scenario finished\n")
    assert len(read_history(path)) == 1
    with path.open("a") as stream:
        stream.write(json.dumps(event(status="failure")) + "\n")
    with pytest.raises(ValueError, match="conflicting duplicate"):
        read_history(path)
    path.write_text('{"event_id":')
    with pytest.raises(ValueError, match="incomplete"):
        read_history(path)
    path.write_text('{"bad":}\n')
    with pytest.raises(ValueError, match="invalid history"):
        read_history(path)
    path.write_text("")
    with pytest.raises(ValueError, match="inconclusive"):
        read_history(path)


@pytest.mark.parametrize("wait", [-1, float("nan"), float("inf")])
def test_invalid_allowances(tmp_path, wait):
    with pytest.raises(ValueError):
        compare(read_history(history(tmp_path, event())), [], now=NOW, wait_seconds=wait)


def test_future_event_or_deadline_before_event_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        compare(read_history(history(tmp_path, event(age=-1))), [], now=NOW)
    with pytest.raises(ValueError):
        compare(read_history(history(tmp_path, event())), [], now=NOW, deadline=NOW - timedelta(seconds=500))


def page(items, total, offset, limit=1):
    return BytesIO(json.dumps({"items": items, "total": total, "offset": offset, "limit": limit}).encode())


def test_client_reads_every_page_and_confirms_snapshot():
    first, second = incident(["x"]), incident(["run-1"], name="older")
    with patch("gap_detector.client.urlopen", side_effect=[
        page([first], 2, 0), page([second], 2, 1), page([first], 2, 0), page([second], 2, 1),
    ]) as request:
        assert IncidentClient("http://127.0.0.1:8000", page_size=1).incidents() == [first, second]
    assert [call.args[0] for call in request.call_args_list] == [
        "http://127.0.0.1:8000/incidents?limit=1&offset=0",
        "http://127.0.0.1:8000/incidents?limit=1&offset=1",
    ] * 2


@pytest.mark.parametrize("responses", [
    lambda: [page([], 1, 0)],
    lambda: [page([incident(["x"])], 2, 0), page([incident(["x"])], 2, 1)],
    lambda: [page([incident(["x"])], 2, 0), page([], 3, 1)],
    lambda: [page([], 0, 0), page([incident(["x"])], 1, 0)],
    lambda: [page([{"incident_id": "bad"}], 1, 0)],
    lambda: [BytesIO(b"not json")],
])
def test_incomplete_or_changing_incident_history_is_rejected(responses):
    with patch("gap_detector.client.urlopen", side_effect=responses()):
        with pytest.raises(ValueError):
            IncidentClient("http://localhost:8000", page_size=1).incidents()


@pytest.mark.parametrize("url", ["file:///tmp/incidents", "http://", "https://a:b@localhost", "http://localhost?x=1"])
def test_invalid_detection_urls(url):
    with pytest.raises(ValueError):
        IncidentClient(url)


def test_cli_exit_codes_and_previous_report_survives_failure(tmp_path, capsys, cli_clock):
    path = history(tmp_path, event())
    output = tmp_path / "report.json"
    args = ["--history", str(path), "--output", str(output), "--wait-seconds", "0"]
    with patch.object(IncidentClient, "incidents", return_value=[]):
        assert cli.main(args) == 1
    original = output.read_bytes()
    assert json.loads(original)["counts"]["gap"] == 1
    assert output.stat().st_mode & 0o077 == 0
    with patch.object(IncidentClient, "incidents", side_effect=OSError("private credential")):
        assert cli.main(args) == 2
    assert output.read_bytes() == original
    assert "private credential" not in capsys.readouterr().err
    with patch.object(IncidentClient, "incidents", return_value=[]), patch.object(cli.time, "sleep", side_effect=KeyboardInterrupt):
        assert cli.main(args + ["--interval", "1"]) == 0


def test_watch_recovers_from_failure(tmp_path, cli_clock):
    path = history(tmp_path, event())
    output = tmp_path / "report.json"
    with patch.object(IncidentClient, "incidents", side_effect=[OSError("offline"), []]), \
            patch.object(cli.time, "sleep", side_effect=[None, KeyboardInterrupt]):
        assert cli.main(["--history", str(path), "--output", str(output), "--interval", "1"]) == 0
    assert json.loads(output.read_text())["counts"]["gap"] == 1


def test_cli_refuses_to_overwrite_history(tmp_path):
    path = history(tmp_path, event())
    original = path.read_bytes()
    with pytest.raises(SystemExit):
        cli.main(["--history", str(path), "--output", str(path)])
    assert path.read_bytes() == original


def test_atomic_write_failure_keeps_previous_report(tmp_path):
    output = tmp_path / "report.json"
    output.write_text("previous")
    with patch.object(cli.os, "replace", side_effect=OSError("write failed")):
        with pytest.raises(OSError):
            cli.write_report(output, {"counts": {}})
    assert output.read_text() == "previous"
    assert list(tmp_path.iterdir()) == [output]