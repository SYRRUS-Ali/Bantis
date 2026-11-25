import ast
import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from gap_detector import cli
from gap_detector.core import SCENARIOS, compare, read_history
from gap_detector.suggester import TECHNIQUES, main, matches_draft, suggest_rules

NOW = datetime(2026, 11, 25, 12, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[2]


def event(scenario="compromised-ci-step", event_id="missed-run", status="success"):
    return {"event_id": event_id, "timestamp": (NOW - timedelta(seconds=400)).isoformat(),
            "source": "attack-sim", "event_type": "attack_scenario_run",
            "level": "INFO", "logger": "attack_sim", "message": "private tool output",
            "details": {"scenario": scenario, "status": status,
                        "mitre_technique": TECHNIQUES[scenario],
                        "artifact": "private artifact", "tool_output_tail": "private credential"}}


def report_for(tmp_path, *events):
    history = tmp_path / "history.log"
    history.write_text("".join(json.dumps(item) + "\n" for item in events))
    return compare(read_history(history), [], now=NOW)


@pytest.mark.parametrize("scenario", sorted(SCENARIOS))
def test_schema_based_draft_for_every_m2_scenario(tmp_path, scenario):
    report = report_for(tmp_path, event(scenario))
    draft, = suggest_rules(report)["drafts"]
    assert draft["enabled"] is False
    assert draft["status"] == "draft"
    assert draft["selector"] == {"source": "attack-sim", "event_type": "attack_scenario_run",
                                 "details.scenario": scenario, "details.status": ["success", "failure"]}
    assert draft["correlation"] == {"kind": "single-event", "group_by": ["event_id"],
                                    "min_events": 1, "window_seconds": 0}
    assert draft["incident_template"]["correlated_event_ids"] == ["$event.event_id"]
    assert draft["incident_template"]["confidence"] is None
    assert draft["evidence"]["gap_ids"] == ["gap:missed-run"]
    assert "private" not in json.dumps(draft)
    for status in ("success", "failure"):
        assert matches_draft(draft, event(scenario, event_id="fresh-run", status=status))
    assert not matches_draft(draft, event(scenario, status="error"))
    assert matches_draft(draft, {**event(scenario), "details": {"scenario": scenario, "status": "success"}})
    for case in draft["validation_cases"]:
        assert matches_draft(draft, case["event"]) is case["matches"], case["name"]


def test_multiple_gaps_grouped_stably_and_input_is_not_modified(tmp_path):
    report = report_for(tmp_path, event(event_id="z"), event(event_id="a", status="failure"),
                        event("leaked-secret", event_id="b"))
    original = copy.deepcopy(report)
    result = suggest_rules(report)
    assert len(result["drafts"]) == 2
    ci_draft = result["drafts"][0]
    assert ci_draft["evidence"] == {"gap_ids": ["gap:a", "gap:z"], "event_ids": ["a", "z"],
                                    "outcomes": ["failure", "success"]}
    assert report == original
    report["runs"].reverse()
    assert suggest_rules(report) == result
    reduced = report_for(tmp_path, event())
    assert suggest_rules(reduced)["drafts"][0]["draft_id"] == ci_draft["draft_id"]


@pytest.mark.parametrize("state", ["detected", "pending", "invalid", "late_detection"])
def test_only_outstanding_gaps_generate_new_rules(tmp_path, state):
    item = event(status="error" if state == "invalid" else "success")
    if state == "pending":
        item["timestamp"] = NOW.isoformat()
    report = report_for(tmp_path, item)
    if state in {"detected", "late_detection"}:
        age = 200 if state == "detected" else 1
        incident = {"incident_id": "existing", "created_at": (NOW - timedelta(seconds=age)).isoformat(),
                    "correlated_event_ids": [item["event_id"]]}
        report = compare(read_history(tmp_path / "history.log"), [incident], now=NOW)
    assert report["runs"][0]["state"] == state
    assert suggest_rules(report)["drafts"] == []


@pytest.mark.parametrize("change", [
    {"complete": False}, {"schema_version": 2}, {"schema_version": True},
    {"runs": None}, {"observed_at": "invalid"}, {"counts": {}},
])
def test_incomplete_or_unknown_report_contract_rejected(tmp_path, change):
    report = report_for(tmp_path, event())
    report.update(change)
    with pytest.raises(ValueError):
        suggest_rules(report)


@pytest.mark.parametrize("change", [
    {"event_id": ""}, {"scenario": "unknown"}, {"status": "error"},
    {"gap_id": "gap:unrelated"}, {"incident_ids": ["already-detected"]},
    {"first_detected_at": NOW.isoformat()}, {"deadline": (NOW + timedelta(seconds=1)).isoformat()},
    {"timestamp": (NOW + timedelta(seconds=1)).isoformat()},
])
def test_contradictory_gap_evidence_rejected(tmp_path, change):
    report = report_for(tmp_path, event())
    report["runs"][0].update(change)
    with pytest.raises(ValueError):
        suggest_rules(report)


def test_duplicate_evidence_rejected(tmp_path):
    report = report_for(tmp_path, event())
    report["runs"].append(copy.deepcopy(report["runs"][0]))
    with pytest.raises(ValueError, match="duplicate"):
        suggest_rules(report)


@pytest.mark.parametrize("changes", [
    {"source": "ci"}, {"event_type": "http_request"}, {"details": None},
    {"event_id": ""}, {"timestamp": "bad"}, {"timestamp": "2026-01-01T00:00:00"},
    {"details": {"scenario": "noop", "status": "success"}},
])
def test_preview_rejects_unrelated_and_invalid_events(tmp_path, changes):
    draft, = suggest_rules(report_for(tmp_path, event()))["drafts"]
    assert not matches_draft(draft, {**event(), **changes})


def test_technique_mapping_matches_actual_scenario_declarations():
    assert set(TECHNIQUES) == SCENARIOS
    for scenario, technique in TECHNIQUES.items():
        tree = ast.parse((ROOT / "attack-sim/scenarios" / (scenario.replace("-", "_") + ".py")).read_text())
        declarations = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for assignment in node.body:
                    if isinstance(assignment, ast.Assign) and isinstance(assignment.value, ast.Constant):
                        for target in assignment.targets:
                            if isinstance(target, ast.Name):
                                declarations[target.id] = assignment.value.value
        assert declarations["name"] == scenario
        assert declarations["mitre_technique"] == technique


def test_offline_cli_and_failed_generation_preserve_existing_output(tmp_path, capsys):
    report = report_for(tmp_path, event())
    source, output = tmp_path / "gaps.json", tmp_path / "drafts.json"
    source.write_text(json.dumps(report))
    args = ["--report", str(source), "--output", str(output)]
    assert main(args) == 0
    assert json.loads(output.read_text()) == suggest_rules(report)
    assert output.stat().st_mode & 0o077 == 0
    previous = output.read_bytes()
    source.write_text('{"private credential":')
    assert main(args) == 2
    assert output.read_bytes() == previous
    assert "private credential" not in capsys.readouterr().err
    with pytest.raises(SystemExit):
        main(["--report", str(source), "--output", str(source)])


def test_service_embeds_drafts_and_keeps_gap_exit_code(tmp_path, monkeypatch):
    from unittest.mock import patch

    report_for(tmp_path, event())
    output = tmp_path / "report.json"

    class Clock:
        @staticmethod
        def now(tz):
            return NOW

    monkeypatch.setattr(cli, "datetime", Clock)
    with patch.object(cli.IncidentClient, "incidents", return_value=[]):
        assert cli.main(["--history", str(tmp_path / "history.log"), "--output", str(output)]) == 1
    report = json.loads(output.read_text())
    assert report["rule_suggestions"] == suggest_rules(report)