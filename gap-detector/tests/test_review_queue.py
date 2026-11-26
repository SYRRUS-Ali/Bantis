import copy
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest
from gap_detector import cli
from gap_detector.review_queue import ReviewQueue, main, queue_path
from gap_detector.suggester import main as suggest_main
from gap_detector.suggester import suggest_rules
from test_suggester import event, report_for


def test_pending_queue_survives_restart_and_report_replacement(tmp_path):
    path = tmp_path / "queue.db"
    suggestions = suggest_rules(report_for(tmp_path, event()))
    ReviewQueue(path).enqueue(suggestions)
    proposal, = ReviewQueue(path).list()
    assert proposal["status"] == "pending_review"
    assert proposal["draft"] == suggestions["drafts"][0]
    assert proposal["draft"]["enabled"] is False
    assert proposal["reviewer"] is proposal["reviewed_at"] is proposal["reason"] is None
    ReviewQueue(path).enqueue(suggestions)
    ReviewQueue(path).enqueue({"schema_version": 1, "drafts": []})
    assert ReviewQueue(path).list() == [proposal]
    assert path.stat().st_mode & 0o077 == 0


@pytest.mark.parametrize("decision", ["approved", "rejected"])
def test_review_is_content_bound_and_never_enables_rules(tmp_path, decision):
    path = tmp_path / "queue.db"
    queue = ReviewQueue(path)
    suggestions = suggest_rules(report_for(tmp_path, event()))
    original = copy.deepcopy(suggestions)
    queue.enqueue(suggestions)
    pending, = queue.list()
    result = queue.decide(pending["proposal_id"], decision, reviewer="operator", reason="Checked replay evidence")
    assert result["status"] == decision
    assert result["reviewer"] == "operator"
    assert result["reason"] == "Checked replay evidence"
    assert result["reviewed_at"]
    assert result["draft"]["enabled"] is False
    queue.enqueue(suggestions)
    assert ReviewQueue(path).show(pending["proposal_id"]) == result
    assert queue.list() == []
    with pytest.raises(ValueError, match="already reviewed"):
        queue.decide(pending["proposal_id"], "approved", reviewer="another", reason="override")
    suggestions["drafts"][0]["selector"]["details.status"] = ["success"]
    queue.enqueue(suggestions)
    revision, = queue.list()
    assert revision["proposal_id"] != pending["proposal_id"]
    assert revision["draft_id"] == pending["draft_id"]
    assert revision["reviewer"] is None
    assert queue.show(pending["proposal_id"])["draft"] == original["drafts"][0]


def test_concurrent_review_has_one_winner(tmp_path):
    path = tmp_path / "queue.db"
    queue = ReviewQueue(path)
    queue.enqueue(suggest_rules(report_for(tmp_path, event())))
    proposal, = queue.list()

    def decide(decision):
        try:
            ReviewQueue(path).decide(proposal["proposal_id"], decision, reviewer=decision, reason="reviewed")
            return True
        except ValueError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(decide, ["approved", "rejected"])) == [False, True]
    assert len(queue.list(None)) == 1
    assert queue.show(proposal["proposal_id"])["draft"]["enabled"] is False


@pytest.mark.parametrize("reviewer,reason,decision", [
    ("", "checked", "approved"), ("operator", "  ", "approved"),
    ("operator", "checked", "enabled"),
])
def test_invalid_decision_keeps_proposal_pending(tmp_path, reviewer, reason, decision):
    queue = ReviewQueue(tmp_path / "queue.db")
    queue.enqueue(suggest_rules(report_for(tmp_path, event())))
    proposal, = queue.list()
    with pytest.raises(ValueError):
        queue.decide(proposal["proposal_id"], decision, reviewer=reviewer, reason=reason)
    assert queue.list() == [proposal]
    with pytest.raises(ValueError):
        queue.decide("missing", "approved", reviewer="operator", reason="checked")
    assert queue.list() == [proposal]


@pytest.mark.parametrize("change", [{"enabled": True}, {"status": "approved"}])
def test_enqueue_refuses_active_or_preapproved_input_atomically(tmp_path, change):
    queue = ReviewQueue(tmp_path / "queue.db")
    suggestions = suggest_rules(report_for(tmp_path, event()))
    invalid = copy.deepcopy(suggestions["drafts"][0])
    invalid.update(change)
    suggestions["drafts"].append(invalid)
    with pytest.raises(ValueError):
        queue.enqueue(suggestions)
    assert queue.list(None) == []


def test_offline_generation_and_review_cli(tmp_path, capsys):
    source, output, path = tmp_path / "gaps.json", tmp_path / "drafts.json", tmp_path / "queue.db"
    source.write_text(json.dumps(report_for(tmp_path, event())))
    args = ["--report", str(source), "--output", str(output), "--review-queue", str(path)]
    assert suggest_main(args) == 0
    capsys.readouterr()
    prefix = ["--queue", str(path)]
    assert main(prefix + ["list"]) == 0
    proposal, = json.loads(capsys.readouterr().out)
    assert main(prefix + ["show", proposal["proposal_id"]]) == 0
    assert json.loads(capsys.readouterr().out) == proposal
    assert main(prefix + ["approve", proposal["proposal_id"], "--reviewer", "operator",
                          "--reason", "Positive and benign replay cases checked"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "approved"
    assert suggest_main(args) == 0
    assert ReviewQueue(path).list() == []
    assert json.loads(output.read_text())["drafts"][0]["enabled"] is False
    assert main(prefix + ["reject", proposal["proposal_id"], "--reviewer", "operator", "--reason", "retry"]) == 2
    assert "no rule activated" in capsys.readouterr().err


def test_queue_failure_preserves_previous_report(tmp_path, monkeypatch):
    report = report_for(tmp_path, event())
    source, output = tmp_path / "gaps.json", tmp_path / "output.json"
    source.write_text(json.dumps(report))
    output.write_text("previous complete report")

    def fail(*args):
        raise sqlite3.OperationalError("disk full")

    monkeypatch.setattr(ReviewQueue, "enqueue", fail)
    assert suggest_main(["--report", str(source), "--output", str(output)]) == 2
    assert output.read_text() == "previous complete report"
    monkeypatch.setattr(cli.IncidentClient, "incidents", lambda self: [])
    assert cli.main(["--history", str(tmp_path / "history.log"), "--output", str(output)]) == 2
    assert output.read_text() == "previous complete report"


def test_queue_paths_cannot_overwrite_inputs_or_outputs(tmp_path):
    source, output = tmp_path / "source", tmp_path / "output"
    for queue in (source, output):
        with pytest.raises(SystemExit):
            suggest_main(["--report", str(source), "--output", str(output), "--review-queue", str(queue)])
        with pytest.raises(SystemExit):
            cli.main(["--history", str(source), "--output", str(output), "--review-queue", str(queue)])
    assert queue_path(output) == tmp_path / "output.review.sqlite3"