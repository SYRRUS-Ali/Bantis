"""Generate inactive, single-event correlation drafts from completed gap reports."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import Counter
from pathlib import Path

from .core import SCENARIOS, nonempty, utc

TECHNIQUES = {
    "malicious-dependency": "T1195.001",
    "leaked-secret": "T1552.001",
    "compromised-ci-step": "T1195.002",
    "typosquatting": "T1195.001",
}
STATES = {"gap", "detected", "pending", "late_detection", "invalid"}


def _gap_groups(report: dict) -> dict[str, list[dict]]:
    if (not isinstance(report, dict) or type(report.get("schema_version")) is not int
            or report["schema_version"] != 1 or report.get("complete") is not True
            or not isinstance(report.get("runs"), list)):
        raise ValueError("a complete version 1 gap report is required")
    observed = utc(report.get("observed_at"))
    groups: dict[str, list[dict]] = {}
    covered = set()
    seen = set()
    counts: Counter = Counter()
    for run in report["runs"]:
        if not isinstance(run, dict) or not nonempty(run.get("event_id")):
            raise ValueError("each run requires an event_id")
        event_id, scenario, state = run["event_id"], run.get("scenario"), run.get("state")
        if (not isinstance(scenario, str) or scenario not in SCENARIOS
                or not isinstance(state, str) or state not in STATES
                or run.get("status") not in ("success", "failure", "error")):
            raise ValueError("unsupported scenario, state, or outcome")
        if event_id in seen:
            raise ValueError("duplicate run event_id")
        seen.add(event_id)
        counts[state] += 1
        emitted, deadline = utc(run.get("timestamp")), utc(run.get("deadline"))
        if emitted > observed or deadline < emitted:
            raise ValueError("invalid run observation times")
        if (run["status"] == "error") != (state == "invalid"):
            raise ValueError("scenario errors must be invalid exercises")
        if state in {"detected", "late_detection"}:
            incident_ids = run.get("incident_ids")
            first_detected = utc(run.get("first_detected_at"))
            if (not isinstance(incident_ids, list) or not incident_ids
                    or not all(nonempty(value) for value in incident_ids)
                    or first_detected > observed
                    or (first_detected <= deadline) != (state == "detected")):
                raise ValueError("detection evidence is incomplete or contradicts its state")
            covered.add(scenario)
        if state == "gap":
            if (deadline > observed or run.get("incident_ids") != []
                    or run.get("first_detected_at") is not None
                    or run.get("gap_id") != "gap:" + event_id):
                raise ValueError("gap evidence is incomplete or contradicts its state")
            groups.setdefault(scenario, []).append(run)
    expected = {state: counts[state] for state in STATES}
    actual = report.get("counts")
    if (not isinstance(actual, dict) or actual != expected
            or any(type(value) is not int for value in actual.values())):
        raise ValueError("report counts do not match run states")
    # Partial coverage needs investigation, rather than a duplicate scenario rule.
    return {scenario: runs for scenario, runs in groups.items() if scenario not in covered}


def matches_draft(draft: dict, event: dict) -> bool:
    """Preview the fixed selector format; never execute rule text or persist incidents."""
    if not isinstance(event, dict) or not nonempty(event.get("event_id")):
        return False
    try:
        utc(event.get("timestamp"))
    except ValueError:
        return False
    details = event.get("details")
    if not isinstance(details, dict):
        return False
    selector = draft["selector"]
    return (event.get("source") == selector["source"]
            and event.get("event_type") == selector["event_type"]
            and details.get("scenario") == selector["details.scenario"]
            and details.get("status") in selector["details.status"])


def _draft(scenario: str, runs: list[dict]) -> dict:
    rule_id = f"scenario-{scenario}-single-event-v1"
    example = {
        "event_id": "example-run", "timestamp": "2026-01-01T00:00:00Z",
        "level": "INFO", "logger": "attack_sim", "source": "attack-sim",
        "event_type": "attack_scenario_run", "message": "Scenario verification completed",
        "details": {"scenario": scenario, "mitre_technique": TECHNIQUES[scenario], "status": "success"},
    }
    cases = []
    for status in ("success", "failure", "error"):
        cases.append({"name": f"scenario outcome {status}", "matches": status != "error",
                      "event": {**example, "details": {**example["details"], "status": status}}})
    for name, changes in (
        ("ordinary request", {"event_type": "http_request"}),
        ("different producer", {"source": "api"}),
        ("different scenario", {"details": {**example["details"], "scenario": "noop"}}),
        ("missing scenario details", {"details": {}}),
    ):
        cases.append({"name": name, "matches": False, "event": {**example, **changes}})
    return {
        "draft_id": rule_id, "status": "pending_review", "enabled": False,
        "title": f"Single-event coverage for {scenario}",
        "scenario": scenario, "mitre_technique": TECHNIQUES[scenario],
        "schema_reference": "docs/event-schema.md#attack_scenario_run",
        "schema_fields": {
            "event_id": "nonempty string; incident membership and deduplication",
            "timestamp": "ISO 8601 with timezone; event time",
            "source": "attack-sim", "event_type": "attack_scenario_run",
            "details.scenario": scenario, "details.status": ["success", "failure", "error"],
            "details.mitre_technique": "scenario technique; not a selector constraint",
            "details.artifact": "optional evidence; not a selector constraint",
            "details.tool_returncode": "optional evidence; not a selector constraint",
        },
        "selector": {"source": "attack-sim", "event_type": "attack_scenario_run",
                     "details.scenario": scenario, "details.status": ["success", "failure"]},
        "correlation": {"kind": "single-event", "group_by": ["event_id"],
                        "min_events": 1, "window_seconds": 0},
        "incident_template": {
            "pattern": f"scenario-{scenario}", "correlated_event_ids": ["$event.event_id"],
            "mitre_techniques": ["$event.details.mitre_technique"],
            "summary": f"Individual {scenario} scenario result requires review",
            "severity_by_status": {"success": "high", "failure": "medium"},
            "confidence": None, "confidence_note": "Uncalibrated; reviewer must choose and evaluate scoring.",
        },
        "evidence": {"gap_ids": sorted(run["gap_id"] for run in runs),
                     "event_ids": sorted(run["event_id"] for run in runs),
                     "outcomes": sorted({run["status"] for run in runs})},
        "rationale": "A single valid scenario run can lack the partner required by existing grouped rules. "
                     "Propose individual coverage without constraining the selector to one run or artifact.",
        "limitations": [
            "Only detects instrumented attack-sim scenario results, not equivalent real-world activity.",
            "A rule cannot fix lost telemetry, failed correlation, or detection latency.",
            "Legitimate lab replays also match; evaluate noise before integration.",
        ],
        "integration_review": [
            "Confirm the event reached storage and correlation ran; triage the gap before adding a rule.",
            "Preserve composite-dependency-secret priority and its 300-second partner hold; "
            "do not claim a dependency or secret early and prevent its composite incident.",
            "Decide fallback ordering relative to same-source-burst and reuse existing event-claim deduplication.",
            "Set and calibrate confidence, review severity, and verify incident schema compatibility.",
            "Add positive and benign negative tests, replay the original gap with fresh IDs, "
            "and verify no duplicate incidents or loss of grouped coverage.",
        ],
        "validation_cases": cases,
    }


def suggest_rules(report: dict) -> dict:
    """Draft only for missed scenarios with no observed detection in this report."""
    groups = _gap_groups(report)
    return {"schema_version": 1, "generator": "scenario-to-rule-v1",
            "gap_report_observed_at": report["observed_at"],
            "drafts": [_draft(scenario, groups[scenario]) for scenario in sorted(groups)]}


def main(argv: list[str] | None = None) -> int:
    # Imported lazily: the service imports suggest_rules from this module.
    from .cli import write_report
    from .review_queue import ReviewQueue, queue_path

    parser = argparse.ArgumentParser(description="Generate inactive correlation drafts from a gap report.")
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--review-queue", type=Path, help="Persistent SQLite review queue (default: beside output)")
    args = parser.parse_args(argv)
    queue = queue_path(args.output, args.review_queue)
    if len({args.report.resolve(), args.output.resolve(), queue.resolve()}) != 3:
        parser.error("report, output, and review queue must be different files")
    try:
        with args.report.open(encoding="utf-8") as stream:
            suggestions = suggest_rules(json.load(stream))
        ReviewQueue(queue).enqueue(suggestions)
        write_report(args.output, suggestions)
    except (OSError, ValueError, TypeError, sqlite3.Error) as exc:
        print(json.dumps({"status": "error", "error_type": type(exc).__name__,
                          "message": "Draft generation failed; previous output retained."}), file=sys.stderr)
        return 2
    print(json.dumps({"status": "ok", "draft_count": len(suggestions["drafts"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())