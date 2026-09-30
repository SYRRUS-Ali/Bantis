from __future__ import annotations

import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.correlation import correlate  # noqa: E402
from app.event_models import EventORM  # noqa: E402

_T0 = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)


def _attack_event(event_id, source, seconds_after_t0=0, scenario=None, status="success", mitre="T1195.001"):
    details = {"status": status, "mitre_technique": mitre}
    if scenario is not None:
        details["scenario"] = scenario
    return EventORM(
        event_id=event_id,
        timestamp=_T0 + timedelta(seconds=seconds_after_t0),
        level="INFO",
        logger="attack_sim",
        source=source,
        event_type="attack_scenario_run",
        message="test event",
        details=details,
    )


def _http_event(event_id, source, seconds_after_t0=0, status_code=200):
    return EventORM(
        event_id=event_id,
        timestamp=_T0 + timedelta(seconds=seconds_after_t0),
        level="INFO",
        logger=f"{source}.access",
        source=source,
        event_type="http_request",
        message="request handled",
        details={"method": "GET", "path": "/health", "status_code": status_code},
    )


def _pull_event(event_id, seconds_after_t0=0, registry="docker.io"):
    return EventORM(
        event_id=event_id,
        timestamp=_T0 + timedelta(seconds=seconds_after_t0),
        level="INFO",
        logger="ci",
        source="ci",
        event_type="container_image_pull",
        message="image pulled",
        details={"registry": registry, "image": "library/python:3.12-slim"},
    )


@dataclass
class Case:
    label: str
    events: list = field(default_factory=list)
    expected_patterns: list = field(default_factory=list)  # [] means "no incident expected"


TRUE_POSITIVES = [
    Case(
        "composite pair, both defended",
        [
            _attack_event("dep", "attack-sim", 0, scenario="malicious-dependency", status="failure"),
            _attack_event("sec", "attack-sim", 50, scenario="leaked-secret", status="failure"),
        ],
        ["composite-dependency-secret"],
    ),
    Case(
        "composite pair, both succeeded",
        [
            _attack_event("dep2", "attack-sim", 0, scenario="malicious-dependency", status="success"),
            _attack_event("sec2", "attack-sim", 50, scenario="leaked-secret", status="success"),
        ],
        ["composite-dependency-secret"],
    ),
    Case(
        "same-source burst of two distinct scenarios",
        [
            _attack_event("a", "attack-sim", 0, scenario="compromised-ci-step"),
            _attack_event("b", "attack-sim", 10, scenario="typosquatting"),
        ],
        ["same-source-burst"],
    ),
    Case(
        "untrusted registry pull",
        [_pull_event("pull1", 0, registry="evil-registry.example.com")],
        ["untrusted-registry-pull"],
    ),
    Case(
        "all four M2 scenarios back-to-back",
        [
            _attack_event("dep3", "attack-sim", 0, scenario="malicious-dependency", status="failure"),
            _attack_event("sec3", "attack-sim", 1, scenario="leaked-secret", status="failure"),
            _attack_event("ci3", "attack-sim", 2, scenario="compromised-ci-step", status="success"),
            _attack_event("ts3", "attack-sim", 3, scenario="typosquatting", status="success"),
        ],
        ["composite-dependency-secret", "same-source-burst"],
    ),
]

TRUE_NEGATIVES = [
    Case(
        "ordinary api traffic burst",
        [_http_event("r1", "api", 0), _http_event("r2", "api", 5), _http_event("r3", "api", 10)],
    ),
    Case(
        "ordinary nginx traffic burst",
        [_http_event("r1", "nginx", 0), _http_event("r2", "nginx", 5)],
    ),
    Case(
        "single isolated attack-sim event",
        [_attack_event("only", "attack-sim", 0, scenario="noop", status="success")],
    ),
    Case(
        "two attack-sim events from different sources",
        [_attack_event("x", "attack-sim", 0), _attack_event("y", "ci", 1)],
    ),
    Case(
        "two attack-sim events outside the time window",
        [_attack_event("far1", "attack-sim", 0), _attack_event("far2", "attack-sim", 9999)],
    ),
    Case(
        "trusted registry pull (docker.io)",
        [_pull_event("trusted1", 0, registry="docker.io")],
    ),
    Case(
        "trusted registry pull (ghcr.io)",
        [_pull_event("trusted2", 0, registry="ghcr.io")],
    ),
    Case(
        "two ERROR-status attack-sim events",
        [_attack_event("e1", "attack-sim", 0, status="error"), _attack_event("e2", "attack-sim", 10, status="error")],
    ),
]


def _run(cases: list[Case]) -> list[tuple[Case, bool, list[str]]]:
    results = []
    for case in cases:
        incidents = correlate(case.events)
        actual_patterns = sorted(i.pattern for i in incidents)
        expected_patterns = sorted(case.expected_patterns)
        results.append((case, actual_patterns == expected_patterns, actual_patterns))
    return results


def main() -> int:
    tp_results = _run(TRUE_POSITIVES)
    tn_results = _run(TRUE_NEGATIVES)

    print("True Positives (should form the named incident(s)):")
    tp_hits = 0
    for case, matched, actual in tp_results:
        marker = "PASS" if matched else "FAIL"
        tp_hits += matched
        print(f"  [{marker}] {case.label}: expected {case.expected_patterns}, got {actual}")

    print("\nTrue Negatives (should form no incident):")
    tn_correct = 0
    for case, matched, actual in tn_results:
        marker = "PASS" if matched else "FAIL"
        tn_correct += matched
        print(f"  [{marker}] {case.label}: got {actual}")

    detection_rate = tp_hits / len(tp_results) * 100
    false_positive_rate = (len(tn_results) - tn_correct) / len(tn_results) * 100

    print("\n" + "=" * 72)
    print(f"Detection rate:      {tp_hits}/{len(tp_results)} = {detection_rate:.1f}%")
    print(f"False positive rate: {len(tn_results) - tn_correct}/{len(tn_results)} = {false_positive_rate:.1f}%")

    if detection_rate < 100 or false_positive_rate > 0:
        print("\nEVALUATION FAILED: rule thresholds need attention.")
        return 1

    print("\nEVALUATION PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())