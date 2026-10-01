import uuid
from datetime import datetime, timedelta, timezone

from app.event_models import EventORM
from app.incident_models import IncidentORM
from app.scorecard import generate_scorecard

_T0 = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)


def _event(event_id, seconds_after_t0=0):
    return EventORM(
        event_id=event_id,
        timestamp=_T0 + timedelta(seconds=seconds_after_t0),
        level="INFO",
        logger="attack_sim",
        source="attack-sim",
        event_type="attack_scenario_run",
        message="test event",
        details={"status": "failure"},
    )


def _incident(pattern, correlated_event_ids, created_at):
    return IncidentORM(
        incident_id=str(uuid.uuid4()),
        created_at=created_at,
        pattern=pattern,
        window_seconds=60,
        correlated_event_ids=correlated_event_ids,
        mitre_techniques=["T1195.001"],
        severity="high",
        confidence=0.6,
        summary="test incident",
    )


def test_perfect_run_scores_full_detection_and_zero_false_positives():
    events = [_event("e1", 0), _event("e2", 10)]
    incidents = [_incident("same-source-burst", ["e1", "e2"], _T0 + timedelta(seconds=15))]

    scorecard = generate_scorecard(events, incidents, expected_patterns=["same-source-burst"])

    assert scorecard.detection_rate == 1.0
    assert scorecard.detected_count == 1
    assert scorecard.expected_count == 1
    assert scorecard.false_positive_count == 0
    assert scorecard.false_positive_rate == 0.0


def test_a_missing_expected_incident_lowers_the_detection_rate():
    events = [_event("e1", 0)]
    incidents: list[IncidentORM] = []

    scorecard = generate_scorecard(
        events, incidents, expected_patterns=["composite-dependency-secret", "same-source-burst"]
    )

    assert scorecard.detected_count == 0
    assert scorecard.detection_rate == 0.0


def test_an_unexpected_incident_counts_as_a_false_positive():
    events = [_event("e1", 0), _event("e2", 5)]
    incidents = [_incident("same-source-burst", ["e1", "e2"], _T0 + timedelta(seconds=10))]

    scorecard = generate_scorecard(events, incidents, expected_patterns=["composite-dependency-secret"])

    assert scorecard.detection_rate == 0.0
    assert scorecard.false_positive_count == 1
    assert scorecard.false_positive_rate == 1.0
    assert scorecard.unexpected_patterns == ["same-source-burst"]


def test_mttd_is_the_average_gap_between_earliest_event_and_incident_creation():
    events = [_event("e1", 0), _event("e2", 10)]
    incidents = [_incident("same-source-burst", ["e1", "e2"], _T0 + timedelta(seconds=7))]

    scorecard = generate_scorecard(events, incidents, expected_patterns=["same-source-burst"])

    assert scorecard.mttd_seconds == 7.0


def test_mttd_averages_across_multiple_incidents():
    events = [_event("e1", 0), _event("e2", 0), _event("e3", 0), _event("e4", 0)]
    incidents = [
        _incident("same-source-burst", ["e1"], _T0 + timedelta(seconds=4)),
        _incident("composite-dependency-secret", ["e2"], _T0 + timedelta(seconds=10)),
    ]

    scorecard = generate_scorecard(
        events, incidents, expected_patterns=["same-source-burst", "composite-dependency-secret"]
    )

    assert scorecard.mttd_seconds == 7.0


def test_mttd_is_none_when_no_incidents_formed():
    events = [_event("e1", 0)]

    scorecard = generate_scorecard(events, [], expected_patterns=[])

    assert scorecard.mttd_seconds is None
    assert "n/a" in scorecard.report()


def test_report_is_human_readable_and_includes_all_three_numbers():
    events = [_event("e1", 0), _event("e2", 5)]
    incidents = [_incident("same-source-burst", ["e1", "e2"], _T0 + timedelta(seconds=8))]

    scorecard = generate_scorecard(events, incidents, expected_patterns=["same-source-burst"])
    report = scorecard.report()

    assert "Detection rate" in report
    assert "False positives" in report
    assert "MTTD" in report
    assert "8.00s" in report


def test_naive_and_aware_timestamps_both_compute_the_same_mttd():
    events = [_event("e1", 0)]
    naive_created_at = (_T0 + timedelta(seconds=3)).replace(tzinfo=None)
    incidents = [_incident("same-source-burst", ["e1"], naive_created_at)]

    scorecard = generate_scorecard(events, incidents, expected_patterns=["same-source-burst"])

    assert scorecard.mttd_seconds == 3.0