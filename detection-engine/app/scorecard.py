from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.event_models import EventORM
from app.incident_models import IncidentORM


@dataclass
class Scorecard:
    total_incidents: int
    expected_count: int
    detected_count: int
    detection_rate: float
    false_positive_count: int
    false_positive_rate: float
    mttd_seconds: float | None
    unexpected_patterns: list[str] = field(default_factory=list)

    def report(self) -> str:
        lines = [
            "Bantis Detection Scorecard",
            "=" * 40,
            f"Detection rate:   {self.detected_count}/{self.expected_count} "
            f"= {self.detection_rate * 100:.1f}%",
            f"False positives:  {self.false_positive_count}/{self.total_incidents} "
            f"= {self.false_positive_rate * 100:.1f}%",
            f"MTTD:             {self._mttd_display()}",
        ]
        if self.unexpected_patterns:
            lines.append(f"Unexpected incidents: {self.unexpected_patterns}")
        return "\n".join(lines)

    def _mttd_display(self) -> str:
        if self.mttd_seconds is None:
            return "n/a (no incidents formed)"
        return f"{self.mttd_seconds:.2f}s"


def _as_naive_utc(moment: datetime) -> datetime:
    if moment.tzinfo is not None:
        return moment.astimezone(timezone.utc).replace(tzinfo=None)
    return moment


def _time_to_detect(incident: IncidentORM, events_by_id: dict[str, EventORM]) -> float | None:
    timestamps = [
        events_by_id[event_id].timestamp for event_id in incident.correlated_event_ids if event_id in events_by_id
    ]
    if not timestamps:
        return None

    earliest = min(timestamps)
    return (_as_naive_utc(incident.created_at) - _as_naive_utc(earliest)).total_seconds()


def generate_scorecard(
    events: list[EventORM],
    incidents: list[IncidentORM],
    expected_patterns: list[str],
) -> Scorecard:
    """Scores one run of the detection engine against a known-good
    expectation -- the same ground truth every other correlation
    evaluation in this project already relies on
    (tests/evaluate_correlation_rules.py's labeled cases,
    tests/run_m2_baseline.py's real scenario run): "detection rate" and
    "false positives" aren't well-defined without first knowing what
    should have happened. `expected_patterns` is that ground truth —
    the incident pattern(s) this run's attack activity is known to
    warrant, e.g. ["composite-dependency-secret", "same-source-burst"]
    for a full M2 run (docs/m2-detection-baseline.md).

    MTTD doesn't need that ground truth: it's the gap between an
    incident's correlated events' earliest timestamp and the moment the
    correlation engine actually formed the incident, averaged across
    every incident in this run — a real latency number regardless of
    whether the incident turned out to be expected or not.
    """
    actual_patterns = Counter(incident.pattern for incident in incidents)
    expected = Counter(expected_patterns)

    matched = sum((actual_patterns & expected).values())
    detection_rate = matched / len(expected_patterns) if expected_patterns else 1.0

    unexpected = actual_patterns - expected
    false_positive_count = sum(unexpected.values())
    false_positive_rate = false_positive_count / len(incidents) if incidents else 0.0

    events_by_id = {event.event_id: event for event in events}
    ttds = [ttd for incident in incidents if (ttd := _time_to_detect(incident, events_by_id)) is not None]
    mttd_seconds = sum(ttds) / len(ttds) if ttds else None

    return Scorecard(
        total_incidents=len(incidents),
        expected_count=len(expected_patterns),
        detected_count=matched,
        detection_rate=detection_rate,
        false_positive_count=false_positive_count,
        false_positive_rate=false_positive_rate,
        mttd_seconds=mttd_seconds,
        unexpected_patterns=sorted(unexpected.elements()),
    )