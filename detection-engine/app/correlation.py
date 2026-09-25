from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.event_models import EventORM
from app.incident_models import IncidentORM

SAME_SOURCE_WINDOW_SECONDS = 60
COMPOSITE_WINDOW_SECONDS = 300

_COMPOSITE_DEPENDENCY_SCENARIO = "malicious-dependency"
_COMPOSITE_SECRET_SCENARIO = "leaked-secret"


def _scenario_name(event: EventORM) -> str | None:
    return (event.details or {}).get("scenario")


def _is_success(event: EventORM) -> bool:
    return (event.details or {}).get("status") == "success"


def _mitre_technique(event: EventORM) -> str:
    return (event.details or {}).get("mitre_technique", "N/A")


def _cluster_by_gap(events: list[EventORM], window_seconds: int) -> list[list[EventORM]]:
    if not events:
        return []

    clusters: list[list[EventORM]] = [[events[0]]]
    for event in events[1:]:
        gap = (event.timestamp - clusters[-1][-1].timestamp).total_seconds()
        if gap <= window_seconds:
            clusters[-1].append(event)
        else:
            clusters.append([event])
    return clusters


def _build_same_source_incident(group: list[EventORM]) -> IncidentORM:
    any_success = any(_is_success(e) for e in group)
    severity = "high" if any_success else "medium"
    confidence = 0.5 if any_success else 0.3

    parts = [f"{_scenario_name(e) or e.event_type} ({e.details.get('status', e.level.lower())})" for e in group]
    summary = f"{len(group)} {group[0].source} events within {SAME_SOURCE_WINDOW_SECONDS}s: " + ", ".join(parts)

    return IncidentORM(
        incident_id=str(uuid.uuid4()),
        created_at=datetime.now(timezone.utc),
        pattern="same-source-burst",
        window_seconds=SAME_SOURCE_WINDOW_SECONDS,
        correlated_event_ids=[e.event_id for e in group],
        mitre_techniques=[_mitre_technique(e) for e in group],
        severity=severity,
        confidence=confidence,
        summary=summary,
    )


def _find_same_source_incidents(events: list[EventORM], claimed: set[str]) -> list[IncidentORM]:
    incidents: list[IncidentORM] = []
    by_source: dict[str, list[EventORM]] = {}
    for event in events:
        if event.event_id in claimed:
            continue
        by_source.setdefault(event.source, []).append(event)

    for source_events in by_source.values():
        source_events.sort(key=lambda e: e.timestamp)
        for cluster in _cluster_by_gap(source_events, SAME_SOURCE_WINDOW_SECONDS):
            if len(cluster) < 2:
                continue
            incidents.append(_build_same_source_incident(cluster))
            claimed.update(e.event_id for e in cluster)

    return incidents


def _build_composite_incident(dependency: EventORM, secret: EventORM) -> IncidentORM:
    pair = sorted([dependency, secret], key=lambda e: e.timestamp)
    successes = sum(1 for e in pair if _is_success(e))
    severity = "critical" if successes == 2 else "high"
    confidence = round(0.6 + 0.15 * successes, 2)

    return IncidentORM(
        incident_id=str(uuid.uuid4()),
        created_at=datetime.now(timezone.utc),
        pattern="composite-dependency-secret",
        window_seconds=COMPOSITE_WINDOW_SECONDS,
        correlated_event_ids=[e.event_id for e in pair],
        mitre_techniques=[_mitre_technique(e) for e in pair],
        severity=severity,
        confidence=confidence,
        summary=(
            f"malicious-dependency + leaked-secret within {COMPOSITE_WINDOW_SECONDS}s "
            f"({successes}/2 succeeded)"
        ),
    )


def _find_composite_incidents(events: list[EventORM], claimed: set[str]) -> list[IncidentORM]:
    incidents: list[IncidentORM] = []
    dependency_events = [
        e for e in events if e.event_id not in claimed and _scenario_name(e) == _COMPOSITE_DEPENDENCY_SCENARIO
    ]
    secret_events = [
        e for e in events if e.event_id not in claimed and _scenario_name(e) == _COMPOSITE_SECRET_SCENARIO
    ]

    for dependency in dependency_events:
        if dependency.event_id in claimed:
            continue
        for secret in secret_events:
            if secret.event_id in claimed:
                continue
            if abs((dependency.timestamp - secret.timestamp).total_seconds()) <= COMPOSITE_WINDOW_SECONDS:
                incidents.append(_build_composite_incident(dependency, secret))
                claimed.add(dependency.event_id)
                claimed.add(secret.event_id)
                break

    return incidents


def correlate(events: list[EventORM]) -> list[IncidentORM]:
    events = sorted(events, key=lambda e: e.timestamp)
    claimed: set[str] = set()

    incidents: list[IncidentORM] = []
    incidents.extend(_find_composite_incidents(events, claimed))
    incidents.extend(_find_same_source_incidents(events, claimed))
    return incidents


def run_correlation(session: Session) -> list[IncidentORM]:
    already_correlated: set[str] = set()
    for incident in session.query(IncidentORM).all():
        already_correlated.update(incident.correlated_event_ids or [])

    events = [
        event
        for event in session.query(EventORM).order_by(EventORM.timestamp).all()
        if event.event_id not in already_correlated
    ]

    new_incidents = correlate(events)
    for incident in new_incidents:
        session.add(incident)
    session.commit()

    return new_incidents