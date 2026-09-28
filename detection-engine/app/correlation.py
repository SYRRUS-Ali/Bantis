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

_IMAGE_PULL_EVENT_TYPE = "container_image_pull"
_UNTRUSTED_REGISTRY_MITRE_TECHNIQUE = "T1195.002"

TRUSTED_REGISTRIES = {"docker.io", "ghcr.io"}


def _scenario_name(event: EventORM) -> str | None:
    return (event.details or {}).get("scenario")


def _is_success(event: EventORM) -> bool:
    return (event.details or {}).get("status") == "success"


def _is_error(event: EventORM) -> bool:
    return (event.details or {}).get("status") == "error"


def _is_image_pull(event: EventORM) -> bool:
    return event.event_type == _IMAGE_PULL_EVENT_TYPE


def _is_untrusted_registry_pull(event: EventORM) -> bool:
    if not _is_image_pull(event):
        return False
    registry = (event.details or {}).get("registry")
    return registry not in TRUSTED_REGISTRIES


def _mitre_technique(event: EventORM) -> str:
    return (event.details or {}).get("mitre_technique", "N/A")


def _count_successes(events: list[EventORM]) -> int:
    return sum(1 for e in events if _is_success(e))


def _confidence(base: float, per_success_bonus: float, successes: int, max_counted_successes: int) -> float:
    counted = min(successes, max_counted_successes)
    return round(base + per_success_bonus * counted, 2)


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
    successes = _count_successes(group)
    severity = "high" if successes > 0 else "medium"
    confidence = _confidence(base=0.3, per_success_bonus=0.2, successes=successes, max_counted_successes=1)

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
    successes = _count_successes(pair)
    severity = "critical" if successes == 2 else "high"
    confidence = _confidence(base=0.6, per_success_bonus=0.15, successes=successes, max_counted_successes=2)

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


def _build_untrusted_registry_incident(event: EventORM) -> IncidentORM:
    registry = (event.details or {}).get("registry", "unknown")
    image = (event.details or {}).get("image", "unknown")

    return IncidentORM(
        incident_id=str(uuid.uuid4()),
        created_at=datetime.now(timezone.utc),
        pattern="untrusted-registry-pull",
        window_seconds=0,
        correlated_event_ids=[event.event_id],
        mitre_techniques=[_UNTRUSTED_REGISTRY_MITRE_TECHNIQUE],
        severity="high",
        confidence=_confidence(base=0.7, per_success_bonus=0.0, successes=0, max_counted_successes=0),
        summary=f"image pulled from untrusted registry {registry!r}: {image}",
    )


def _find_untrusted_registry_incidents(events: list[EventORM], claimed: set[str]) -> list[IncidentORM]:
    incidents: list[IncidentORM] = []
    for event in events:
        if event.event_id in claimed:
            continue
        if _is_untrusted_registry_pull(event):
            incidents.append(_build_untrusted_registry_incident(event))
            claimed.add(event.event_id)

    return incidents


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
    events = [e for e in events if not _is_error(e)]
    events = sorted(events, key=lambda e: e.timestamp)
    claimed: set[str] = set()

    incidents: list[IncidentORM] = []
    incidents.extend(_find_composite_incidents(events, claimed))
    incidents.extend(_find_untrusted_registry_incidents(events, claimed))
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