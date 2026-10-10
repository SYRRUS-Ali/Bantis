from __future__ import annotations

from datetime import datetime, timezone

from models import CopilotRequest, EvidenceEntry, IncidentPayload

SUMMARY_FIELDS_ALLOWLIST = frozenset({"artifact", "tool_returncode", "registry", "image"})


class MissingEvidenceError(ValueError):
    pass


def as_utc_datetime(value: str | datetime) -> datetime:
    moment = value if isinstance(value, datetime) else datetime.fromisoformat(value.replace("Z", "+00:00"))
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _to_evidence_entry(event: dict) -> EvidenceEntry:
    details = event.get("details") or {}
    return EvidenceEntry(
        event_id=event["event_id"],
        timestamp=as_utc_datetime(event["timestamp"]),
        source=event["source"],
        event_type=event["event_type"],
        scenario=details.get("scenario"),
        status=details.get("status"),
        mitre_technique=details.get("mitre_technique"),
        summary_fields={key: details[key] for key in SUMMARY_FIELDS_ALLOWLIST if key in details},
    )


def build_copilot_request(incident: dict, events: list[dict]) -> CopilotRequest:
    events_by_id = {event["event_id"]: event for event in events}
    missing = [event_id for event_id in incident["correlated_event_ids"] if event_id not in events_by_id]
    if missing:
        raise MissingEvidenceError(
            f"incident {incident['incident_id']!r} references events not provided: {missing}"
        )

    timeline = [_to_evidence_entry(events_by_id[event_id]) for event_id in incident["correlated_event_ids"]]
    timeline.sort(key=lambda entry: (entry.timestamp, entry.event_id))

    return CopilotRequest(
        incident=IncidentPayload(**{**incident, "created_at": as_utc_datetime(incident["created_at"])}),
        evidence_timeline=timeline,
    )