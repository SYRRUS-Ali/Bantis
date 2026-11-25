from __future__ import annotations

import json
import math
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCENARIOS = {
    "malicious-dependency", "leaked-secret", "compromised-ci-step", "typosquatting",
}


def utc(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be an ISO 8601 string with a timezone")
    moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if moment.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return moment.astimezone(timezone.utc)


def nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def read_history(path: Path) -> list[dict]:
    """Read completed lines only; CLI result text and unrelated logs are ignored."""
    events: dict[str, dict] = {}
    with path.open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            if not line.endswith("\n"):
                raise ValueError(f"history line {number} is incomplete; retry after the writer finishes")
            if not line.lstrip().startswith(("{", "[")):
                continue  # attack-sim also prints a human-readable result line
            try:
                item = json.loads(line)
                if not isinstance(item, dict):
                    raise ValueError("expected a JSON object")
                if item.get("source") != "attack-sim" or item.get("event_type") != "attack_scenario_run":
                    continue
                details = item.get("details")
                if not isinstance(details, dict):
                    raise ValueError("scenario details must be an object")
                if details.get("scenario") not in SCENARIOS:
                    continue
                if not nonempty(item.get("event_id")):
                    raise ValueError("scenario event_id is required")
                if details.get("status") not in {"success", "failure", "error"}:
                    raise ValueError("unknown scenario status")
                event = {
                    "event_id": item["event_id"], "scenario": details["scenario"],
                    "status": details["status"], "timestamp": utc(item["timestamp"]).isoformat(),
                }
                previous = events.get(event["event_id"])
                if previous is not None and previous != event:
                    raise ValueError("conflicting duplicate event_id")
                events[event["event_id"]] = event
            except (ValueError, KeyError, TypeError) as exc:
                raise ValueError(f"invalid history line {number}: {exc}") from exc
    if not events:
        raise ValueError("history contains no M2 scenario outcomes; coverage is inconclusive")
    return sorted(events.values(), key=lambda event: (event["timestamp"], event["event_id"]))


def validate_incident(item: object) -> dict:
    if not isinstance(item, dict) or not nonempty(item.get("incident_id")):
        raise ValueError("incident_id is required")
    utc(item.get("created_at"))
    ids = item.get("correlated_event_ids")
    if not isinstance(ids, list) or not ids or not all(nonempty(value) for value in ids):
        raise ValueError("incident correlated_event_ids must be a nonempty string list")
    return {"incident_id": item["incident_id"], "created_at": item["created_at"],
            "correlated_event_ids": ids}


def compare(events: list[dict], incidents: list[dict], *, now: datetime,
            wait_seconds: float = 330, deadline: datetime | None = None) -> dict:
    if not math.isfinite(wait_seconds) or wait_seconds < 0:
        raise ValueError("wait_seconds must be finite and nonnegative")
    now = utc(now.isoformat())
    if deadline is not None:
        deadline = utc(deadline.isoformat())
    by_event: dict[str, list[dict]] = {}
    for raw in incidents:
        incident = validate_incident(raw)
        if utc(incident["created_at"]) > now:
            continue  # no future-created incident can establish observed coverage
        for event_id in set(incident["correlated_event_ids"]):
            by_event.setdefault(event_id, []).append(incident)
    results = []
    for event in events:
        emitted = utc(event["timestamp"])
        cutoff = deadline if deadline is not None else emitted + timedelta(seconds=wait_seconds)
        if emitted > now or cutoff < emitted:
            raise ValueError("history event is in the future or after the declared deadline")
        matches = sorted(by_event.get(event["event_id"], []),
                         key=lambda item: (utc(item["created_at"]), item["incident_id"]))
        if event["status"] == "error":
            state = "invalid"
        elif matches:
            state = "detected" if utc(matches[0]["created_at"]) <= cutoff else "late_detection"
        else:
            state = "gap" if now >= cutoff else "pending"
        results.append({**event, "deadline": cutoff.isoformat(), "state": state,
                        "gap_id": "gap:" + event["event_id"] if state in {"gap", "late_detection"} else None,
                        "incident_ids": [item["incident_id"] for item in matches],
                        "first_detected_at": matches[0]["created_at"] if matches else None})
    return {
        "schema_version": 1, "observed_at": now.isoformat(), "complete": True,
        "counts": {state: sum(item["state"] == state for item in results)
                   for state in ("detected", "gap", "late_detection", "pending", "invalid")},
        "runs": results,
    }