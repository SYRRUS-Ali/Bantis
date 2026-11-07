import hashlib
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field, field_validator

from models import Proposal


class IncidentFacts(BaseModel):
    model_config = ConfigDict(extra="ignore")

    incident_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    created_at: datetime
    pattern: str
    correlated_event_ids: list[str] = Field(min_length=1)

    @field_validator("created_at")
    @classmethod
    def aware(cls, value):
        if value.tzinfo is None:
            raise ValueError("incident timestamp must include a timezone")
        return value.astimezone(UTC)


def propose_hold(incident: IncidentFacts, events: list[dict], now: datetime) -> Proposal | None:
    if not all(isinstance(e, dict) and isinstance(e.get("event_id"), str) and isinstance(e.get("details"), dict) for e in events):
        raise ValueError("invalid incident evidence")
    ids = incident.correlated_event_ids
    if len(set(ids)) != len(ids) or sorted(e.get("event_id", "") for e in events) != sorted(ids):
        raise ValueError("incident evidence is incomplete or duplicated")
    if incident.created_at > now:
        return None
    rule = None
    if incident.pattern == "composite-dependency-secret":
        details = [e.get("details") or {} for e in events]
        scenarios = [d.get("scenario") for d in details]
        if (len(events) == 2 and all(isinstance(s, str) for s in scenarios)
                and set(scenarios) == {"malicious-dependency", "leaked-secret"}
                and all(e.get("event_type") == "attack_scenario_run" and e.get("source") == "attack-sim" for e in events)
                and any(d.get("status") == "success" for d in details)):
            rule = "A3:composite-success"
    elif incident.pattern == "untrusted-registry-pull" and len(events) == 1:
        event = events[0]
        registry = (event.get("details") or {}).get("registry")
        if event.get("event_type") == "container_image_pull" and isinstance(registry, str) and registry.strip() and registry not in {"docker.io", "ghcr.io"}:
            rule = "A3:untrusted-registry"
    if rule is None:
        return None
    action_id = "act_" + hashlib.sha256(f"hold_promotion:{incident.incident_id}".encode()).hexdigest()[:32]
    return Proposal(action_id=action_id, incident_id=incident.incident_id, type="hold_promotion", params={},
                    policy_rule=rule, created_at=incident.created_at,
                    expires_at=incident.created_at + timedelta(hours=1))