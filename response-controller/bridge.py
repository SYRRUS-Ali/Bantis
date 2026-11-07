"""Join deterministic policy proposals to independently recorded review context."""

import os
import pwd
from datetime import UTC, datetime
from pathlib import Path

from approval_flow import ApprovalFlow
from incident_client import IncidentClient
from incident_policy import IncidentFacts, propose_hold
from kill_switch import Level, trip
from recommendations import RecommendationIntegrityError, read_recommendations


def sync_incidents(client: IncidentClient, flow: ApprovalFlow, *, state_dir: Path,
                   decision_log: Path | None, since: datetime, execute: bool = False,
                   now: datetime | None = None) -> list[dict]:
    now = now or datetime.now(UTC)
    try:
        recommendations = read_recommendations(decision_log)
    except RecommendationIntegrityError:
        trip(state_dir, Level.EXECUTION_OFF, "recommendation decision log integrity check failed", ai_off=True)
        flow.store.record({"action_id": "bridge", "event": "kill_switch_tripped",
                           "actor": pwd.getpwuid(os.getuid()).pw_name, "at": now.isoformat(),
                           "level": Level.EXECUTION_OFF.value, "ai_off": True,
                           "reason": "recommendation decision log integrity check failed"})
        raise
    reports = []
    for raw in client.incidents_since(since):
        incident = IncidentFacts.model_validate(raw)
        if incident.created_at < since:
            continue
        # Recommendations are deliberately absent from the policy's arguments.
        events = client.events(incident.incident_id)
        proposal = propose_hold(incident, events, now)
        context = recommendations.get(incident.incident_id, {
            "status": "unavailable", "label": "Copilot output — untrusted review context",
        })
        if proposal is None:
            reports.append({"incident_id": incident.incident_id, "status": "no_policy_action", "copilot": context})
            continue
        facts = incident.model_dump(mode="json")
        facts["evidence"] = [{"event_id": e["event_id"], "source": e.get("source"),
                              "event_type": e.get("event_type"),
                              "scenario": e["details"].get("scenario"), "status": e["details"].get("status")}
                             for e in events]
        status = flow.ingest_policy(proposal, facts, context, now=now)
        if status == "pending" and proposal.is_expired(now):
            status = "expired"
        report = {"incident_id": incident.incident_id, "action_id": proposal.action_id,
                  "status": status, "copilot": context}
        if execute and status == "pending":
            report["outcome"] = flow.run_automatic(proposal.action_id, now=now).model_dump(mode="json")
            report["status"] = report["outcome"]["status"]
        reports.append(report)
    return reports