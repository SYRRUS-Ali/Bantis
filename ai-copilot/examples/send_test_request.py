#!/usr/bin/env python3

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from models import CopilotRequest, EvidenceEntry, IncidentPayload  # noqa: E402
from providers.claude import ClaudeProvider  # noqa: E402

_NOW = datetime.now(timezone.utc)

request = CopilotRequest(
    incident=IncidentPayload(
        incident_id="manual-test-incident",
        created_at=_NOW,
        pattern="composite-dependency-secret",
        window_seconds=300,
        correlated_event_ids=["dep-1", "sec-1"],
        mitre_techniques=["T1195.001", "T1552.001"],
        severity="high",
        confidence=0.6,
        summary="malicious-dependency + leaked-secret within 300s (0/2 succeeded)",
    ),
    evidence_timeline=[
        EvidenceEntry(
            event_id="dep-1",
            timestamp=_NOW,
            source="attack-sim",
            event_type="attack_scenario_run",
            scenario="malicious-dependency",
            status="failure",
            mitre_technique="T1195.001",
            summary_fields={"artifact": "bantis-attack-sim-simulated-malicious-dependency==0.0.0", "tool_returncode": 1},
        ),
        EvidenceEntry(
            event_id="sec-1",
            timestamp=_NOW,
            source="attack-sim",
            event_type="attack_scenario_run",
            scenario="leaked-secret",
            status="failure",
            mitre_technique="T1552.001",
            summary_fields={"artifact": "config.py", "tool_returncode": 1},
        ),
    ],
)

print("Sending request to Claude...")
provider = ClaudeProvider()
response = provider.analyze(request)

print("\n--- CopilotResponse ---")
print(response.model_dump_json(indent=2))