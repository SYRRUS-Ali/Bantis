from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field, field_validator

_VALID_ACTION_TYPES = {
    "notify_operator",
    "flag_for_review",
    "suggest_investigation",
    "no_action_recommended",
    "analysis_failed",
}


class IncidentPayload(BaseModel):

    incident_id: str
    created_at: datetime
    pattern: str
    window_seconds: int
    correlated_event_ids: list[str]
    mitre_techniques: list[str]
    severity: str
    confidence: float
    summary: str


class EvidenceEntry(BaseModel):

    event_id: str
    timestamp: datetime
    source: str
    event_type: str
    scenario: str | None = None
    status: str | None = None
    mitre_technique: str | None = None
    summary_fields: dict = Field(default_factory=dict)


class CopilotRequest(BaseModel):

    incident: IncidentPayload
    evidence_timeline: list[EvidenceEntry]


class ProposedAction(BaseModel):

    type: str
    description: str
    requires_approval: bool = True

    @field_validator("type")
    @classmethod
    def _type_is_known(cls, value: str) -> str:
        if value not in _VALID_ACTION_TYPES:
            raise ValueError(f"proposed_action.type must be one of {sorted(_VALID_ACTION_TYPES)}, got {value!r}")
        return value

    @field_validator("requires_approval")
    @classmethod
    def _approval_always_required(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("proposed_action.requires_approval must be true in v1 (ADR 0004 -- recommend-only)")
        return value


class CopilotResponse(BaseModel):

    incident_id: str
    reasoning: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    proposed_action: ProposedAction
    model: str
    generated_at: datetime

    @classmethod
    def analysis_failed(cls, incident_id: str, model: str, reason: str) -> CopilotResponse:
        return cls(
            incident_id=incident_id,
            reasoning=f"analysis unavailable: {reason}",
            confidence=0.0,
            proposed_action=ProposedAction(
                type="analysis_failed",
                description="The AI Copilot could not produce a valid analysis for this incident.",
                requires_approval=True,
            ),
            model=model,
            generated_at=datetime.now(timezone.utc),
        )