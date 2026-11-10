"""Bounded, server-side access to the Copilot's public record fields."""

import json
from datetime import datetime
from typing import Literal
from urllib.parse import quote

import httpx
from pydantic import BaseModel, Field, ValidationError, field_validator

from .detection import Incident, UpstreamError


class Recommendation(BaseModel):
    type: Literal[
        "notify_operator",
        "flag_for_review",
        "suggest_investigation",
        "no_action_recommended",
        "analysis_failed",
    ]
    description: str
    requires_approval: Literal[True]


class Analysis(BaseModel):
    incident_id: str
    reasoning: str
    confidence: float = Field(ge=0, le=1)
    proposed_action: Recommendation
    model: str
    generated_at: datetime


class AnalysisRecord(BaseModel):
    incident_id: str
    status: Literal["not_recorded", "skipped", "failed", "analyzed"]
    recorded_at: datetime | None = None
    record_id: str | None = None
    outcome: str | None = None
    model: str | None = None
    note: str | None = None
    analysis: Analysis | None = None
    can_ask: bool = False


class Question(BaseModel):
    question: str = Field(min_length=1, max_length=2000)

    @field_validator("question")
    @classmethod
    def meaningful(cls, value):
        if not value.strip():
            raise ValueError("Question must not be empty")
        return value.strip()


class Followup(BaseModel):
    followup_id: str
    incident_id: str
    asked_at: datetime
    question: str
    answer: str
    model: str

    @field_validator("asked_at")
    @classmethod
    def utc_time(cls, value):
        return Incident.utc_time(value)


class CopilotClient:
    def __init__(self, client: httpx.AsyncClient, configured: bool):
        self.client = client
        self.configured = configured

    async def request(
        self, incident_id: str, resource: str, question: Question | None = None
    ):
        if not self.configured:
            raise UpstreamError(503, "Copilot is not configured on this dashboard")
        path = f"incidents/{quote(incident_id, safe='')}/{resource}"
        try:
            async with self.client.stream(
                "POST" if question else "GET",
                path,
                json=question.model_dump() if question else None,
                timeout=90.0 if question else 3.0,
            ) as response:
                if response.status_code not in {200, 201}:
                    messages = {
                        404: "No recorded Copilot context for this incident",
                        409: "Recorded analysis is required before asking questions",
                        422: "Question rejected. Use up to 2,000 characters and omit credentials",
                        429: "Copilot rate or token budget limit reached. Try again later",
                    }
                    code = (
                        response.status_code
                        if response.status_code in messages
                        else 503
                    )
                    raise UpstreamError(
                        code,
                        messages.get(
                            code, "Copilot service or provider is unavailable"
                        ),
                    )
                content = bytearray()
                async for chunk in response.aiter_bytes():
                    content.extend(chunk)
                    if len(content) > 2_000_000:
                        raise UpstreamError(
                            502, "Copilot response exceeded the size limit"
                        )
            raw = json.loads(content)
            if resource == "analysis":
                result = AnalysisRecord.model_validate(raw)
                if result.analysis and result.analysis.incident_id != incident_id:
                    raise ValueError("Mismatched analysis")
            elif question:
                result = Followup.model_validate(raw)
            else:
                if not isinstance(raw, list):
                    raise ValueError("Expected conversation history")
                records = [Followup.model_validate(item) for item in raw]
                if any(item.incident_id != incident_id for item in records):
                    raise ValueError("Mismatched conversation")
                return sorted(
                    records, key=lambda item: (item.asked_at, item.followup_id)
                )
            if result.incident_id != incident_id:
                raise ValueError("Mismatched incident")
            return result
        except (httpx.HTTPError, OSError) as exc:
            message = "Copilot request timed out or service is unavailable"
            if question:
                message += (
                    ". Delivery is uncertain; refresh conversation before retrying"
                )
            raise UpstreamError(503, message) from exc
        except (ValidationError, ValueError, UnicodeError, RecursionError) as exc:
            raise UpstreamError(502, "Copilot returned invalid data") from exc