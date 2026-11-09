import json
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import quote

import httpx
from pydantic import BaseModel, Field, ValidationError, field_validator

Severity = Literal["low", "medium", "high", "critical"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
LIVE_DETAILS = {
    "scenario",
    "status",
    "mitre_technique",
    "artifact",
    "tool_returncode",
    "registry",
    "image",
}


class Incident(BaseModel):
    incident_id: str
    created_at: datetime
    pattern: str
    window_seconds: int = Field(ge=0)
    correlated_event_ids: list[str]
    mitre_techniques: list[str]
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    summary: str

    @field_validator("created_at")
    @classmethod
    def utc_time(cls, value):
        return (
            value.replace(tzinfo=timezone.utc)
            if value.tzinfo is None
            else value.astimezone(timezone.utc)
        )


class IncidentPage(BaseModel):
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    offset: int = Field(ge=0)
    items: list[Incident]


class Evidence(BaseModel):
    event_id: str
    timestamp: datetime
    source: str
    event_type: str
    details: dict[str, str | int | float | bool | None] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def utc_time(cls, value):
        return Incident.utc_time(value)


class LiveEvent(Evidence):
    received_at: datetime
    level: LogLevel
    logger: str

    @field_validator("received_at")
    @classmethod
    def received_utc(cls, value):
        return Incident.utc_time(value)

    @field_validator("level", mode="before")
    @classmethod
    def normalize_level(cls, value):
        return value.upper() if isinstance(value, str) else value

    @field_validator("details", mode="before")
    @classmethod
    def selected_details(cls, value):
        if not isinstance(value, dict):
            raise ValueError("Expected event details")
        return {
            key: item
            for key, item in value.items()
            if key in LIVE_DETAILS
            and (item is None or isinstance(item, (str, int, float, bool)))
        }


class LiveEventPage(BaseModel):
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=500)
    items: list[LiveEvent] = Field(max_length=500)

    @field_validator("items")
    @classmethod
    def unique_events(cls, items):
        if len({event.event_id for event in items}) != len(items):
            raise ValueError("Duplicate event IDs")
        return sorted(
            items, key=lambda event: (event.received_at, event.event_id), reverse=True
        )


class UpstreamError(Exception):
    def __init__(self, status: int, message: str):
        self.status = status
        self.message = message
        super().__init__(message)


class DetectionClient:
    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def get(self, path: str, params=None):
        try:
            async with self.client.stream("GET", path, params=params) as response:
                if response.status_code == 404:
                    raise UpstreamError(404, "Incident not found")
                if response.status_code != 200:
                    raise UpstreamError(503, "Detection Engine is unavailable")
                content = bytearray()
                async for chunk in response.aiter_bytes():
                    content.extend(chunk)
                    if len(content) > 2_000_000:
                        raise UpstreamError(
                            502, "Detection Engine response exceeded the size limit"
                        )
            return json.loads(content)
        except (httpx.HTTPError, OSError) as exc:
            raise UpstreamError(503, "Detection Engine is unavailable") from exc
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise UpstreamError(502, "Detection Engine returned invalid data") from exc

    async def incidents(self, params=None) -> IncidentPage:
        try:
            return IncidentPage.model_validate(await self.get("incidents", params))
        except ValidationError as exc:
            raise UpstreamError(
                502, "Detection Engine returned invalid incident data"
            ) from exc

    async def live_events(self) -> LiveEventPage:
        try:
            return LiveEventPage.model_validate(
                await self.get("events", {"limit": 500})
            )
        except ValidationError as exc:
            raise UpstreamError(
                502, "Detection Engine returned invalid live event data"
            ) from exc

    async def incident(self, incident_id: str) -> Incident:
        try:
            return Incident.model_validate(
                await self.get(f"incidents/{quote(incident_id, safe='')}")
            )
        except ValidationError as exc:
            raise UpstreamError(
                502, "Detection Engine returned invalid incident data"
            ) from exc

    async def evidence(self, incident_id: str) -> list[Evidence]:
        raw = await self.get(f"incidents/{quote(incident_id, safe='')}/events")
        allowed = {
            "scenario",
            "status",
            "mitre_technique",
            "artifact",
            "tool_returncode",
            "registry",
            "image",
        }
        try:
            if not isinstance(raw, list):
                raise TypeError("Expected an evidence list")
            result = []
            for event in raw:
                details = event.get("details", {})
                selected = {
                    key: value for key, value in details.items() if key in allowed
                }
                result.append(Evidence.model_validate({**event, "details": selected}))
            return sorted(
                result,
                key=lambda item: (
                    item.timestamp.replace(tzinfo=timezone.utc)
                    if item.timestamp.tzinfo is None
                    else item.timestamp.astimezone(timezone.utc),
                    item.event_id,
                ),
            )
        except (ValidationError, ValueError, AttributeError, TypeError) as exc:
            raise UpstreamError(
                502, "Detection Engine returned invalid evidence data"
            ) from exc