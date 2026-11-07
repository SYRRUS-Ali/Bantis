"""Read a verified decision-log snapshot as untrusted review context only."""

import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    ValidationError,
    field_validator,
)


class RecommendationIntegrityError(ValueError):
    pass


class SuggestedAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["notify_operator", "flag_for_review", "suggest_investigation", "no_action_recommended", "analysis_failed"]
    description: str = Field(max_length=16000)
    requires_approval: StrictBool

    @field_validator("requires_approval")
    @classmethod
    def approval_required(cls, value):
        if not value:
            raise ValueError("recommendations must require approval")
        return value


class Recommendation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str
    reasoning: str = Field(min_length=1, max_length=16000)
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False)
    proposed_action: SuggestedAction
    model: str = Field(max_length=256)
    generated_at: datetime


def read_recommendations(path: Path | None) -> dict[str, dict]:
    if path is None or not path.exists():
        return {}
    try:
        uri = path.resolve().as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True)) as connection:
            connection.execute("BEGIN")
            rows = connection.execute("SELECT seq, record_id, incident_id, record_json, prev_hash, record_hash FROM decisions ORDER BY seq").fetchall()
        previous = "0" * 64
        result = {}
        for seq, record_id, incident_id, body, prev, digest in rows:
            expected = hashlib.sha256(f"{prev}\n{body}".encode()).hexdigest()
            if prev != previous or digest != expected:
                raise RecommendationIntegrityError(f"decision log integrity check failed at sequence {seq}")
            previous = digest
            record = json.loads(body)
            if record["record_id"] != record_id or record["incident_id"] != incident_id or incident_id in result:
                raise RecommendationIntegrityError("decision record identity is inconsistent or duplicated")
            response = record.get("response")
            context = {"status": "skipped" if record.get("outcome") == "skipped" else "unavailable",
                       "label": "Copilot output — untrusted review context",
                       "record_id": record_id, "record_hash": digest}
            if response is not None:
                try:
                    recommendation = Recommendation.model_validate(response)
                    if recommendation.incident_id != incident_id:
                        raise RecommendationIntegrityError("recommendation incident does not match its decision")
                    context.update(status="analysis_failed" if recommendation.proposed_action.type == "analysis_failed" else "available",
                                   recommendation=recommendation.model_dump(mode="json"))
                except ValidationError:
                    context["status"] = "invalid"
            result[incident_id] = context
        return result
    except (sqlite3.Error, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise RecommendationIntegrityError(f"decision log could not be verified ({type(exc).__name__})") from exc
