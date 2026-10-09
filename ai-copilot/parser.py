from __future__ import annotations

import json
import math
import re
from datetime import datetime, timezone

from pydantic import ValidationError

from models import CopilotResponse, ProposedAction

MODEL_ACTION_TYPES = frozenset(
    {"notify_operator", "flag_for_review", "suggest_investigation", "no_action_recommended"}
)

_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


class OutputParseError(ValueError):
    pass


def _extract_json_object(text: str) -> dict:
    fenced = _FENCE.search(text)
    candidate = fenced.group(1) if fenced else text

    try:
        whole = json.loads(candidate)
    except json.JSONDecodeError:
        pass
    else:
        if isinstance(whole, dict):
            return whole
        raise OutputParseError(f"the response must be a single JSON object, got a JSON {type(whole).__name__}")

    decoder = json.JSONDecoder()
    for start in (i for i, char in enumerate(candidate) if char == "{"):
        try:
            value, _ = decoder.raw_decode(candidate, start)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value

    if not text.strip():
        raise OutputParseError("the response was empty")
    raise OutputParseError("the response did not contain a JSON object")


def _require_confidence(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise OutputParseError(f"confidence must be a number between 0.0 and 1.0, got {value!r}")
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise OutputParseError(f"confidence must be a number between 0.0 and 1.0, got {value!r}")
    return float(value)


def _require_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise OutputParseError(f"{field} must be a non-empty string, got {value!r}")
    return value.strip()


def _require_action(value: object) -> ProposedAction:
    if not isinstance(value, dict):
        raise OutputParseError(f"proposed_action must be a JSON object, got {value!r}")

    action_type = value.get("type")
    if action_type not in MODEL_ACTION_TYPES:
        raise OutputParseError(
            f"proposed_action.type must be one of {sorted(MODEL_ACTION_TYPES)}, got {action_type!r}"
        )
    if value.get("requires_approval") is not True:
        raise OutputParseError(
            "proposed_action.requires_approval must be exactly true -- every v1 action needs "
            f"human approval, got {value.get('requires_approval')!r}"
        )
    return ProposedAction(
        type=action_type,
        description=_require_text(value.get("description"), "proposed_action.description"),
        requires_approval=True,
    )


def parse_model_output(text: str, incident_id: str, model: str) -> CopilotResponse:
    parsed = _extract_json_object(text)

    for field in ("reasoning", "confidence", "proposed_action"):
        if field not in parsed:
            raise OutputParseError(f"missing required field {field!r}")

    try:
        return CopilotResponse(
            incident_id=incident_id,
            reasoning=_require_text(parsed["reasoning"], "reasoning"),
            confidence=_require_confidence(parsed["confidence"]),
            proposed_action=_require_action(parsed["proposed_action"]),
            model=model,
            generated_at=datetime.now(timezone.utc),
        )
    except ValidationError as exc:
        raise OutputParseError(f"response failed schema validation: {exc.errors()[0]['msg']}") from exc