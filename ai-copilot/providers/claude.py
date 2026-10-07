from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import anthropic

from models import CopilotRequest, CopilotResponse, ProposedAction
from providers.base import AIProvider

DEFAULT_MODEL = "claude-sonnet-5"

_MAX_VALIDATION_RETRIES = 2

_SYSTEM_PROMPT = """\
You are Bantis's AI Copilot. You analyze one correlated security \
incident from a supply-chain detection system and respond with your \
reasoning and a recommended next step.

You never execute anything yourself -- you only recommend. Respond \
with exactly one JSON object, nothing else before or after it, \
matching this shape:

{
  "reasoning": "<your analysis, in plain language>",
  "confidence": <float 0.0-1.0, your own confidence in this analysis>,
  "proposed_action": {
    "type": "<one of: notify_operator, flag_for_review, suggest_investigation, no_action_recommended>",
    "description": "<one short sentence>",
    "requires_approval": true
  }
}

requires_approval must always be exactly true. It is not your choice --\
every action in v1 requires a human operator's approval before anything \
happens, with no exception."""


class ClaudeProvider(AIProvider):
    """The AIProvider implementation ADR 0003's abstraction exists for --
    swapping in a different provider later means writing a new class
    that implements AIProvider, not touching anything that calls
    analyze().

    `client` is accepted for dependency injection: tests pass a fake
    object with a `.messages.create()` method instead of this talking to
    the real API, the same reason attack-sim's tests inject a fake
    subprocess.run rather than needing a real docker/gitleaks install.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        client: anthropic.Anthropic | None = None,
    ) -> None:
        self._client = client or anthropic.Anthropic(api_key=api_key or os.environ["ANTHROPIC_API_KEY"])
        self._model = model

    def analyze(self, request: CopilotRequest) -> CopilotResponse:
        payload = request.model_dump_json()
        last_error: str | None = None

        for attempt in range(_MAX_VALIDATION_RETRIES + 1):
            user_message = payload if attempt == 0 else (
                f"{payload}\n\nYour previous response was invalid: {last_error}. "
                "Return ONLY the corrected JSON object, nothing else."
            )

            try:
                reply = self._client.messages.create(
                    model=self._model,
                    max_tokens=1024,
                    system=_SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": user_message}],
                )
            except anthropic.APIError as exc:
                return _analysis_failed(request.incident.incident_id, self._model, str(exc))

            try:
                return _parse_response(reply, request.incident.incident_id, self._model)
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                last_error = str(exc)

        return _analysis_failed(request.incident.incident_id, self._model, last_error)


def _parse_response(reply: anthropic.types.Message, incident_id: str, model: str) -> CopilotResponse:
    raw_text = "".join(block.text for block in reply.content if block.type == "text")
    parsed = json.loads(raw_text)

    return CopilotResponse(
        incident_id=incident_id,
        reasoning=parsed["reasoning"],
        confidence=parsed["confidence"],
        proposed_action=ProposedAction(**parsed["proposed_action"]),
        model=model,
        generated_at=datetime.now(timezone.utc),
    )


def _analysis_failed(incident_id: str, model: str, reason: str | None) -> CopilotResponse:
    return CopilotResponse(
        incident_id=incident_id,
        reasoning=f"analysis unavailable: {reason or 'unknown error'}",
        confidence=0.0,
        proposed_action=ProposedAction(
            type="analysis_failed",
            description="The AI Copilot could not produce a valid analysis for this incident.",
            requires_approval=True,
        ),
        model=model,
        generated_at=datetime.now(timezone.utc),
    )