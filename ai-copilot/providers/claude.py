from __future__ import annotations

import os

import anthropic

from models import CopilotRequest, CopilotResponse
from parser import OutputParseError, parse_model_output
from providers.base import AIProvider

DEFAULT_MODEL = "claude-sonnet-5"

MAX_VALIDATION_RETRIES = 2
_MAX_TOKENS = 1024

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
    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        client: anthropic.Anthropic | None = None,
    ) -> None:
        self._client = client or anthropic.Anthropic(api_key=api_key or os.environ["ANTHROPIC_API_KEY"])
        self._model = model

    def analyze(self, request: CopilotRequest) -> CopilotResponse:
        incident_id = request.incident.incident_id
        messages: list[dict] = [{"role": "user", "content": request.model_dump_json()}]
        last_error = "no attempt made"
        attempts = MAX_VALIDATION_RETRIES + 1

        for _ in range(attempts):
            try:
                reply = self._client.messages.create(
                    model=self._model,
                    max_tokens=_MAX_TOKENS,
                    system=_SYSTEM_PROMPT,
                    messages=messages,
                )
            except anthropic.APIError as exc:
                return CopilotResponse.analysis_failed(incident_id, self._model, f"provider error: {exc}")

            text = "".join(block.text for block in reply.content if block.type == "text")
            try:
                if getattr(reply, "stop_reason", None) == "max_tokens":
                    raise OutputParseError(
                        f"the response was cut off at the {_MAX_TOKENS}-token limit -- keep the reasoning shorter"
                    )
                return parse_model_output(text, incident_id, self._model)
            except OutputParseError as exc:
                last_error = str(exc)
                messages = _with_correction(messages, text, last_error)

        return CopilotResponse.analysis_failed(incident_id, self._model, f"no valid response after {attempts} attempts: {last_error}")


def _with_correction(messages: list[dict], bad_text: str, error: str) -> list[dict]:
    correction = f"Your previous response was invalid: {error}. Return ONLY the corrected JSON object, nothing else."
    if bad_text.strip():
        return [*messages, {"role": "assistant", "content": bad_text}, {"role": "user", "content": correction}]
    return [{"role": "user", "content": f"{messages[0]['content']}\n\n{correction}"}]