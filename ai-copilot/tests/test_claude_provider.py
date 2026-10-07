import json
from datetime import datetime, timezone
from types import SimpleNamespace

import anthropic
import pytest

from models import CopilotRequest, EvidenceEntry, IncidentPayload
from providers.claude import ClaudeProvider

_T0 = datetime(2026, 10, 7, 12, 0, 0, tzinfo=timezone.utc)


def _request() -> CopilotRequest:
    return CopilotRequest(
        incident=IncidentPayload(
            incident_id="inc-1",
            created_at=_T0,
            pattern="composite-dependency-secret",
            window_seconds=300,
            correlated_event_ids=["dep-1", "sec-1"],
            mitre_techniques=["T1195.001", "T1552.001"],
            severity="high",
            confidence=0.6,
            summary="malicious-dependency + leaked-secret within 300s",
        ),
        evidence_timeline=[
            EvidenceEntry(
                event_id="dep-1",
                timestamp=_T0,
                source="attack-sim",
                event_type="attack_scenario_run",
                scenario="malicious-dependency",
                status="failure",
                mitre_technique="T1195.001",
                summary_fields={"artifact": "fake-package==0.0.0", "tool_returncode": 1},
            ),
        ],
    )


def _text_message(payload: dict) -> SimpleNamespace:
    return SimpleNamespace(content=[SimpleNamespace(type="text", text=json.dumps(payload))])


_VALID_REPLY = {
    "reasoning": "Both halves were defended but close in time.",
    "confidence": 0.7,
    "proposed_action": {
        "type": "flag_for_review",
        "description": "Escalate to the operator.",
        "requires_approval": True,
    },
}


class _FakeMessages:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def _fake_client(*responses):
    return SimpleNamespace(messages=_FakeMessages(responses))


def test_analyze_returns_a_validated_response_on_the_first_try():
    client = _fake_client(_text_message(_VALID_REPLY))
    provider = ClaudeProvider(client=client)

    response = provider.analyze(_request())

    assert response.incident_id == "inc-1"
    assert response.reasoning == _VALID_REPLY["reasoning"]
    assert response.confidence == 0.7
    assert response.proposed_action.type == "flag_for_review"
    assert response.proposed_action.requires_approval is True
    assert client.messages.calls[0]["system"]  # system prompt was sent
    assert len(client.messages.calls) == 1


def test_analyze_retries_on_malformed_json_then_succeeds():
    client = _fake_client(
        _text_message({"not": "the expected shape"}),
        _text_message(_VALID_REPLY),
    )
    provider = ClaudeProvider(client=client)

    response = provider.analyze(_request())

    assert response.proposed_action.type == "flag_for_review"
    assert len(client.messages.calls) == 2
    # the retry tells the model what went wrong
    assert "previous response was invalid" in client.messages.calls[1]["messages"][0]["content"]


def test_analyze_falls_back_to_analysis_failed_after_exhausting_retries():
    client = _fake_client(
        _text_message({"bad": 1}),
        _text_message({"bad": 2}),
        _text_message({"bad": 3}),
    )
    provider = ClaudeProvider(client=client)

    response = provider.analyze(_request())

    assert response.proposed_action.type == "analysis_failed"
    assert response.confidence == 0.0
    assert "analysis unavailable" in response.reasoning
    assert len(client.messages.calls) == 3  # original attempt + 2 retries, no more


def test_analyze_never_retries_a_provider_level_error():
    client = _fake_client(anthropic.APIConnectionError(request=SimpleNamespace()))
    provider = ClaudeProvider(client=client)

    response = provider.analyze(_request())

    assert response.proposed_action.type == "analysis_failed"
    assert len(client.messages.calls) == 1  # no retry -- a dead connection won't fix itself


def test_a_response_that_tries_to_disable_approval_is_rejected_and_falls_back():
    tampered = dict(_VALID_REPLY, proposed_action=dict(_VALID_REPLY["proposed_action"], requires_approval=False))
    client = _fake_client(_text_message(tampered), _text_message(tampered), _text_message(tampered))
    provider = ClaudeProvider(client=client)

    response = provider.analyze(_request())

    assert response.proposed_action.type == "analysis_failed"
    assert response.proposed_action.requires_approval is True


def test_an_unknown_action_type_is_rejected_and_falls_back():
    tampered = dict(_VALID_REPLY, proposed_action=dict(_VALID_REPLY["proposed_action"], type="delete_everything"))
    client = _fake_client(_text_message(tampered), _text_message(tampered), _text_message(tampered))
    provider = ClaudeProvider(client=client)

    response = provider.analyze(_request())

    assert response.proposed_action.type == "analysis_failed"


def test_requires_an_api_key_when_no_client_is_injected(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    with pytest.raises(KeyError):
        ClaudeProvider()