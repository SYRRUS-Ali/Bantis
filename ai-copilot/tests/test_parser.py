import json

import pytest

from parser import MODEL_ACTION_TYPES, OutputParseError, parse_model_output

_VALID = {
    "reasoning": "Two defended supply-chain attempts close together.",
    "confidence": 0.7,
    "proposed_action": {"type": "flag_for_review", "description": "Escalate.", "requires_approval": True},
}


def _parse(payload) -> object:
    text = payload if isinstance(payload, str) else json.dumps(payload)
    return parse_model_output(text, incident_id="inc-1", model="test-model")


def _with(**overrides) -> dict:
    return {**_VALID, **overrides}


def _with_action(**overrides) -> dict:
    return {**_VALID, "proposed_action": {**_VALID["proposed_action"], **overrides}}


# ---- Accepted ---------------------------------------------------------------

def test_a_plain_json_object_parses():
    response = _parse(_VALID)

    assert response.incident_id == "inc-1"
    assert response.model == "test-model"
    assert response.confidence == 0.7
    assert response.proposed_action.type == "flag_for_review"
    assert response.proposed_action.requires_approval is True


@pytest.mark.parametrize(
    "wrapped",
    [
        "```json\n{body}\n```",
        "```\n{body}\n```",
        "Here is my analysis:\n{body}",
        "{body}\nLet me know if you need more detail.",
        "Note: I considered {{possible}} explanations first.\n{body}",
    ],
    ids=["json-fence", "bare-fence", "prose-before", "prose-after", "braces-in-prose-before"],
)
def test_json_surrounded_by_fences_or_prose_is_extracted(wrapped):
    response = _parse(wrapped.format(body=json.dumps(_VALID)))

    assert response.proposed_action.type == "flag_for_review"


@pytest.mark.parametrize("confidence", [0, 1, 0.0, 1.0, 0.5])
def test_confidence_accepts_ints_and_floats_within_range(confidence):
    assert _parse(_with(confidence=confidence)).confidence == float(confidence)


def test_reasoning_and_description_are_stripped():
    response = _parse(_with(reasoning="  padded  ", proposed_action={**_VALID["proposed_action"], "description": " d "}))

    assert response.reasoning == "padded"
    assert response.proposed_action.description == "d"


def test_extra_keys_are_ignored_and_cannot_override_bantis_owned_fields():
    response = _parse(_with(incident_id="someone-else", model="spoofed", extra="ignored"))

    assert response.incident_id == "inc-1"
    assert response.model == "test-model"


@pytest.mark.parametrize("action_type", sorted(MODEL_ACTION_TYPES))
def test_every_model_action_type_is_accepted(action_type):
    assert _parse(_with_action(type=action_type)).proposed_action.type == action_type


# ---- Rejected: structure ----------------------------------------------------

@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "empty"),
        ("   \n", "empty"),
        ("I think this incident is serious.", "did not contain a JSON object"),
        (json.dumps([_VALID]), "single JSON object, got a JSON list"),
        (json.dumps("just a string"), "single JSON object, got a JSON str"),
        ('{"reasoning": "cut off mid-', "did not contain a JSON object"),
    ],
    ids=["empty", "whitespace", "prose-only", "top-level-array", "top-level-string", "truncated"],
)
def test_structurally_invalid_output_is_rejected(text, message):
    with pytest.raises(OutputParseError, match=message):
        _parse(text)


@pytest.mark.parametrize("field", ["reasoning", "confidence", "proposed_action"])
def test_a_missing_required_field_is_named(field):
    payload = {key: value for key, value in _VALID.items() if key != field}

    with pytest.raises(OutputParseError, match=f"missing required field '{field}'"):
        _parse(payload)


# ---- Rejected: types and values ---------------------------------------------

@pytest.mark.parametrize(
    "confidence",
    [True, False, "0.7", None, -0.1, 1.01, 7],
    ids=["bool-true", "bool-false", "string", "null", "negative", "just-above-one", "out-of-range-int"],
)
def test_confidence_must_be_a_number_in_range(confidence):
    with pytest.raises(OutputParseError, match="confidence must be a number"):
        _parse(_with(confidence=confidence))


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_confidence_is_rejected(literal):
    text = json.dumps(_VALID).replace("0.7", literal)

    with pytest.raises(OutputParseError, match="confidence must be a number"):
        _parse(text)


@pytest.mark.parametrize("reasoning", ["", "   ", None, 42])
def test_reasoning_must_be_non_empty_text(reasoning):
    with pytest.raises(OutputParseError, match="reasoning must be a non-empty string"):
        _parse(_with(reasoning=reasoning))


def test_proposed_action_must_be_an_object():
    with pytest.raises(OutputParseError, match="proposed_action must be a JSON object"):
        _parse(_with(proposed_action="flag_for_review"))


@pytest.mark.parametrize("action_type", ["rollback_dependency", "FLAG_FOR_REVIEW", None])
def test_unknown_action_types_are_rejected(action_type):
    with pytest.raises(OutputParseError, match="proposed_action.type must be one of"):
        _parse(_with_action(type=action_type))


def test_the_model_cannot_produce_analysis_failed():
    with pytest.raises(OutputParseError, match="proposed_action.type must be one of"):
        _parse(_with_action(type="analysis_failed"))


@pytest.mark.parametrize("value", [False, "true", 1, None])
def test_requires_approval_must_be_exactly_true(value):
    """ADR 0004 -- and strictly `true`, not a truthy string or 1."""
    with pytest.raises(OutputParseError, match="requires_approval must be exactly true"):
        _parse(_with_action(requires_approval=value))


def test_a_missing_requires_approval_is_rejected_not_defaulted():
    action = {key: value for key, value in _VALID["proposed_action"].items() if key != "requires_approval"}

    with pytest.raises(OutputParseError, match="requires_approval must be exactly true"):
        _parse(_with(proposed_action=action))


@pytest.mark.parametrize("description", ["", "  ", None])
def test_description_must_be_non_empty_text(description):
    with pytest.raises(OutputParseError, match="description must be a non-empty string"):
        _parse(_with_action(description=description))