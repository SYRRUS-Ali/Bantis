import pytest
from pydantic import ValidationError

from models import ProposedAction


def test_proposed_action_accepts_every_valid_type():
    for action_type in [
        "notify_operator",
        "flag_for_review",
        "suggest_investigation",
        "no_action_recommended",
        "analysis_failed",
    ]:
        action = ProposedAction(type=action_type, description="x", requires_approval=True)
        assert action.type == action_type


def test_proposed_action_rejects_an_unknown_type():
    with pytest.raises(ValidationError, match="must be one of"):
        ProposedAction(type="rollback_dependency", description="x", requires_approval=True)


def test_proposed_action_rejects_requires_approval_false():
    with pytest.raises(ValidationError, match="recommend-only"):
        ProposedAction(type="flag_for_review", description="x", requires_approval=False)


def test_proposed_action_defaults_requires_approval_to_true():
    action = ProposedAction(type="flag_for_review", description="x")

    assert action.requires_approval is True