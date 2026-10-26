from datetime import datetime, timedelta

import pytest
from helpers import T0, approve, proposal
from pydantic import ValidationError

from models import Approval, Proposal


def test_the_hash_is_stable_for_the_same_proposal():
    p = proposal()
    assert p.proposal_hash == Proposal(**p.model_dump()).proposal_hash


@pytest.mark.parametrize(
    "change",
    [
        {"type": "rollback_latest"},
        {"params": {"variable": "OTHER"}},
        {"incident_id": "inc-2"},
        {"expires_at": T0 + timedelta(hours=2)},
        {"required_approvals": 2},
        {"policy_rule": "other"},
    ],
)
def test_any_change_changes_the_hash(change):
    p = proposal()
    assert p.model_copy(update=change).proposal_hash != p.proposal_hash


def test_proposals_are_immutable():
    with pytest.raises(ValidationError):
        proposal().params = {"variable": "x"}


def test_unknown_fields_are_rejected():
    with pytest.raises(ValidationError):
        proposal(proposal_hash="0" * 64)


def test_naive_times_are_rejected():
    with pytest.raises(ValidationError):
        proposal(created_at=datetime(2026, 10, 23, 12, 0))


def test_nested_params_are_rejected():
    with pytest.raises(ValidationError):
        proposal(params={"variable": {"nested": "x"}})


@pytest.mark.parametrize("prefix", ["abc", "z" * 12, "ABCDEF123456"])
def test_an_approval_needs_a_12_char_lowercase_hex_prefix(prefix):
    with pytest.raises(ValidationError):
        Approval(action_id="a", approver="op", hash_prefix=prefix, approved_at=T0)


def test_an_approval_matches_only_its_proposal():
    p = proposal()
    a = approve(p)
    assert a.matches(p)
    assert not a.matches(proposal())  # different action_id
    assert not a.matches(p.model_copy(update={"params": {"variable": "OTHER"}}))