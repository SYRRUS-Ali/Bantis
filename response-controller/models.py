from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

HASH_PREFIX_LENGTH = 12
DEFAULT_PROPOSAL_TTL = timedelta(minutes=60)

JsonScalar = str | int | float | bool | None


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("times must be timezone-aware")
    return value.astimezone(UTC)


class Proposal(BaseModel):
    """One concrete action the policy wants to take. Immutable: an approval
    is bound to its hash, so any change after approval means no execution.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    action_id: str = Field(default_factory=lambda: f"act_{uuid.uuid4().hex}")
    incident_id: str = Field(min_length=1)
    type: str = Field(min_length=1)
    params: dict[str, JsonScalar] = Field(default_factory=dict)
    policy_rule: str = Field(min_length=1)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime = Field(default_factory=lambda: datetime.now(UTC) + DEFAULT_PROPOSAL_TTL)
    required_approvals: int = Field(default=1, ge=1)

    @field_validator("created_at", "expires_at")
    @classmethod
    def _aware_utc(cls, value: datetime) -> datetime:
        return _utc(value)

    @property
    def proposal_hash(self) -> str:
        """sha256 over the canonical JSON of every field. Computed, never
        stored, so it can't disagree with the fields it covers."""
        canonical = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at


class Approval(BaseModel):
    """What an approver confirmed: this action_id, as identified by the
    first HASH_PREFIX_LENGTH characters of its proposal_hash."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    action_id: str = Field(min_length=1)
    approver: str = Field(min_length=1)
    hash_prefix: str = Field(min_length=HASH_PREFIX_LENGTH, max_length=64, pattern=r"^[0-9a-f]+$")
    approved_at: datetime

    @field_validator("approved_at")
    @classmethod
    def _aware_utc(cls, value: datetime) -> datetime:
        return _utc(value)

    def matches(self, proposal: Proposal) -> bool:
        return self.action_id == proposal.action_id and proposal.proposal_hash.startswith(self.hash_prefix)


class Status(StrEnum):
    REFUSED = "refused"  # never eligible: unknown type, disabled, bad params, duplicate, bad approval
    AWAITING_APPROVAL = "awaiting_approval"
    EXPIRED = "expired"
    INVALIDATED = "invalidated"  # kill switch or preconditions said no at execution time
    DRY_RUN = "dry_run"  # everything passed; recorded what would have happened, did nothing
    SUCCEEDED = "succeeded"
    FAILED = "failed"  # acted, and the action or its post-check failed: trips the kill switch


class Outcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    action_id: str
    type: str
    status: Status
    reasons: list[str] = Field(default_factory=list)
    plan: str | None = None
    detail: dict[str, JsonScalar] = Field(default_factory=dict)