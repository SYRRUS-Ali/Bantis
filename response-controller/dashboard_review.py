"""Host-local JSON bridge for the dashboard; no network listener or shell input."""

import json
import sqlite3
import sys
from contextlib import closing
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from approval_flow import ApprovalFlow, ReviewError, ReviewStore
from cli import _authenticate
from config import from_env
from executor import Executor
from wiring import build_registry


class ReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    operation: Literal["pending", "approve", "modify", "dismiss"]
    incident_id: str = Field(min_length=1, max_length=512)
    action_id: str = Field(default="", max_length=512)
    proposal_hash: str = Field(default="", max_length=64)
    secret: str = Field(default="", max_length=512, repr=False)
    reason: str = Field(default="", max_length=2000)
    params: dict = Field(default_factory=dict)


def handle(body: ReviewRequest) -> dict:
    config = from_env()
    # A dashboard must not silently initialize a different review queue.
    path = config.state_dir / "reviews.sqlite3"
    if not path.is_file():
        return {"error": "Controller review queue is unavailable", "code": 503}
    actor = None
    if body.operation != "pending":
        try:
            actor = _authenticate(body.secret)
        except (ValueError, OSError):
            return {"error": "Operator authentication failed or is not configured", "code": 403}
    with closing(ReviewStore(path)) as store:
        if body.operation == "pending":
            store.verify()
            proposals = [p for p in store.pending() if p.incident_id == body.incident_id]
            if len(proposals) > 100:
                return {"error": "Too many proposals; use the controller CLI", "code": 503}
            return {
                "dry_run": config.dry_run,
                "items": [{**p.model_dump(mode="json"), "proposal_hash": p.proposal_hash}
                          for p in proposals],
            }
        proposal, _ = store.get(body.action_id)
        if proposal.incident_id != body.incident_id:
            return {"error": "Proposal does not belong to this incident", "code": 409}
        registry = build_registry(store=store)
        flow = ApprovalFlow(store, Executor(registry, config, store), registry)
        if body.operation == "approve":
            outcome = flow.approve(body.action_id, body.proposal_hash, actor)
            return {"status": outcome.status, "action_id": outcome.action_id,
                    "reasons": outcome.reasons}
        if body.operation == "modify":
            replacement = flow.modify(body.action_id, body.proposal_hash, actor, body.params, body.reason)
            return {"status": "modified", "action_id": body.action_id,
                    "replacement_id": replacement.action_id}
        flow.dismiss(body.action_id, body.proposal_hash, actor, body.reason)
        return {"status": "dismissed", "action_id": body.action_id}


def main() -> None:
    try:
        raw = sys.stdin.read(16_385)
        if len(raw) > 16_384:
            raise ValueError("Request too large")
        result = handle(ReviewRequest.model_validate_json(raw))
    except ReviewError as exc:
        result = {"error": str(exc), "code": 409}
    except (ValidationError, ValueError):
        result = {"error": "Invalid review request or controller configuration", "code": 422}
    except (OSError, sqlite3.Error):
        result = {"error": "Controller review queue is unavailable", "code": 503}
    print(json.dumps(result))


if __name__ == "__main__":
    main()