import json
from contextlib import closing
from datetime import UTC, datetime, timedelta

import pytest
from helpers import FakeAction, clear_switch

import dashboard_review
from approval_flow import ApprovalFlow, ReviewError, ReviewStore
from config import ControllerConfig
from executor import Executor
from models import Proposal
from registry import ActionRegistry


@pytest.fixture
def review(tmp_path, monkeypatch):
    monkeypatch.setenv("BANTIS_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("RESPONSE_ENABLED_ACTIONS", "hold_promotion")
    monkeypatch.setenv("RESPONSE_DRY_RUN", "true")
    secret = tmp_path / "secret"
    secret.write_text("operator-secret")
    secret.chmod(0o600)
    monkeypatch.setenv("RESPONSE_APPROVER_SECRET_FILE", str(secret))
    clear_switch(tmp_path)
    action = FakeAction()
    registry = ActionRegistry()
    registry.register(action)
    monkeypatch.setattr(dashboard_review, "build_registry", lambda **_: registry)
    with closing(ReviewStore(tmp_path / "reviews.sqlite3")) as store:
        flow = ApprovalFlow(store, Executor(registry, ControllerConfig(tmp_path), store), registry)
        proposal = flow.submit(Proposal(incident_id="inc-1", type=action.type,
                                       params={"variable": "HOLD"}, policy_rule="A3:test"))
    return proposal, action, tmp_path


def request(proposal, **changes):
    return dashboard_review.ReviewRequest(
        **({"operation": "approve", "incident_id": proposal.incident_id,
            "action_id": proposal.action_id, "proposal_hash": proposal.proposal_hash,
            "secret": "operator-secret"} | changes)
    )


@pytest.mark.parametrize("dry_run", [True, False])
def test_dashboard_approval_obeys_mode_and_executes_once(review, monkeypatch, dry_run):
    proposal, action, _ = review
    monkeypatch.setenv("RESPONSE_DRY_RUN", str(dry_run).lower())
    result = dashboard_review.handle(request(proposal))
    assert result["status"] == ("dry_run" if dry_run else "succeeded")
    assert action.done_steps == ([] if dry_run else [1, 2])
    with pytest.raises(ReviewError, match="closed"):
        dashboard_review.handle(request(proposal))
    assert action.done_steps == ([] if dry_run else [1, 2])


def test_host_identity_cannot_supply_two_approvals(review):
    proposal, action, path = review
    two = proposal.model_copy(update={"required_approvals": 2})
    with closing(ReviewStore(path / "reviews.sqlite3")) as store:
        store.db.execute("UPDATE proposals SET payload = ?", (two.model_dump_json(),))
    assert dashboard_review.handle(request(two))["status"] == "awaiting_approval"
    with pytest.raises(ReviewError, match="already approved"):
        dashboard_review.handle(request(two))
    assert action.done_steps == []


def test_expired_proposal_is_hidden_and_cannot_be_approved(review):
    proposal, action, path = review
    expired = proposal.model_copy(update={"expires_at": datetime.now(UTC) - timedelta(seconds=1)})
    with closing(ReviewStore(path / "reviews.sqlite3")) as store:
        store.db.execute("UPDATE proposals SET payload = ?", (expired.model_dump_json(),))
    assert dashboard_review.handle(request(expired, operation="pending"))["items"] == []
    with pytest.raises(ReviewError, match="review window"):
        dashboard_review.handle(request(expired))
    assert action.done_steps == []


def test_public_secret_file_cannot_authorize_dashboard(review):
    proposal, action, path = review
    (path / "secret").chmod(0o644)
    result = dashboard_review.handle(request(proposal))
    assert result["code"] == 403
    assert action.done_steps == []


def test_protocol_validation_does_not_echo_secret(monkeypatch, capsys):
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO('{"secret":"private-value","operation":"execute"}'))
    dashboard_review.main()
    output = capsys.readouterr().out
    assert json.loads(output)["code"] == 422
    assert "private-value" not in output