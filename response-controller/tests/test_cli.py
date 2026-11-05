import pytest

from cli import main
from kill_switch import Level, read_state


def test_status_reports_fail_closed_before_any_switch_exists(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("BANTIS_STATE_DIR", str(tmp_path))
    assert main(["status"]) == 0
    out = capsys.readouterr().out
    assert "level: execution-off" in out and "ai: off" in out and "mode: dry run" in out


def test_kill_engages_with_one_command(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("BANTIS_STATE_DIR", str(tmp_path))
    assert main(["kill", "--reason", "drill", "--ai-off"]) == 0
    state = read_state(tmp_path)
    assert state.level == Level.EXECUTION_OFF and state.ai_off


def test_there_is_no_resume_command_yet(tmp_path, monkeypatch):
    import pytest

    monkeypatch.setenv("BANTIS_STATE_DIR", str(tmp_path))
    with pytest.raises(SystemExit):
        main(["resume", "--reason", "x"])

def test_promotion_hold_status_is_read_only(monkeypatch, capsys):
    from fake_github import TOKEN, FakeGitHub

    github = FakeGitHub()
    try:
        github.variables["BANTIS_PROMOTION_HOLD"] = "bantis-hold incident=inc-1 action=act_1"
        monkeypatch.setenv("RESPONSE_GITHUB_REPO", github.repo)
        monkeypatch.setenv("RESPONSE_GITHUB_TOKEN_PROMOTION", TOKEN)
        monkeypatch.setenv("RESPONSE_GITHUB_API_URL", github.url)

        assert main(["promotion-hold"]) == 0
        assert "HELD — bantis-hold incident=inc-1" in capsys.readouterr().out
        assert github.writes() == []
    finally:
        github.close()


def test_promotion_hold_status_needs_credentials(monkeypatch, capsys):
    monkeypatch.delenv("RESPONSE_GITHUB_REPO", raising=False)
    monkeypatch.delenv("RESPONSE_GITHUB_TOKEN_PROMOTION", raising=False)
    assert main(["promotion-hold"]) == 2


def _review_setup(tmp_path, monkeypatch):
    from models import Proposal

    monkeypatch.setenv("BANTIS_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("RESPONSE_ENABLED_ACTIONS", "lift_promotion_hold")
    monkeypatch.setenv("RESPONSE_DRY_RUN", "true")
    secret = tmp_path / "approver-secret"
    secret.write_text("test-operator-secret\n")
    secret.chmod(0o600)
    monkeypatch.setenv("RESPONSE_APPROVER_SECRET_FILE", str(secret))
    monkeypatch.setattr("cli.getpass.getpass", lambda prompt: "test-operator-secret")
    proposal = Proposal(incident_id="inc-1", type="lift_promotion_hold", policy_rule="B3:operator-request")
    source = tmp_path / "proposal.json"
    source.write_text(proposal.model_dump_json())
    assert main(["propose", str(source)]) == 0
    return proposal, secret


def test_cli_propose_list_show_modify_and_dismiss(tmp_path, monkeypatch, capsys):
    import json

    p, _ = _review_setup(tmp_path, monkeypatch)
    capsys.readouterr()
    assert main(["pending"]) == 0
    assert p.action_id in capsys.readouterr().out
    assert main(["show", p.action_id]) == 0
    assert p.proposal_hash in capsys.readouterr().out

    params = tmp_path / "params.json"
    params.write_text("{}")
    assert main(["modify", p.action_id, p.proposal_hash[:12], "--params-file", str(params), "--reason", "review again"]) == 0
    output = capsys.readouterr().out
    replacement = json.JSONDecoder().raw_decode(output)[0]
    assert replacement["action_id"] != p.action_id
    assert "fresh approval required" in output
    assert main(["approve", p.action_id, p.proposal_hash[:12]]) == 2
    assert "closed" in capsys.readouterr().err
    assert main(["dismiss", replacement["action_id"], replacement["proposal_hash"][:12], "--reason", "false positive"]) == 0
    capsys.readouterr()
    assert main(["pending"]) == 0
    assert "No pending proposals" in capsys.readouterr().out


def test_cli_approval_authenticates_then_uses_executor_dry_run(tmp_path, monkeypatch, capsys):
    from fake_github import TOKEN, FakeGitHub
    from helpers import clear_switch

    github = FakeGitHub()
    try:
        github.variables["BANTIS_PROMOTION_HOLD"] = "bantis-hold incident=inc-1 action=act_1"
        monkeypatch.setenv("RESPONSE_GITHUB_REPO", github.repo)
        monkeypatch.setenv("RESPONSE_GITHUB_TOKEN_PROMOTION", TOKEN)
        monkeypatch.setenv("RESPONSE_GITHUB_API_URL", github.url)
        p, _ = _review_setup(tmp_path, monkeypatch)
        clear_switch(tmp_path)
        capsys.readouterr()
        assert main(["approve", p.action_id, p.proposal_hash[:12]]) == 0
        assert '"status": "dry_run"' in capsys.readouterr().out
        assert github.writes() == []
    finally:
        github.close()


def test_cli_bad_secret_cannot_change_proposal(tmp_path, monkeypatch, capsys):
    p, _ = _review_setup(tmp_path, monkeypatch)
    capsys.readouterr()
    monkeypatch.setattr("cli.getpass.getpass", lambda prompt: "wrong-secret")
    assert main(["approve", p.action_id, p.proposal_hash[:12]]) == 2
    captured = capsys.readouterr()
    assert "authentication failed" in captured.err
    assert "wrong-secret" not in captured.err + captured.out
    assert main(["pending"]) == 0
    assert p.action_id in capsys.readouterr().out


def test_cli_missing_or_public_secret_is_refused(tmp_path, monkeypatch, capsys):
    p, secret = _review_setup(tmp_path, monkeypatch)
    capsys.readouterr()
    secret.chmod(0o644)
    assert main(["dismiss", p.action_id, p.proposal_hash[:12], "--reason", "ignore"]) == 2
    assert "0600" in capsys.readouterr().err
    monkeypatch.delenv("RESPONSE_APPROVER_SECRET_FILE")
    assert main(["approve", p.action_id, p.proposal_hash[:12]]) == 2
    assert "RESPONSE_APPROVER_SECRET_FILE" in capsys.readouterr().err


def test_cli_approval_can_lift_hold_using_only_fake_github(tmp_path, monkeypatch, capsys):
    from fake_github import TOKEN, FakeGitHub
    from helpers import clear_switch

    github = FakeGitHub()
    try:
        github.variables["BANTIS_PROMOTION_HOLD"] = "bantis-hold incident=inc-1 action=act_1"
        monkeypatch.setenv("RESPONSE_GITHUB_REPO", github.repo)
        monkeypatch.setenv("RESPONSE_GITHUB_TOKEN_PROMOTION", TOKEN)
        monkeypatch.setenv("RESPONSE_GITHUB_API_URL", github.url)
        p, _ = _review_setup(tmp_path, monkeypatch)
        monkeypatch.setenv("RESPONSE_DRY_RUN", "false")
        clear_switch(tmp_path)
        capsys.readouterr()
        assert main(["approve", p.action_id, p.proposal_hash[:12]]) == 0
        assert '"status": "succeeded"' in capsys.readouterr().out
        assert "BANTIS_PROMOTION_HOLD" not in github.variables
        assert len(github.writes()) == 1
        assert main(["approve", p.action_id, p.proposal_hash[:12]]) == 2
        assert len(github.writes()) == 1
    finally:
        github.close()


@pytest.mark.parametrize("command", ["kill", "emergency-stop"])
def test_stopping_ignores_invalid_execution_configuration(tmp_path, monkeypatch, capsys, command):
    monkeypatch.setenv("BANTIS_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("RESPONSE_ENABLED_ACTIONS", "unknown-action")
    monkeypatch.setenv("RESPONSE_DRY_RUN", "invalid")
    monkeypatch.setattr("cli.getpass.getpass", lambda _: pytest.fail("Stopping must not prompt"))
    assert main([command, "--reason", "Stop now"]) == 0
    assert not read_state(tmp_path).execution_allowed
    assert "Kill switch engaged" in capsys.readouterr().out


def test_emergency_stop_needs_no_arguments_and_stops_ai(tmp_path, monkeypatch):
    from helpers import clear_switch

    clear_switch(tmp_path)
    monkeypatch.setenv("BANTIS_STATE_DIR", str(tmp_path))
    assert main(["emergency-stop"]) == 0
    state = read_state(tmp_path)
    assert not state.execution_allowed and not state.auto_allowed and state.ai_off


@pytest.mark.parametrize("reason", ["", "   "])
def test_stop_rejects_blank_reason_without_traceback(tmp_path, monkeypatch, capsys, reason):
    monkeypatch.setenv("BANTIS_STATE_DIR", str(tmp_path))
    assert main(["emergency-stop", "--reason", reason]) == 2
    assert "a reason is required" in capsys.readouterr().err


def test_stop_reports_an_unwritable_state_path(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("BANTIS_STATE_DIR", str(tmp_path / "missing"))
    assert main(["emergency-stop"]) == 2
    assert "Could not engage kill switch" in capsys.readouterr().err


def test_emergency_stop_survives_a_broken_audit_journal(tmp_path, monkeypatch, capsys):
    (tmp_path / "reviews.sqlite3").write_text("broken database")
    monkeypatch.setenv("BANTIS_STATE_DIR", str(tmp_path))
    assert main(["emergency-stop"]) == 1
    assert not read_state(tmp_path).execution_allowed and read_state(tmp_path).ai_off
    captured = capsys.readouterr()
    assert "Kill switch engaged" in captured.out
    assert "could not audit engagement" in captured.err



def test_emergency_button_uses_the_same_persistent_stop(tmp_path, monkeypatch):
    monkeypatch.setenv("BANTIS_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("RESPONSE_DRY_RUN", "invalid")
    monkeypatch.setattr("emergency_button.show_button", lambda stop: stop())
    assert main(["emergency-button"]) == 0
    state = read_state(tmp_path)
    assert not state.execution_allowed and state.ai_off