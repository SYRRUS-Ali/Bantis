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