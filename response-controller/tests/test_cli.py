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