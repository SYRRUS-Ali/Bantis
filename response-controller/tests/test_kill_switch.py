import json
import os

import pytest

from kill_switch import OPERATOR_FILE, TRIPWIRE_FILE, Level, engage, read_state, trip


def _halted(state):
    return not state.execution_allowed and state.ai_off


def test_a_missing_state_directory_halts_everything(tmp_path):
    assert _halted(read_state(tmp_path / "nope"))


def test_a_missing_switch_file_halts_everything(tmp_path):
    """Only a readable file saying clear allows execution."""
    assert _halted(read_state(tmp_path))


@pytest.mark.parametrize(
    "content",
    ["", "not json", "[]", '{"level": "off"}', '{"ai_off": false}', '{"level": "clear", "ai_off": "no"}'],
)
def test_a_garbled_switch_file_halts_everything(tmp_path, content):
    (tmp_path / OPERATOR_FILE).write_text(content)
    assert _halted(read_state(tmp_path))


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file permissions")
def test_an_unreadable_switch_file_halts_everything(tmp_path):
    engage(tmp_path, Level.CLEAR, "setup", "test")
    (tmp_path / OPERATOR_FILE).chmod(0)
    try:
        assert _halted(read_state(tmp_path))
    finally:
        (tmp_path / OPERATOR_FILE).chmod(0o600)


def test_clear_allows_everything(tmp_path):
    engage(tmp_path, Level.CLEAR, "setup", "test")
    state = read_state(tmp_path)
    assert state.execution_allowed and state.auto_allowed and not state.ai_off


def test_auto_off_allows_only_approved_execution(tmp_path):
    engage(tmp_path, Level.AUTO_OFF, "policy misfiring", "op")
    state = read_state(tmp_path)
    assert state.execution_allowed and not state.auto_allowed


def test_engaging_never_lowers_the_level(tmp_path):
    engage(tmp_path, Level.EXECUTION_OFF, "stop", "op")
    engage(tmp_path, Level.AUTO_OFF, "softer", "op")
    assert read_state(tmp_path).level == Level.EXECUTION_OFF


def test_engaging_needs_a_reason(tmp_path):
    with pytest.raises(ValueError):
        engage(tmp_path, Level.EXECUTION_OFF, "  ", "op")


def test_a_tripwire_overrides_a_clear_operator_switch(tmp_path):
    engage(tmp_path, Level.CLEAR, "setup", "test")
    trip(tmp_path, Level.EXECUTION_OFF, "post-check failed")
    state = read_state(tmp_path)
    assert state.level == Level.EXECUTION_OFF
    assert any("post-check failed" in r for r in state.reasons)


def test_a_tripwire_can_engage_but_never_clear(tmp_path):
    with pytest.raises(ValueError):
        trip(tmp_path, Level.CLEAR, "all good")
    trip(tmp_path, Level.EXECUTION_OFF, "first")
    trip(tmp_path, Level.AUTO_OFF, "second, milder")
    engage(tmp_path, Level.CLEAR, "setup", "test")
    assert read_state(tmp_path).level == Level.EXECUTION_OFF


def test_a_garbled_tripwire_file_halts_everything(tmp_path):
    engage(tmp_path, Level.CLEAR, "setup", "test")
    (tmp_path / TRIPWIRE_FILE).write_text("{")
    assert _halted(read_state(tmp_path))


def test_writes_are_atomic_and_leave_no_temp_file(tmp_path):
    engage(tmp_path, Level.AUTO_OFF, "x", "op")
    assert sorted(p.name for p in tmp_path.iterdir()) == [OPERATOR_FILE]
    assert json.loads((tmp_path / OPERATOR_FILE).read_text())["set_by"] == "op"


def test_ai_off_is_independent_of_the_execution_level(tmp_path):
    engage(tmp_path, Level.CLEAR, "setup", "test", ai_off=True)
    state = read_state(tmp_path)
    assert state.execution_allowed and state.ai_off