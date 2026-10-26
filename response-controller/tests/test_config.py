import pytest

from config import ConfigError, ControllerConfig, from_env


def test_by_default_nothing_is_enabled_and_nothing_is_live(tmp_path):
    config = from_env({"BANTIS_STATE_DIR": str(tmp_path)})
    assert config.enabled_actions == frozenset() and config.dry_run is True


def test_actions_are_enabled_one_by_one(tmp_path):
    config = from_env({"BANTIS_STATE_DIR": str(tmp_path), "RESPONSE_ENABLED_ACTIONS": "notify_channel, preserve_evidence", "RESPONSE_DRY_RUN": "false"})
    assert config.enabled_actions == {"notify_channel", "preserve_evidence"} and config.dry_run is False


def test_enabling_something_outside_the_catalog_fails_at_startup(tmp_path):
    with pytest.raises(ConfigError, match="not in the catalog"):
        ControllerConfig(state_dir=tmp_path, enabled_actions=frozenset({"run_command"}))


@pytest.mark.parametrize("value", ["no", "0", "False ", ""])
def test_dry_run_takes_only_true_or_false(tmp_path, value):
    if value.strip().lower() in {"true", "false"}:
        return
    with pytest.raises(ConfigError):
        from_env({"BANTIS_STATE_DIR": str(tmp_path), "RESPONSE_DRY_RUN": value})


def test_the_state_directory_is_required():
    with pytest.raises(ConfigError, match="BANTIS_STATE_DIR"):
        from_env({})