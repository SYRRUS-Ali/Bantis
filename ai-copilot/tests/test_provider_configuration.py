import json

import pytest

from providers.base import UnavailableProvider
from providers.claude import ClaudeProvider, from_environment
from providers.configuration import load_provider_file

KEY = "test-private-anthropic-key"
CONFIG = {"version": 1, "provider": "claude", "model": "claude-sonnet-5", "api_key": KEY}


def write(path, data):
    path.write_text(json.dumps(data))
    path.chmod(0o600)


def test_wizard_selection_supplies_actual_provider_key_and_model(tmp_path, monkeypatch):
    path = tmp_path / "ai-provider.json"
    write(path, CONFIG)
    monkeypatch.setenv("BANTIS_AI_CONFIG", str(path))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "different-environment-key")
    provider = from_environment()
    assert isinstance(provider, ClaudeProvider)
    assert provider.model == CONFIG["model"]
    assert provider._client.api_key == KEY
    provider._client.close()


def test_none_explicitly_disables_ai_even_with_an_environment_key(tmp_path, monkeypatch):
    path = tmp_path / "ai-provider.json"
    write(path, {"version": 1, "provider": "none"})
    monkeypatch.setenv("BANTIS_AI_CONFIG", str(path))
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    assert isinstance(from_environment(), UnavailableProvider)


@pytest.mark.parametrize("changes", [{"version": 2}, {"provider": "openai"},
                                     {"api_key": "short"}, {"api_key": KEY + "\n"},
                                     {"endpoint": "http://localhost"}, {"model": "not-claude"}])
def test_invalid_file_does_not_fall_back_to_environment(tmp_path, monkeypatch, changes):
    path = tmp_path / "ai-provider.json"
    write(path, CONFIG | changes)
    monkeypatch.setenv("BANTIS_AI_CONFIG", str(path))
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    result = from_environment()
    assert isinstance(result, UnavailableProvider)
    assert KEY not in result.reason


def test_missing_corrupt_or_public_file_is_unavailable(tmp_path, monkeypatch):
    path = tmp_path / "ai-provider.json"
    monkeypatch.setenv("BANTIS_AI_CONFIG", str(path))
    assert isinstance(from_environment(), UnavailableProvider)
    path.write_text("broken")
    path.chmod(0o600)
    assert isinstance(from_environment(), UnavailableProvider)
    write(path, CONFIG)
    path.chmod(0o644)
    assert isinstance(from_environment(), UnavailableProvider)


def test_config_path_must_be_absolute():
    with pytest.raises(ValueError, match="unavailable or invalid"):
        load_provider_file("relative.json")