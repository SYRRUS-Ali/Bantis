import json

import pytest
from cryptography.fernet import Fernet

from providers.base import UnavailableProvider
from providers.claude import ClaudeProvider, from_environment
from providers.configuration import load_api_token_file, load_provider_file

KEY = "test-private-anthropic-key"
CONFIG = {"version": 1, "provider": "claude", "model": "claude-sonnet-5", "api_key": KEY}


@pytest.fixture(autouse=True)
def clear_external_key_path(monkeypatch):
    monkeypatch.delenv("BANTIS_SECRETS_KEY_FILE", raising=False)


def write(path, data, purpose="ai-provider"):
    key_path = path.parent / ".secrets.key"
    if not key_path.exists():
        key_path.write_bytes(Fernet.generate_key())
        key_path.chmod(0o600)
    cipher = Fernet(key_path.read_bytes())
    payload = json.dumps({"purpose": purpose, "data": data}).encode()
    path.write_text(json.dumps({"version": 2, "ciphertext": cipher.encrypt(payload).decode()}))
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

def test_plaintext_provider_file_is_rejected(tmp_path, monkeypatch):
    path = tmp_path / "ai-provider.json"
    path.write_text(json.dumps(CONFIG))
    path.chmod(0o600)
    monkeypatch.setenv("BANTIS_AI_CONFIG", str(path))
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    assert isinstance(from_environment(), UnavailableProvider)


@pytest.mark.parametrize("failure", ["missing", "wrong", "public", "symlink"])
def test_unavailable_encryption_key_never_falls_back(tmp_path, monkeypatch, failure):
    path = tmp_path / "ai-provider.json"
    write(path, CONFIG)
    key_path = tmp_path / ".secrets.key"
    if failure == "missing":
        key_path.unlink()
    elif failure == "wrong":
        key_path.write_bytes(Fernet.generate_key())
    elif failure == "public":
        key_path.chmod(0o644)
    else:
        alternate = tmp_path / "alternate-key"
        key_path.rename(alternate)
        key_path.symlink_to(alternate)
    monkeypatch.setenv("BANTIS_AI_CONFIG", str(path))
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    assert isinstance(from_environment(), UnavailableProvider)


def test_separate_private_key_path_is_supported(tmp_path, monkeypatch):
    path = tmp_path / "ai-provider.json"
    write(path, CONFIG)
    key_path = tmp_path / "separate.key"
    (tmp_path / ".secrets.key").rename(key_path)
    monkeypatch.setenv("BANTIS_SECRETS_KEY_FILE", str(key_path))
    assert load_provider_file(str(path)) == CONFIG


def test_tampered_ciphertext_is_rejected(tmp_path):
    path = tmp_path / "ai-provider.json"
    write(path, CONFIG)
    data = json.loads(path.read_text())
    token = data["ciphertext"]
    data["ciphertext"] = token[:60] + ("A" if token[60] != "A" else "B") + token[61:]
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="unavailable or invalid"):
        load_provider_file(str(path))

def test_managed_api_token_uses_purpose_bound_encrypted_storage(tmp_path):
    path = tmp_path / "orchestration.json"
    token = "test-managed-api-token-with-at-least-32-characters"
    data = {"version": 1, "copilot_api_token": token, "services": ["detection-engine", "copilot-api"]}
    write(path, data, purpose="orchestration")
    assert token not in path.read_text()
    assert load_api_token_file(str(path)) == token
    with pytest.raises(ValueError):
        load_provider_file(str(path))
    write(path, data, purpose="ai-provider")
    with pytest.raises(ValueError):
        load_api_token_file(str(path))


def test_api_entrypoint_prefers_encrypted_credential_and_never_falls_back_after_failure(tmp_path, monkeypatch):
    import api
    import uvicorn

    path = tmp_path / "orchestration.json"
    token = "test-managed-api-token-with-at-least-32-characters"
    write(path, {"version": 1, "copilot_api_token": token, "services": []}, purpose="orchestration")
    monkeypatch.setenv("BANTIS_COPILOT_TOKEN_CONFIG", str(path))
    monkeypatch.setenv("COPILOT_API_TOKEN", "other-environment-token")
    monkeypatch.delenv("BANTIS_AI_CONFIG", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    captured = []
    monkeypatch.setattr(api, "create_app", lambda *args, **kwargs: captured.append(args[2]) or object())
    monkeypatch.setattr(uvicorn, "run", lambda *args, **kwargs: None)
    assert api.main(["--decision-log", str(tmp_path / "log.db")]) == 0
    assert captured == [token]
    path.write_text("corrupted")
    assert api.main(["--decision-log", str(tmp_path / "log.db")]) == 2
    assert captured == [token]