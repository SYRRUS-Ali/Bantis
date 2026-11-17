import concurrent.futures
import json
import os
import runpy
import stat
import traceback
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from bantis_dashboard.admin import AdminError
from bantis_dashboard.config import Settings
from bantis_dashboard.main import create_app
from bantis_dashboard.secret_store import SecretStore
from test_dashboard import ORIGIN, TOKEN

SECRET = "private-api-key-that-must-not-be-on-disk"
PROVIDER = {"version": 1, "provider": "claude", "model": "claude-sonnet-5", "api_key": SECRET}


@pytest.fixture
def store(tmp_path):
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    return SecretStore(directory)


def test_authenticated_ciphertext_and_private_files_survive_restart(store):
    store.write("ai-provider", PROVIDER)
    path = store.directory / "ai-provider.json"
    assert SECRET not in path.read_text()
    assert set(json.loads(path.read_text())) == {"version", "ciphertext"}
    assert json.loads(path.read_text())["version"] == 2
    for file in (store.key_file, path):
        assert stat.S_IMODE(file.stat().st_mode) == 0o600
    assert SecretStore(store.directory).read("ai-provider") == (PROVIDER, False)
    load = runpy.run_path(str(Path(__file__).resolve().parents[2] / "ai-copilot/providers/configuration.py"))["load_provider_file"]
    assert load(str(path)) == PROVIDER


def test_identical_saves_use_different_ciphertext(store):
    store.write("ai-provider", PROVIDER)
    path = store.directory / "ai-provider.json"
    first = path.read_bytes()
    store.write("ai-provider", PROVIDER)
    assert path.read_bytes() != first


@pytest.mark.parametrize("failure", ["missing", "wrong", "public", "symlink", "invalid"])
def test_bad_key_cannot_read_write_or_be_replaced(store, failure):
    store.write("ai-provider", PROVIDER)
    before = (store.directory / "ai-provider.json").read_bytes()
    if failure == "missing":
        store.key_file.unlink()
    elif failure == "wrong":
        store.key_file.write_bytes(Fernet.generate_key())
    elif failure == "public":
        store.key_file.chmod(0o644)
    elif failure == "invalid":
        store.key_file.write_bytes(b"invalid")
    else:
        other = store.directory / "other-key"
        store.key_file.rename(other)
        store.key_file.symlink_to(other)
    with pytest.raises(AdminError):
        store.read("ai-provider")
    with pytest.raises(AdminError):
        store.write("ai-provider", PROVIDER)
    with pytest.raises(AdminError):
        SecretStore(store.directory)
    assert (store.directory / "ai-provider.json").read_bytes() == before
    if failure == "missing":
        assert not store.key_file.exists()


def test_tampering_and_cross_document_substitution_fail_closed(store):
    store.write("ai-provider", PROVIDER)
    source = store.directory / "ai-provider.json"
    (store.directory / "telegram.json").write_bytes(source.read_bytes())
    (store.directory / "telegram.json").chmod(0o600)
    with pytest.raises(AdminError):
        store.read("telegram")
    envelope = json.loads(source.read_text())
    token = envelope["ciphertext"]
    envelope["ciphertext"] = token[:60] + ("A" if token[60] != "A" else "B") + token[61:]
    source.write_text(json.dumps(envelope))
    with pytest.raises(AdminError):
        store.read("ai-provider")


@pytest.mark.parametrize("kind", ["symlink", "public", "oversized", "fifo"])
def test_unsafe_configuration_files_are_rejected(store, kind):
    store.write("ai-provider", PROVIDER)
    path = store.directory / "ai-provider.json"
    if kind == "symlink":
        other = store.directory / "other"
        path.rename(other)
        path.symlink_to(other)
    elif kind == "public":
        path.chmod(0o644)
    elif kind == "oversized":
        path.write_bytes(b"x" * 16385)
    else:
        path.unlink()
        os.mkfifo(path, mode=0o600)
    with pytest.raises(AdminError):
        store.read("ai-provider")


def test_failed_atomic_write_keeps_original_and_no_temporary_plaintext(store, monkeypatch):
    store.write("ai-provider", PROVIDER)
    previous = (store.directory / "ai-provider.json").read_bytes()

    def fail(source, destination):
        assert SECRET not in Path(source).read_text()
        raise OSError("storage unavailable")

    monkeypatch.setattr("bantis_dashboard.secret_store.os.replace", fail)
    with pytest.raises(AdminError):
        store.write("ai-provider", PROVIDER)
    assert (store.directory / "ai-provider.json").read_bytes() == previous
    assert sorted(p.name for p in store.directory.iterdir()) == [".secrets.key", "ai-provider.json"]


def test_concurrent_key_creation_never_replaces_an_existing_key(tmp_path):
    tmp_path.chmod(0o700)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        stores = list(executor.map(lambda _: SecretStore(tmp_path), range(4)))
    stores[0].write("ai-provider", PROVIDER)
    for store in stores:
        assert store.read("ai-provider")[0] == PROVIDER


def test_existing_legacy_settings_migrate_without_plaintext_backup(tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path / "ai-provider.json"
    path.write_text(json.dumps(PROVIDER))
    path.chmod(0o600)
    telegram = tmp_path / "telegram.json"
    telegram.write_text(json.dumps({"version": 1, "enabled": True,
                                    "bot_token": "123456:telegram-private-test-token", "chat_id": "12345"}))
    telegram.chmod(0o600)
    create_app(Settings(token=TOKEN, origin=ORIGIN, state_dir=tmp_path))
    assert SECRET not in path.read_text()
    assert "telegram-private-test-token" not in telegram.read_text()
    assert SecretStore(tmp_path).read("ai-provider")[0] == PROVIDER
    assert sorted(p.name for p in tmp_path.iterdir()) == [".secrets.key", "admin.sqlite3", "ai-provider.json", "telegram.json"]


def test_invalid_legacy_settings_are_never_silently_migrated(store):
    path = store.directory / "ai-provider.json"
    path.write_text(json.dumps(PROVIDER | {"api_key": SECRET + "\n"}))
    path.chmod(0o600)
    previous = path.read_bytes()
    with pytest.raises(AdminError) as error:
        create_app(Settings(token=TOKEN, origin=ORIGIN, state_dir=store.directory))
    assert SECRET not in "".join(traceback.format_exception(error.value))
    assert path.read_bytes() == previous


def test_separate_existing_private_key_is_supported(tmp_path):
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    key_file = tmp_path / "operator.key"
    key_file.write_bytes(Fernet.generate_key())
    key_file.chmod(0o600)
    store = SecretStore(directory, key_file)
    store.write("ai-provider", PROVIDER)
    assert not (directory / ".secrets.key").exists()
    assert SecretStore(directory, key_file).read("ai-provider")[0] == PROVIDER


def test_missing_external_key_is_not_generated(tmp_path):
    with pytest.raises(AdminError):
        SecretStore(tmp_path, tmp_path / "missing.key")
    assert not (tmp_path / "missing.key").exists()