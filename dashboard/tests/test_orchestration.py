import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

from bantis_dashboard.admin import AdminError
from bantis_dashboard.config import Settings
from bantis_dashboard.orchestration import CommandRunner, LOG_LIMIT, LogRedactor, Orchestrator, SERVICES
from bantis_dashboard.permissions_setup import PermissionsSave, PermissionsSetup
from bantis_dashboard.provider_setup import ProviderSave, ProviderSetup
from bantis_dashboard.secret_store import SecretStore
from bantis_dashboard.telegram_setup import TelegramSave, TelegramSetup
from test_dashboard import ORIGIN, TOKEN


@pytest.fixture
def anyio_backend():
    return "asyncio"


class FakeRunner:
    def __init__(self):
        self.calls = []
        self.selected = []
        self.fail_up = False
        self.bad_health = False
        self.bad_status = False
        self.block_up = None
        self.up_entered = None
        self.message = 'detection-engine | 2026-11-24T10:00:00Z <img src=x onerror="window.untrustedExecuted=true"> service log'

    async def run(self, argv, *, env, cwd, line=None, timeout=30, capture=False):
        self.calls.append((argv[:], env.copy()))
        if "context" in argv:
            return 0, "unix:///var/run/docker.sock\n"
        if "info" in argv:
            return 0, "28.0.0\n"
        if "config" in argv:
            return 0, ""
        if "ps" in argv:
            if self.bad_status:
                return 0, "not JSON"
            return 0, json.dumps([{"Service": name, "State": "running", "Health": "" if name == "copilot-worker" else "unhealthy" if self.bad_health else "healthy"} for name in self.selected])
        if "logs" in argv:
            if line:
                await line(self.message)
            await asyncio.Event().wait()
        if "up" in argv:
            if line:
                await line("Building configured services")
                await line("Authorization: Bearer fixture-service-credential")
            if self.up_entered:
                self.up_entered.set()
            if self.block_up:
                await self.block_up.wait()
            if self.fail_up:
                return 1, ""
            self.selected = argv[argv.index("--wait-timeout") + 2:]
            return 0, ""
        raise AssertionError(f"Unexpected command: {argv}")


def build(tmp_path, *, runner=None, range_enabled=False, root=None):
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700, exist_ok=True)
    store = SecretStore(directory)
    permissions = PermissionsSetup(store)
    permissions.save(PermissionsSave(ai_requests=False, telegram_messages=False, response_decisions=False))
    provider = ProviderSetup(directory, store=store)
    provider.save(ProviderSave(provider="none"), "test-session")
    telegram = TelegramSetup(directory, store=store)
    telegram.save(TelegramSave(enabled=False), "test-session")
    settings = Settings(token=TOKEN, origin=ORIGIN, state_dir=directory, orchestration_enabled=True, orchestration_range=range_enabled)
    manager = Orchestrator(settings, store, permissions, provider, telegram, runner=runner or FakeRunner(), root=root or tmp_path, interval=0.05)
    return manager


@pytest.mark.anyio
async def test_start_fixed_services_once_and_stream_logs(tmp_path):
    runner = FakeRunner()
    runner.block_up, runner.up_entered = asyncio.Event(), asyncio.Event()
    manager = build(tmp_path, runner=runner)
    await manager.open()
    try:
        assert (await manager.start())["phase"] == "starting"
        await asyncio.wait_for(runner.up_entered.wait(), 2)
        assert (await manager.start())["phase"] == "starting"
        runner.block_up.set()
        await manager.startup
        assert manager.phase == "ready"
        await manager.start()
        assert len([argv for argv, _ in runner.calls if "up" in argv]) == 1
        argv, environment = next((argv, env) for argv, env in runner.calls if "up" in argv)
        assert argv[-2:] == ["detection-engine", "copilot-api"]
        assert "--wait" in argv and "--build" in argv
        assert "COPILOT_API_TOKEN" not in environment
        assert "DASHBOARD_TOKEN" not in environment
        assert not any(key.startswith("RESPONSE_") for key in environment)
        await asyncio.sleep(0.06)
        snapshot = manager.snapshot()
        assert snapshot["ready"] is True
        assert any("service log" in item["text"] for item in snapshot["logs"])
        assert "fixture-service-credential" not in json.dumps(snapshot)
        assert manager.copilot_token not in json.dumps(snapshot)
        assert TOKEN not in json.dumps(snapshot)
        assert manager.copilot_token not in (manager.store.directory / "orchestration.json").read_text()
        import runpy
        load_token = runpy.run_path(str(Path(__file__).resolve().parents[2] / "ai-copilot/providers/configuration.py"))["load_api_token_file"]
        assert load_token(str(manager.store.directory / "orchestration.json")) == manager.copilot_token
    finally:
        await manager.close()


@pytest.mark.anyio
@pytest.mark.parametrize("failure", ["exit", "health", "status"])
async def test_failed_start_never_reports_ready_and_can_retry(tmp_path, failure):
    runner = FakeRunner()
    runner.fail_up = failure == "exit"
    runner.bad_health = failure == "health"
    runner.bad_status = failure == "status"
    manager = build(tmp_path, runner=runner)
    await manager.open()
    try:
        await manager.start()
        await manager.startup
        assert manager.phase == "failed"
        assert manager.error
        assert manager.snapshot()["ready"] is False
        runner.fail_up = runner.bad_health = runner.bad_status = False
        await manager.start()
        await manager.startup
        assert manager.phase == "ready"
        assert len([argv for argv, _ in runner.calls if "up" in argv]) == 2
    finally:
        await manager.close()


@pytest.mark.anyio
async def test_restart_reconciles_existing_containers_without_starting_again(tmp_path):
    runner = FakeRunner()
    first = build(tmp_path, runner=runner)
    await first.open()
    await first.start()
    await first.startup
    project, token = first.project, first.copilot_token
    await first.close()
    second = build(tmp_path, runner=runner)
    assert second.project == project and second.copilot_token == token
    await second.open()
    try:
        await asyncio.sleep(0.12)
        assert second.phase == "ready"
        await second.start()
        assert len([argv for argv, _ in runner.calls if "up" in argv]) == 1
    finally:
        await second.close()


@pytest.mark.anyio
async def test_second_coordinator_cannot_launch_or_follow(tmp_path):
    first = build(tmp_path)
    second = build(tmp_path)
    await first.open()
    await second.open()
    try:
        assert second.phase == "unavailable"
        with pytest.raises(AdminError):
            await second.start()
        assert second.runner.calls == []
    finally:
        await second.close()
        await first.close()


@pytest.mark.anyio
async def test_range_requires_private_config_and_explicit_placeholders_replaced(tmp_path):
    root = tmp_path / "repo"
    (root / "range").mkdir(parents=True)
    manager = build(tmp_path, range_enabled=True, root=root)
    await manager.open()
    try:
        with pytest.raises(AdminError, match="range/.env"):
            await manager.start()
        path = root / "range/.env"
        path.write_text("POSTGRES_USER=user\nPOSTGRES_PASSWORD=range-password-private\nPOSTGRES_DB=app\nDATABASE_URL=postgresql+asyncpg://user:range-password-private@db:5432/app\nJWT_SECRET_KEY=jwt-private-value\nREDIS_PASSWORD=redis-password-private\nREDIS_URL=redis://:redis-password-private@redis:6379/0\n")
        path.chmod(0o644)
        with pytest.raises(AdminError):
            await manager.start()
        path.chmod(0o600)
        await manager.start()
        await manager.startup
        assert set(manager.selected) == {"detection-engine", "copilot-api", "db", "redis", "api", "nginx"}
        assert manager.phase == "ready"
        await manager.log("failed password range-password-private redis-password-private jwt-private-value")
        assert "range-password-private" not in json.dumps(manager.snapshot())
        assert "redis-password-private" not in json.dumps(manager.snapshot())
    finally:
        await manager.close()


@pytest.mark.anyio
async def test_copilot_worker_needs_saved_key_and_ai_permission(tmp_path):
    manager = build(tmp_path)
    manager.store.write("ai-provider", {"version": 1, "provider": "claude", "model": "claude-fixture", "api_key": "fixture-private-provider-key"})
    manager._prepare(launch=True)
    assert "copilot-worker" not in manager.selected
    manager.permissions.save(PermissionsSave(ai_requests=True, telegram_messages=False, response_decisions=False))
    manager._prepare(launch=True)
    assert "copilot-worker" in manager.selected
    assert manager.redactor.clean("fixture-private-provider-key", "test") == "[REDACTED]"


@pytest.mark.anyio
async def test_prerequisite_choices_cannot_be_bypassed(tmp_path):
    manager = build(tmp_path)
    manager.store.write("permissions", {"version": 1, "ai_requests": False, "telegram_messages": False, "response_decisions": False})
    (manager.store.directory / "telegram.json").unlink()
    await manager.open()
    try:
        with pytest.raises(AdminError, match="configure or skip Telegram"):
            await manager.start()
        assert not any("up" in argv for argv, _ in manager.runner.calls)
    finally:
        await manager.close()


@pytest.mark.anyio
async def test_log_window_and_epoch_report_missing_history(tmp_path):
    manager = build(tmp_path)
    for number in range(LOG_LIMIT + 10):
        await manager.log(f"line {number}")
    snapshot = manager.snapshot(after=1, epoch=manager.epoch)
    assert len(snapshot["logs"]) == LOG_LIMIT and snapshot["gap"] is True
    assert manager.snapshot(after=manager.sequence)["logs"] == []
    assert manager.snapshot(after=manager.sequence, epoch="previous-process")["gap"] is True


def test_redaction_hides_known_secrets_generic_credentials_and_private_keys():
    redactor = LogRedactor()
    redactor.add("fixture secret with spaces")
    for value in ("fixture secret with spaces", "fixture%20secret%20with%20spaces", "password=unknown-password", '"api_key":"unknown-key"', "Bearer unknown-token", "https://user:password@example.test/path", "/bot12345:private_telegram_token/sendMessage"):
        cleaned = redactor.clean(value, "test")
        assert "[REDACTED]" in cleaned
        assert "unknown-" not in cleaned
    private_key_header = "-----BEGIN " + "PRIVATE KEY-----"
    private_key_footer = "-----END " + "PRIVATE KEY-----"
    assert "omitted" in redactor.clean(private_key_header, "test")
    assert "secret-key-line" not in redactor.clean("secret-key-line", "test")
    redactor.clean(private_key_footer, "test")
    assert redactor.clean("normal log", "test") == "normal log"
    assert "\x1b" not in redactor.clean("\x1b[31mtext\x1b[0m", "test")


@pytest.mark.anyio
async def test_command_output_is_bounded_and_timeout_cleans_up_process(tmp_path):
    runner = CommandRunner()
    lines = []

    async def line(text):
        lines.append(text)

    code, _ = await runner.run([sys.executable, "-u", "-c", "print('x' * 10000); print('normal')"],
                               env={"PATH": os.environ["PATH"]}, cwd=tmp_path, line=line)
    assert code == 0 and lines == ["[Oversized log line omitted]", "normal"]
    pid_file = tmp_path / "pid"
    with pytest.raises(AdminError, match="timed out"):
        await runner.run([sys.executable, "-u", "-c", "import os,time,pathlib; pathlib.Path('pid').write_text(str(os.getpid())); time.sleep(30)"],
                         env={"PATH": os.environ["PATH"]}, cwd=tmp_path, timeout=0.5)
    with pytest.raises(ProcessLookupError):
        os.kill(int(pid_file.read_text()), 0)

@pytest.mark.anyio
async def test_failed_checkpoint_does_not_leave_starting_state_or_launch_anything(tmp_path, monkeypatch):
    manager = build(tmp_path)
    await manager.open()
    original = manager.store.write

    def fail(*args):
        raise AdminError(503, "Private storage is unavailable")

    try:
        monkeypatch.setattr(manager.store, "write", fail)
        with pytest.raises(AdminError, match="Private storage"):
            await manager.start()
        assert manager.phase == "idle"
        assert manager.startup is None
        assert not any("up" in argv for argv, _ in manager.runner.calls)
        monkeypatch.setattr(manager.store, "write", original)
        await manager.start()
        await manager.startup
        assert manager.phase == "ready"
    finally:
        await manager.close()


def test_concurrent_coordinator_construction_shares_one_encrypted_credential(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    manager = build(tmp_path)
    (manager.store.directory / "orchestration.json").unlink()

    def construct(_):
        return Orchestrator(manager.settings, manager.store, manager.permissions, manager.provider, manager.telegram, runner=FakeRunner())

    with ThreadPoolExecutor(max_workers=4) as executor:
        copies = list(executor.map(construct, range(4)))
    tokens = {copy.copilot_token for copy in copies}
    assert len(tokens) == 1
    assert manager.store.read("orchestration")[0]["copilot_api_token"] == tokens.pop()


@pytest.mark.anyio
async def test_remote_context_cannot_be_hidden_by_a_local_docker_host_variable(tmp_path, monkeypatch):
    class RemoteRunner(FakeRunner):
        async def run(self, argv, **kwargs):
            if "context" in argv:
                return 0, "ssh://remote.invalid"
            return await super().run(argv, **kwargs)

    monkeypatch.setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
    monkeypatch.setenv("DOCKER_CONTEXT", "remote")
    manager = build(tmp_path, runner=RemoteRunner())
    await manager.open()
    try:
        await manager.start()
        await manager.startup
        assert manager.phase == "failed"
        assert not any("up" in argv for argv, _ in manager.runner.calls)
    finally:
        await manager.close()


@pytest.mark.anyio
async def test_healthy_old_containers_cannot_hide_a_failed_launch(tmp_path):
    runner = FakeRunner()
    runner.selected = ["detection-engine", "copilot-api"]
    runner.fail_up = True
    manager = build(tmp_path, runner=runner)
    await manager.open()
    try:
        await manager.start()
        await manager.startup
        await asyncio.sleep(0.15)
        assert manager.phase == "failed"
        assert manager.snapshot()["ready"] is False
        runner.fail_up = False
        await manager.start()
        await manager.startup
        assert manager.phase == "ready"
    finally:
        await manager.close()