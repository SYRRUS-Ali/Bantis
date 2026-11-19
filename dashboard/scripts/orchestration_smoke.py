"""Build and check an isolated real Docker stack; no AI calls or existing Range state.

Run from the repository root with a Python environment containing dashboard deps.
Only this test's Compose project and database volume are removed on exit.
"""

import asyncio
import json
import os
import secrets
import shutil
import socket
import sys
import tempfile
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "dashboard"))

from bantis_dashboard.config import Settings
from bantis_dashboard.orchestration import CommandRunner, Orchestrator
from bantis_dashboard.permissions_setup import PermissionsSave, PermissionsSetup
from bantis_dashboard.provider_setup import ProviderSave, ProviderSetup
from bantis_dashboard.secret_store import SecretStore
from bantis_dashboard.telegram_setup import TelegramSave, TelegramSetup


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def copy_sources(target):
    for component in ("detection-engine/app", "ai-copilot/providers", "range/api/app", "deploy"):
        shutil.copytree(ROOT / component, target / component,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".env*", "*.db", "*.sqlite*", "tests"))
    for component in ("detection-engine", "ai-copilot", "range/api"):
        (target / component).mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / component / "requirements.txt", target / component / "requirements.txt")
    for source in (ROOT / "ai-copilot").glob("*.py"):
        shutil.copy2(source, target / "ai-copilot" / source.name)
    shutil.copy2(ROOT / "range/api/Dockerfile", target / "range/api/Dockerfile")
    (target / "range/nginx").mkdir(parents=True)
    shutil.copy2(ROOT / "range/nginx/default.conf", target / "range/nginx/default.conf")
    shutil.copy2(ROOT / "compose.yaml", target / "compose.yaml")
    password, redis, jwt = (secrets.token_hex(24) for _ in range(3))
    path = target / "range/.env"
    path.write_text(f"POSTGRES_USER=smoke\nPOSTGRES_PASSWORD={password}\nPOSTGRES_DB=smoke\n"
                    f"DATABASE_URL=postgresql+asyncpg://smoke:{password}@db:5432/smoke\n"
                    f"JWT_SECRET_KEY={jwt}\nREDIS_PASSWORD={redis}\nREDIS_URL=redis://:{redis}@redis:6379/0\n"
                    "ACCESS_TOKEN_EXPIRE_MINUTES=30\nCACHE_TTL_SECONDS=60\nLOG_LEVEL=INFO\n")
    path.chmod(0o600)


async def smoke():
    with tempfile.TemporaryDirectory(prefix="bantis-orchestration-smoke-") as temporary:
        directory = Path(temporary)
        source, state = directory / "source", directory / "state"
        copy_sources(source)
        state.mkdir(mode=0o700)
        store = SecretStore(state)
        permissions = PermissionsSetup(store)
        permissions.save(PermissionsSave(ai_requests=False, telegram_messages=False, response_decisions=False))
        provider = ProviderSetup(state, store=store)
        provider.save(ProviderSave(provider="none"), "smoke")
        telegram = TelegramSetup(state, store=store)
        telegram.save(TelegramSave(enabled=False), "smoke")
        detection_port, copilot_port, range_port = free_port(), free_port(), free_port()
        settings = Settings(token=secrets.token_urlsafe(32), state_dir=state,
                            detection_url=f"http://127.0.0.1:{detection_port}", copilot_url=f"http://127.0.0.1:{copilot_port}",
                            orchestration_enabled=True, orchestration_range_port=range_port)
        manager = Orchestrator(settings, store, permissions, provider, telegram, root=source)
        print(f"Disposable Compose project: {manager.project}", flush=True)
        await manager.open()
        owned = False
        try:
            runner = CommandRunner()
            code, existing = await runner.run([shutil.which("docker") or "docker", "ps", "--all", "--quiet", "--filter", f"label=com.docker.compose.project={manager.project}"],
                                              env={"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", "")}, cwd=source, capture=True)
            if code or existing.strip():
                raise RuntimeError("Docker is unavailable or the disposable project already exists; refusing to change it")
            owned = True
            await manager.start()
            while not manager.startup.done():
                await asyncio.sleep(5)
                last = manager.logs[-1]["text"] if manager.logs else "Waiting for Docker"
                print(f"{manager.phase}: {last[:180]}", flush=True)
            await manager.startup
            if not manager.snapshot()["ready"]:
                for entry in list(manager.logs)[-35:]:
                    print(entry["text"], flush=True)
                raise RuntimeError(manager.error or "The stack did not become ready")
            async with httpx.AsyncClient(trust_env=False, timeout=5) as client:
                for port in (detection_port, copilot_port, range_port):
                    result = await client.get(f"http://127.0.0.1:{port}/health")
                    assert result.status_code == 200
                response = await client.get(f"http://127.0.0.1:{copilot_port}/usage", headers={"Authorization": f"Bearer {manager.copilot_token}"})
                assert response.status_code == 200 and response.json()["calls"] == 0
                assert (await client.get(f"http://127.0.0.1:{copilot_port}/usage")).status_code == 401
                event = {"event_id": "orchestration-smoke", "timestamp": "2026-11-24T10:00:00Z", "level": "info",
                         "logger": "smoke", "source": "smoke", "event_type": "container_image_pull",
                         "message": "Disposable orchestration smoke event", "details": {"registry": "untrusted.invalid", "image": "fixture:test"}}
                assert (await client.post(f"http://127.0.0.1:{detection_port}/events", json=event)).status_code in {200, 201}
                assert (await client.get(f"http://127.0.0.1:{detection_port}/events")).json()["total"] >= 1
            assert "copilot-worker" not in manager.selected
            assert manager.copilot_token not in json.dumps(manager.snapshot())
            print("PASS: real builds, dependency health, Detection Engine, authenticated Copilot API, Range, event ingestion, and AI disabled", flush=True)
        finally:
            await manager.close()
            if owned and manager.context:
                command, environment = manager.context
                code, _ = await CommandRunner().run([*command, "down", "--volumes", "--remove-orphans"],
                                                   env=environment, cwd=source, timeout=120)
                if code:
                    raise RuntimeError(f"Disposable project cleanup failed: {manager.project}")
                print("Disposable containers and database volume removed.", flush=True)


if __name__ == "__main__":
    asyncio.run(smoke())