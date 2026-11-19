"""Fixed Docker Compose startup and bounded, redacted live operational logs."""

import asyncio
import fcntl
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import signal
import stat
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

from dotenv import dotenv_values
from pydantic import BaseModel, ConfigDict

from .admin import AdminError
from .secret_store import private_directory, private_read

ROOT = Path(__file__).resolve().parents[2]
SERVICES = ("detection-engine", "db", "redis", "api", "nginx", "copilot-api", "copilot-worker")
RANGE = ("db", "redis", "api", "nginx")
LOG_LIMIT = 500
LINE_LIMIT = 8192


def utc_now():
    return datetime.now(timezone.utc).isoformat()


class StartServices(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class LogRedactor:
    def __init__(self):
        self.values = set()
        self.private_blocks = set()

    def add(self, *values):
        for value in values:
            if isinstance(value, str) and len(value) >= 4:
                self.values.update((value, quote(value, safe=""), json.dumps(value)[1:-1]))

    def clean(self, text, source):
        if "-----BEGIN " in text and "PRIVATE KEY-----" in text:
            self.private_blocks.add(source)
        if source in self.private_blocks:
            if "-----END " in text and "PRIVATE KEY-----" in text:
                self.private_blocks.discard(source)
            return "[Private key content omitted]"
        text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
        text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", text)
        for value in sorted(self.values, key=len, reverse=True):
            text = text.replace(value, "[REDACTED]")
        text = re.sub(r"(?i)(https?://|postgresql(?:\+asyncpg)?://|redis://)([^\s/]+@)", r"\1[REDACTED]@", text)
        text = re.sub(r"(?i)(bearer\s+)[^\s\"',}]+", r"\1[REDACTED]", text)
        text = re.sub(r"(?i)((?:password|secret|api[_-]?key|bot[_-]?token|token|authorization)[\"']?\s*[:=]\s*[\"']?)[^\s\"',}]+", r"\1[REDACTED]", text)
        text = re.sub(r"/bot[0-9]+:[A-Za-z0-9_-]+", "/bot[REDACTED]", text)
        text = re.sub(r"\b(?:sk-ant-|gh[pousr]_)[A-Za-z0-9_-]+", "[REDACTED]", text)
        return text[:4096]


class CommandRunner:
    """Only internal fixed argv reaches this runner; no shell or request commands."""

    async def run(self, argv, *, env, cwd, line=None, timeout=30, capture=False):
        try:
            process = await asyncio.create_subprocess_exec(
                *argv, cwd=cwd, env=env, stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
        except OSError:
            raise AdminError(503, "Docker could not be started. Check its installation and host permissions") from None
        captured = bytearray()

        async def pump(stream, stdout=False):
            pending = bytearray()
            oversized = False
            while chunk := await stream.read(1024):
                if capture and stdout:
                    captured.extend(chunk)
                    if len(captured) > 1048576:
                        raise AdminError(502, "Docker returned too much status data")
                for part in chunk.splitlines(keepends=True):
                    if not oversized:
                        pending.extend(part)
                        if len(pending) > LINE_LIMIT:
                            pending.clear()
                            oversized = True
                    if part.endswith((b"\n", b"\r")):
                        if line:
                            await line("[Oversized log line omitted]" if oversized else pending.decode("utf-8", "replace").rstrip())
                        pending.clear()
                        oversized = False
            if line and (pending or oversized):
                await line("[Oversized log line omitted]" if oversized else pending.decode("utf-8", "replace"))

        readers = [asyncio.create_task(pump(process.stdout, True)), asyncio.create_task(pump(process.stderr))]
        try:
            async def finish():
                await asyncio.gather(*readers)
                return await process.wait()

            code = await asyncio.wait_for(finish(), timeout=timeout)
            return code, captured.decode("utf-8", "replace")
        except TimeoutError:
            raise AdminError(504, "Docker operation timed out. Some containers may already be running; check status before retrying") from None
        finally:
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    await asyncio.wait_for(process.wait(), 3)
                except TimeoutError:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    await process.wait()
            for reader in readers:
                reader.cancel()
            await asyncio.gather(*readers, return_exceptions=True)


def credential_record(store):
    # Serialize only initial credential creation, independently of the long-lived
    # coordinator lock, so a second dashboard cannot replace the first token.
    try:
        descriptor = os.open(store.directory / ".orchestration.settings.lock",
                             os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        with os.fdopen(descriptor, "rb") as lock:
            info = os.fstat(lock.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError("Private settings lock required")
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                saved, _ = store.read("orchestration")
                if (set(saved) != {"version", "copilot_api_token", "services"}
                        or type(saved["version"]) is not int or saved["version"] != 1
                        or not isinstance(saved["copilot_api_token"], str)
                        or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", saved["copilot_api_token"])
                        or not isinstance(saved["services"], list)
                        or len(saved["services"]) != len(set(saved["services"]))
                        or any(name not in SERVICES for name in saved["services"])
                        or (saved["services"] and not {"detection-engine", "copilot-api"}.issubset(saved["services"]))):
                    raise ValueError("Invalid orchestration settings")
            except FileNotFoundError:
                saved = {"version": 1, "copilot_api_token": secrets.token_urlsafe(32), "services": []}
                store.write("orchestration", saved)
            except (ValueError, TypeError):
                raise AdminError(503, "Saved orchestration settings are invalid") from None
            return saved
    except (OSError, ValueError):
        raise AdminError(503, "Private orchestration settings are unavailable") from None


class Orchestrator:
    def __init__(self, settings, store, permissions, provider, telegram, *, runner=None, root=ROOT, interval=3):
        self.settings, self.store = settings, store
        self.permissions, self.provider, self.telegram = permissions, provider, telegram
        self.runner = runner or CommandRunner()
        self.root, self.interval = root, interval
        self.project = "bantis-" + hashlib.sha256(str(store.directory).encode()).hexdigest()[:12]
        self.phase, self.error, self.last_checked = "idle", None, None
        self.selected = ["detection-engine", "copilot-api", *(RANGE if settings.orchestration_range else ())]
        self.rows = {}
        self.logs = deque(maxlen=LOG_LIMIT)
        self.epoch, self.sequence, self.revision = secrets.token_urlsafe(12), 0, 0
        self.changed = asyncio.Condition()
        self.lock = asyncio.Lock()
        self.startup = self.monitor = self.follower = None
        self.context = None
        self.lock_file = None
        self.redactor = LogRedactor()
        self.redactor.add(settings.token, settings.copilot_token)
        saved = credential_record(store)
        self.record = saved
        self.copilot_token = saved["copilot_api_token"]
        self.redactor.add(self.copilot_token, saved["copilot_api_token"])
        if saved["services"]:
            self.selected = saved["services"][:]

    async def notify(self):
        async with self.changed:
            self.revision += 1
            self.changed.notify_all()

    async def log(self, text, source="startup"):
        clean = self.redactor.clean(text, source)
        if clean:
            self.sequence += 1
            self.logs.append({"sequence": self.sequence, "at": utc_now(), "source": source, "text": clean})
            await self.notify()

    def snapshot(self, *, after=0, epoch=None):
        first = self.logs[0]["sequence"] if self.logs else self.sequence + 1
        reset = epoch is not None and epoch != self.epoch
        cursor = 0 if reset else after
        return {"enabled": True, "project": self.project, "phase": self.phase, "error": self.error,
                "last_checked": self.last_checked, "epoch": self.epoch, "last_sequence": self.sequence,
                "first_sequence": first, "revision": self.revision,
                "ready": self.phase == "ready" and self.error is None,
                "gap": reset or (cursor > 0 and cursor < first - 1),
                "services": [{"name": name, "selected": name in self.selected,
                              "state": self.rows.get(name, {}).get("state", "unknown"),
                              "health": self.rows.get(name, {}).get("health", ""),
                              "note": "Optional; not selected for this launch" if name not in self.selected else
                                      "Process running; no health endpoint" if name == "copilot-worker" else "Health check required"}
                             for name in SERVICES],
                "logs": [entry for entry in self.logs if entry["sequence"] > cursor]}

    async def open(self):
        try:
            descriptor = os.open(self.store.directory / ".orchestration.lock",
                                 os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            self.lock_file = os.fdopen(descriptor, "rb")
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise OSError("Private orchestration lock required")
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            if self.lock_file:
                self.lock_file.close()
                self.lock_file = None
            self.phase = "unavailable"
            self.error = "Another dashboard owns orchestration, or its private lock is unavailable. Use one worker"
            return
        self.monitor = asyncio.create_task(self._monitor())

    async def close(self):
        tasks = [task for task in (self.startup, self.monitor, self.follower) if task]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if self.lock_file:
            self.lock_file.close()
            self.lock_file = None

    def _prepare(self, *, launch=False):
        self.store.status()
        if launch:
            state = self.permissions.status()
            if not state["configured"]:
                raise AdminError(409, "Save Permissions before starting services")
            provider = self.provider.status()
            telegram = self.telegram.status()
            if not provider["configured"] or not telegram["configured"]:
                raise AdminError(409, "Save an AI provider choice and configure or skip Telegram before starting services")
            self.selected = ["detection-engine", "copilot-api", *(RANGE if self.settings.orchestration_range else ())]
            if state["ai_requests"] and provider["has_key"]:
                self.selected.append("copilot-worker")
        env = {key: value for key, value in os.environ.items() if key in {
            "PATH", "HOME", "LANG", "USER", "XDG_RUNTIME_DIR", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG",
            "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR",
        }}
        env.update({"BANTIS_ORCHESTRATION_STATE": str(self.store.directory),
                    "BANTIS_IMAGE_PREFIX": self.project, "BANTIS_RANGE_PORT": str(self.settings.orchestration_range_port),
                    "BANTIS_ORCHESTRATION_KEY_DIR": str(self.store.key_file.parent),
                    "BANTIS_ORCHESTRATION_KEY_NAME": self.store.key_file.name,
                    "BANTIS_RUNTIME_UID": str(os.getuid()), "BANTIS_RUNTIME_GID": str(os.getgid()),
                    "COMPOSE_ANSI": "never", "BUILDKIT_PROGRESS": "plain"})
        for attr, key in (("detection_url", "BANTIS_DETECTION_PORT"), ("copilot_url", "BANTIS_COPILOT_PORT")):
            url = urlsplit(getattr(self.settings, attr))
            if url.scheme != "http" or url.hostname not in {"127.0.0.1", "localhost"} or url.path not in {"", "/"}:
                raise AdminError(409, "Managed service URLs must use HTTP on localhost or 127.0.0.1 without a path")
            env[key] = str(url.port or 80)
        env_file = "/dev/null"
        if any(name in self.selected for name in RANGE):
            env_file = str(self.root / "range" / ".env")
            try:
                values = dotenv_values(stream=io.StringIO(private_read(Path(env_file)).decode()), interpolate=False)
            except (OSError, ValueError):
                raise AdminError(409, "Configure range/.env with private permissions (chmod 600), or disable Range orchestration on the host") from None
            required = ("POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB", "DATABASE_URL", "JWT_SECRET_KEY", "REDIS_PASSWORD", "REDIS_URL")
            if any(not values.get(key) for key in required):
                raise AdminError(409, "Fill in the database, Redis, and JWT settings in range/.env before starting Range")
            if any(str(values[key]).startswith(("change_me", "change_this")) for key in ("POSTGRES_PASSWORD", "REDIS_PASSWORD", "JWT_SECRET_KEY")):
                raise AdminError(409, "Replace the placeholder database, Redis, and JWT secrets in range/.env")
            self.redactor.add(*(value for key, value in values.items() if re.search(r"PASSWORD|SECRET|TOKEN|KEY|URL", key)))
        for name, field in (("ai-provider", "api_key"), ("telegram", "bot_token")):
            try:
                document, _ = self.store.read(name)
                self.redactor.add(document.get(field))
            except FileNotFoundError:
                pass
        self.redactor.add(private_read(self.store.key_file, 128).decode())
        docker = shutil.which("docker", path=env.get("PATH")) or "docker"
        command = [docker, "compose", "--project-name", self.project, "--project-directory", str(self.root),
                   "--env-file", env_file, "-f", str(self.root / "compose.yaml"), "--profile", "range", "--profile", "ai"]
        return command, env

    async def _command(self, args, *, stream=False, capture=False, timeout=30, source="startup"):
        command, env = self.context
        return await self.runner.run([*command, *args], env=env, cwd=self.root,
                                     line=(lambda line: self.log(line, source)) if stream else None,
                                     capture=capture, timeout=timeout)

    async def start(self):
        async with self.lock:
            if self.lock_file is None:
                raise AdminError(503, self.error or "Service orchestration is unavailable")
            if (self.startup and not self.startup.done()) or self.phase == "ready":
                return self.snapshot()
            self.context = self._prepare(launch=True)
            record = {**self.record, "services": self.selected[:]}
            self.store.write("orchestration", record)
            self.record = record
            self.phase, self.error = "starting", None
            self.startup = asyncio.create_task(self._start())
            await self.log("Starting the configured services. Dependencies and health checks run automatically.")
            return self.snapshot()

    async def _start(self):
        try:
            command, env = self.context
            docker = command[0]
            host = env.get("DOCKER_HOST") if not env.get("DOCKER_CONTEXT") else None
            if host and not host.startswith("unix://"):
                raise AdminError(409, "Orchestration requires a local Unix-socket Docker daemon")
            if not host:
                code, context = await self.runner.run([docker, "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
                                                      env=env, cwd=self.root, capture=True)
                if code or not context.strip().startswith("unix://"):
                    raise AdminError(503, "Select an accessible local Docker context before starting services")
            code, _ = await self.runner.run([docker, "info", "--format", "{{.ServerVersion}}"], env=env, cwd=self.root, capture=True)
            if code:
                raise AdminError(503, "Docker is unavailable. Start the daemon and check this user's Docker access")
            code, _ = await self._command(["config", "--quiet"], stream=True)
            if code:
                raise AdminError(409, "The Compose configuration is invalid. Check the startup logs and host settings")
            for name in ("detection-data", "copilot-data"):
                directory = self.store.directory / name
                directory.mkdir(mode=0o700, exist_ok=True)
                private_directory(directory)
            if self.follower:
                self.follower.cancel()
                await asyncio.gather(self.follower, return_exceptions=True)
            self.follower = asyncio.create_task(self._follow())
            code, _ = await self._command(["up", "--detach", "--build", "--wait", "--wait-timeout", "120", *self.selected],
                                          stream=True, timeout=900)
            if code:
                raise AdminError(503, "Service startup failed. Review the logs and service states, fix the cause, then retry")
            await self._poll()
            if not self._ready():
                raise AdminError(503, "Startup returned without all selected services ready. Check the service states and retry")
            self.phase, self.error = "ready", None
            await self.log("All selected services are healthy or running. Startup is complete.")
        except asyncio.CancelledError:
            raise
        except (AdminError, OSError, ValueError) as exc:
            self.phase = "failed"
            self.error = exc.message if isinstance(exc, AdminError) else "Service startup failed. Check host storage and Docker access"
            await self.log(self.error)
        finally:
            await self.notify()

    def _ready(self):
        return all(self.rows.get(name, {}).get("state") == "running" and
                   (self.rows[name]["health"] == "healthy" if name != "copilot-worker" else self.rows[name]["health"] in {"", "healthy"})
                   for name in self.selected)

    async def _poll(self):
        code, text = await self._command(["ps", "--all", "--format", "json", *SERVICES], capture=True)
        if code:
            raise AdminError(503, "Service status is unavailable. Check Docker access and refresh")
        try:
            try:
                data = json.loads(text) if text.strip() else []
            except ValueError:
                data = [json.loads(line) for line in text.splitlines() if line.strip()]
            if isinstance(data, dict):
                data = [data]
            if not isinstance(data, list):
                raise ValueError("Expected service list")
            rows = {}
            for item in data:
                if not isinstance(item, dict):
                    raise ValueError("Invalid service state")
                name = item.get("Service")
                if name not in SERVICES:
                    continue
                state, health = item.get("State"), item.get("Health", "")
                if state not in {"running", "exited", "created", "restarting", "paused", "dead", "removing"} or health not in {"", "healthy", "unhealthy", "starting"}:
                    raise ValueError("Invalid service state")
                if name in rows:
                    raise ValueError("Unexpected replica count")
                rows[name] = {"state": state, "health": health}
            self.rows, self.last_checked = rows, utc_now()
        except (ValueError, TypeError):
            raise AdminError(502, "Docker returned invalid service status data") from None
        await self.notify()

    async def _monitor(self):
        while True:
            try:
                if not self.context:
                    self.context = self._prepare()
                await self._poll()
                if not self.startup or self.startup.done():
                    if self.phase == "failed":
                        pass  # A failed launch still needs an explicit successful retry.
                    elif self.record["services"] and self._ready():
                        self.phase, self.error = "ready", None
                    elif self.record["services"] and self.phase != "failed":
                        self.phase = "degraded"
                        self.error = "Some selected services are stopped or unhealthy. Review their states before retrying"
                    elif not self.record["services"]:
                        self.error = None
                    if self.rows and (not self.follower or self.follower.done()):
                        self.follower = asyncio.create_task(self._follow())
            except (AdminError, OSError, ValueError) as exc:
                self.error = exc.message if isinstance(exc, AdminError) else "Service status is unavailable"
            await self.notify()
            await asyncio.sleep(self.interval)

    async def _follow(self):
        # A bounded recent-log replay reconnects after container recreation.
        seen = deque(maxlen=1000)
        while True:
            async def line(text):
                clean = self.redactor.clean(text, "services")
                if clean not in seen:
                    seen.append(clean)
                    await self.log(clean, "services")

            try:
                command, env = self.context
                await self.runner.run([*command, "logs", "--follow", "--no-color", "--timestamps", "--tail", "100", *SERVICES],
                                      env=env, cwd=self.root, line=line, timeout=None)
            except (AdminError, OSError):
                await self.log("Live service logs disconnected; reconnecting shortly.", "system")
            await asyncio.sleep(self.interval)