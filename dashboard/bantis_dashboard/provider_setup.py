"""Authenticated provider setup with a real, bounded provider request."""

import json
import os
import secrets
import stat
import tempfile
import threading
import time
from pathlib import Path
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .admin import AdminError, AuthLimiter

ENDPOINT = "https://api.anthropic.com/v1/messages"


class ProviderTest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    provider: Literal["claude"] = "claude"
    model: str = Field(min_length=1, max_length=128, pattern=r"^claude-[A-Za-z0-9_.-]+$")
    api_key: str = Field(min_length=16, max_length=512, repr=False)

    @field_validator("api_key")
    @classmethod
    def header_safe(cls, value):
        if not value.isascii() or any(c.isspace() or ord(c) < 33 or ord(c) > 126 for c in value):
            raise ValueError("Invalid API key")
        return value


class ProviderSave(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    provider: Literal["claude", "none"]
    test_id: str = Field(default="", max_length=128)


class ProviderSetup:
    def __init__(self, directory: Path, *, transport=None):
        self.path = directory / "ai-provider.json"
        self.transport = transport
        self.limiter = AuthLimiter()
        self.lock = threading.Lock()
        self.pending = {}

    def status(self):
        try:
            with self.path.open("rb") as source:
                info = os.fstat(source.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or info.st_mode & 0o077 or info.st_size > 4096):
                    raise ValueError("Invalid provider file")
                data = json.loads(source.read(4097))
            if not isinstance(data, dict) or type(data.get("version")) is not int or data["version"] != 1:
                raise ValueError("Invalid provider version")
            if data.get("provider") == "none" and set(data) == {"version", "provider"}:
                return {"configured": True, "provider": "none", "model": None, "has_key": False}
            if set(data) != {"version", "provider", "model", "api_key"}:
                raise ValueError("Invalid provider fields")
            fields = {key: value for key, value in data.items() if key != "version"}
            parsed = ProviderTest.model_validate(fields)
            return {"configured": True, "provider": "claude", "model": parsed.model, "has_key": True}
        except FileNotFoundError:
            return {"configured": False, "provider": "none", "model": None, "has_key": False}
        except (OSError, ValueError, ValidationError) as exc:
            raise AdminError(503, "Saved AI provider configuration is unavailable") from exc

    def _prune(self):
        now = time.monotonic()
        self.pending = {key: value for key, value in self.pending.items() if value[0] > now}

    def forget(self, session_id):
        with self.lock:
            self.pending = {key: value for key, value in self.pending.items() if value[1] != session_id}

    def expire(self):
        with self.lock:
            self._prune()

    def clear(self):
        with self.lock:
            self.pending.clear()

    def test(self, body: ProviderTest, session_id: str):
        self.limiter.check()
        with self.lock:
            self._prune()
            if len(self.pending) >= 32:
                raise AdminError(429, "Too many pending connection tests. Try again later")
        started = time.monotonic()
        try:
            with httpx.Client(timeout=15, follow_redirects=False, trust_env=False, transport=self.transport) as client:
                with client.stream("POST", ENDPOINT,
                                   headers={"x-api-key": body.api_key, "anthropic-version": "2023-06-01"},
                                   json={"model": body.model, "max_tokens": 16,
                                         "messages": [{"role": "user", "content": "Reply with OK."}]}) as response:
                    errors = {
                        401: (422, "The provider rejected the API key"),
                        403: (422, "The API key does not have access to this provider or model"),
                        400: (422, "The provider rejected this model or request; check the model and billing"),
                        404: (422, "This model is not available to the API key"),
                        402: (422, "Provider billing or credits need attention"),
                        429: (429, "The provider rate limit was reached. Try again later"),
                    }
                    if response.status_code != 200:
                        code, message = errors.get(response.status_code, (503, "The AI provider is unavailable"))
                        raise AdminError(code, message)
                    content = bytearray()
                    for chunk in response.iter_bytes():
                        content.extend(chunk)
                        if len(content) > 65536 or time.monotonic() - started > 20:
                            raise AdminError(502, "The provider returned an oversized or slow response")
            data = json.loads(content)
            if (not isinstance(data, dict) or data.get("type") != "message"
                    or data.get("role") != "assistant" or not isinstance(data.get("content"), list)
                    or not any(isinstance(block, dict) and block.get("type") == "text"
                               and isinstance(block.get("text"), str) and block["text"].strip()
                               for block in data["content"])):
                raise ValueError("Invalid provider response")
        except (httpx.HTTPError, OSError) as exc:
            raise AdminError(503, "Connection failed or timed out. Delivery is uncertain; the test may have incurred usage") from exc
        except (ValueError, UnicodeError) as exc:
            raise AdminError(502, "The provider returned invalid data") from exc
        test_id = secrets.token_urlsafe(32)
        with self.lock:
            self._prune()
            self.forget_unlocked(session_id)
            if len(self.pending) >= 32:
                raise AdminError(429, "Too many pending connection tests. Try again later")
            self.pending[test_id] = (time.monotonic() + 300, session_id, body)
        return {"connected": True, "test_id": test_id, "model": body.model, "expires_in": 300}

    def forget_unlocked(self, session_id):
        self.pending = {key: value for key, value in self.pending.items() if value[1] != session_id}

    def save(self, body: ProviderSave, session_id: str):
        with self.lock:
            self._prune()
            if body.provider == "none":
                data = {"version": 1, "provider": "none"}
            else:
                tested = self.pending.get(body.test_id)
                if tested is None or tested[1] != session_id:
                    raise AdminError(409, "Test the connection again before saving this provider")
                data = {"version": 1, **tested[2].model_dump()}
            self._write(data)
            self.forget_unlocked(session_id)
        return self.status()

    def _write(self, data):
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", dir=self.path.parent, delete=False) as target:
                temporary = target.name
                os.fchmod(target.fileno(), 0o600)
                json.dump(data, target)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError as exc:
            raise AdminError(503, "AI provider configuration could not be saved") from exc
        finally:
            if temporary and os.path.exists(temporary):
                try:
                    os.unlink(temporary)
                except OSError:
                    pass