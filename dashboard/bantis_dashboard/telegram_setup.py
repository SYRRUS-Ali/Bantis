"""Optional Telegram setup with session-bound test receipts and private storage."""

import json
import logging
import re
import secrets
import threading
import time
from pathlib import Path

import httpx
from pydantic import BaseModel, ConfigDict, Field

from .admin import AdminError, AuthLimiter
from .secret_store import SecretStore


class _RedactBotToken(logging.Filter):
    def filter(self, record):
        record.msg = re.sub(r"/bot[0-9]+:[A-Za-z0-9_-]+", "/bot[REDACTED]", record.getMessage())
        record.args = ()
        return True


# Telegram requires the token in its API path. HTTPX's INFO request log must
# redact it before any application handler sees the formatted URL.
logging.getLogger("httpx").addFilter(_RedactBotToken())

TEST_MESSAGE = "Bantis setup test: Telegram connection confirmed."


class TelegramTest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    bot_token: str = Field(min_length=20, max_length=256, pattern=r"^[0-9]+:[A-Za-z0-9_-]+$", repr=False)
    chat_id: str = Field(min_length=1, max_length=64, pattern=r"^(?:-?[1-9][0-9]*|@[A-Za-z][A-Za-z0-9_]{4,31})$")


class TelegramSave(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    enabled: bool
    test_id: str = Field(default="", max_length=128)


class TelegramSetup:
    def __init__(self, directory: Path, *, transport=None, store=None):
        self.path = directory / "telegram.json"
        self.store = store or SecretStore(directory)
        self.transport = transport
        self.limiter = AuthLimiter()
        self.lock = threading.Lock()
        self.pending = {}

    def migrate(self):
        try:
            data, legacy = self.store.read("telegram", allow_legacy=True)
        except FileNotFoundError:
            return
        if legacy:
            self._status(data)
            self._write(data)

    def status(self):
        try:
            data, _ = self.store.read("telegram")
            return self._status(data)
        except FileNotFoundError:
            return {"configured": False, "enabled": False, "chat_id": None, "has_token": False}
        except (OSError, ValueError) as exc:
            raise AdminError(503, "Saved Telegram configuration is unavailable") from exc

    def _status(self, data):
        try:
            if (not isinstance(data, dict) or type(data.get("version")) is not int
                    or data["version"] != 1 or type(data.get("enabled")) is not bool):
                raise ValueError("Invalid Telegram configuration")
            if data["enabled"]:
                if set(data) != {"version", "enabled", "bot_token", "chat_id"}:
                    raise ValueError("Invalid Telegram fields")
                parsed = TelegramTest.model_validate({key: data[key] for key in ("bot_token", "chat_id")})
                return {"configured": True, "enabled": True, "chat_id": parsed.chat_id, "has_token": True}
            if set(data) != {"version", "enabled"}:
                raise ValueError("Invalid disabled configuration")
            return {"configured": True, "enabled": False, "chat_id": None, "has_token": False}
        except (OSError, ValueError):
            raise AdminError(503, "Saved Telegram configuration is unavailable") from None

    def _prune(self):
        now = time.monotonic()
        self.pending = {key: value for key, value in self.pending.items() if value[0] > now}

    def _forget(self, session_id):
        self.pending = {key: value for key, value in self.pending.items() if value[1] != session_id}

    def forget(self, session_id):
        with self.lock:
            self._forget(session_id)

    def expire(self):
        with self.lock:
            self._prune()

    def clear(self):
        with self.lock:
            self.pending.clear()

    def test(self, body: TelegramTest, session_id: str):
        self.limiter.check()
        with self.lock:
            self._prune()
            # A failed replacement test must not leave an older receipt usable.
            self._forget(session_id)
            if len(self.pending) >= 32:
                raise AdminError(429, "Too many pending Telegram tests. Try again later")
        started = time.monotonic()
        try:
            with httpx.Client(timeout=15, follow_redirects=False, trust_env=False, transport=self.transport) as client:
                with client.stream("POST", f"https://api.telegram.org/bot{body.bot_token}/sendMessage",
                                   json={"chat_id": body.chat_id, "text": TEST_MESSAGE}) as response:
                    content = bytearray()
                    for chunk in response.iter_bytes():
                        content.extend(chunk)
                        if len(content) > 65536 or time.monotonic() - started > 20:
                            raise AdminError(502, "Telegram returned an oversized or slow response")
            data = json.loads(content)
            if not isinstance(data, dict) or type(data.get("ok")) is not bool:
                raise ValueError("Invalid Telegram response")
            if response.status_code != 200 or data.get("ok") is not True:
                errors = {
                    400: (422, "Telegram rejected the chat. Check the chat ID and start the bot or add it to the chat"),
                    401: (422, "Telegram rejected the bot token"),
                    404: (422, "Telegram rejected the bot token or API request"),
                    403: (422, "The bot cannot send to this chat. Unblock it or grant permission to send messages"),
                    429: (429, "Telegram rate limit reached. Wait before testing again"),
                }
                code = data.get("error_code")
                if type(code) is not int:
                    code = response.status_code
                status, message = errors.get(code, (503, "Telegram is unavailable"))
                raise AdminError(status, message)
            result = data.get("result")
            if (not isinstance(result, dict) or type(result.get("message_id")) is not int
                    or result["message_id"] <= 0 or not isinstance(result.get("chat"), dict)
                    or type(result["chat"].get("id")) is not int
                    or result.get("text") != TEST_MESSAGE):
                raise ValueError("Invalid Telegram message")
            if not body.chat_id.startswith("@") and str(result["chat"]["id"]) != body.chat_id:
                raise ValueError("Unexpected Telegram chat")
        except (httpx.HTTPError, OSError) as exc:
            raise AdminError(503, "Telegram connection failed or timed out. Delivery is uncertain; check the chat before retrying") from exc
        except (ValueError, UnicodeError) as exc:
            raise AdminError(502, "Telegram returned invalid data. Delivery is uncertain; check the chat before retrying") from exc
        test_id = secrets.token_urlsafe(32)
        with self.lock:
            self._prune()
            self._forget(session_id)
            if len(self.pending) >= 32:
                raise AdminError(429, "Too many pending Telegram tests. Try again later")
            self.pending[test_id] = (time.monotonic() + 300, session_id, body)
        return {"connected": True, "test_id": test_id, "expires_in": 300}

    def save(self, body: TelegramSave, session_id: str):
        with self.lock:
            self._prune()
            data = {"version": 1, "enabled": body.enabled}
            if body.enabled:
                tested = self.pending.get(body.test_id)
                if tested is None or tested[1] != session_id:
                    raise AdminError(409, "Send a successful test message again before saving Telegram")
                data.update(tested[2].model_dump())
            self._write(data)
            self._forget(session_id)
        return self.status()

    def _write(self, data):
        self.store.write("telegram", data)