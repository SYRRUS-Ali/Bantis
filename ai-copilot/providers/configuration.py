import json
import os
import re
import stat
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


def load_provider_file(path: str) -> dict:
    try:
        source_path = Path(path)
        if not source_path.is_absolute():
            raise ValueError("An absolute path is required")
        key_path = Path(os.environ.get("BANTIS_SECRETS_KEY_FILE") or source_path.parent / ".secrets.key")
        if not key_path.is_absolute():
            raise ValueError("An absolute key path is required")
        for directory in {source_path.parent, key_path.parent}:
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError("Private configuration and key directories required")
        envelope = json.loads(_private_read(source_path, 16384))
        if (not isinstance(envelope, dict) or set(envelope) != {"version", "ciphertext"}
                or type(envelope["version"]) is not int or envelope["version"] != 2
                or not isinstance(envelope["ciphertext"], str)):
            raise ValueError("Encrypted provider configuration required")
        cipher = Fernet(_private_read(key_path, 128))
        payload = json.loads(cipher.decrypt(envelope["ciphertext"].encode("ascii")))
        if (not isinstance(payload, dict) or set(payload) != {"purpose", "data"}
                or payload["purpose"] != "ai-provider" or not isinstance(payload["data"], dict)):
            raise ValueError("Invalid provider document purpose")
        data = payload["data"]
        if not isinstance(data, dict) or type(data.get("version")) is not int or data["version"] != 1:
            raise ValueError("Invalid version")
        if data.get("provider") == "none" and set(data) == {"version", "provider"}:
            return data
        if (set(data) != {"version", "provider", "model", "api_key"}
                or data["provider"] != "claude"
                or not isinstance(data["model"], str)
                or len(data["model"]) > 128
                or not re.fullmatch(r"claude-[A-Za-z0-9_.-]+", data["model"])
                or not isinstance(data["api_key"], str)
                or not 16 <= len(data["api_key"]) <= 512
                or any(not 33 <= ord(c) <= 126 for c in data["api_key"])):
            raise ValueError("Invalid provider configuration")
        return data
    except (OSError, ValueError, UnicodeError, InvalidToken) as exc:
        raise ValueError("Wizard AI provider configuration is unavailable or invalid") from exc


def _private_read(path: Path, limit: int):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_size > limit):
            raise ValueError("Private regular configuration file required")
        data = source.read(limit + 1)
        if len(data) > limit:
            raise ValueError("Configuration exceeds size limit")
        return data