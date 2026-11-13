import json
import os
import re
import stat
from pathlib import Path


def load_provider_file(path: str) -> dict:
    try:
        source_path = Path(path)
        if not source_path.is_absolute():
            raise ValueError("An absolute path is required")
        with source_path.open("rb") as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o077 or info.st_size > 4096):
                raise ValueError("Private provider configuration required")
            data = json.loads(source.read(4097))
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
    except (OSError, ValueError, UnicodeError) as exc:
        raise ValueError("Wizard AI provider configuration is unavailable or invalid") from exc