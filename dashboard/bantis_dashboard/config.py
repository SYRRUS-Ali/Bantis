import math
import os
from dataclasses import dataclass, field
from urllib.parse import urlsplit


def validate_url(value: str, *, origin: bool = False) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (origin and parsed.path not in {"", "/"})
    ):
        raise ValueError(
            "Service URLs must be HTTP(S), without credentials, query, or fragment"
        )
    _ = parsed.port  # Validate the port before startup.
    return value.rstrip("/")


@dataclass(frozen=True)
class Settings:
    token: str = field(repr=False)
    origin: str = "http://127.0.0.1:8200"
    detection_url: str = "http://127.0.0.1:8000"
    poll_seconds: float = 5.0
    session_seconds: int = 28800

    def __post_init__(self):
        if not 32 <= len(self.token.encode()) <= 512:
            raise ValueError("DASHBOARD_TOKEN must contain 32–512 bytes")
        object.__setattr__(self, "origin", validate_url(self.origin, origin=True))
        object.__setattr__(self, "detection_url", validate_url(self.detection_url))
        if not math.isfinite(self.poll_seconds) or not 1 <= self.poll_seconds <= 300:
            raise ValueError("DASHBOARD_POLL_SECONDS must be between 1 and 300")
        if not 1 <= self.session_seconds <= 28800:
            raise ValueError("Session duration must be between 1 second and 8 hours")

    @classmethod
    def from_env(cls):
        return cls(
            token=os.environ.get("DASHBOARD_TOKEN", ""),
            origin=os.environ.get("DASHBOARD_ORIGIN", "http://127.0.0.1:8200"),
            detection_url=os.environ.get(
                "DETECTION_ENGINE_URL", "http://127.0.0.1:8000"
            ),
            poll_seconds=float(os.environ.get("DASHBOARD_POLL_SECONDS", "5")),
        )