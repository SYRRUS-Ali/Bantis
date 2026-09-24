from __future__ import annotations

import http.client
import json
import logging
import os
import sys
import urllib.parse
from datetime import datetime, timezone

_ALLOWED_URL_SCHEMES = {"http", "https"}

_RESERVED_ATTRS = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "message", "taskName",
}


class JSONFormatter(logging.Formatter):

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        for key, value in record.__dict__.items():
            if key not in _RESERVED_ATTRS:
                payload[key] = value

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str)


class DetectionEngineHandler(logging.Handler):

    def __init__(self, base_url: str, timeout: float = 2.0) -> None:
        super().__init__()
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme not in _ALLOWED_URL_SCHEMES:
            raise ValueError(
                f"DETECTION_ENGINE_URL must be http or https, got {parsed.scheme!r} in {base_url!r}"
            )
        self._is_https = parsed.scheme == "https"
        self._host = parsed.hostname
        self._port = parsed.port or (443 if self._is_https else 80)
        self._path = parsed.path.rstrip("/") + "/events"
        self._timeout = timeout

    def emit(self, record: logging.LogRecord) -> None:
        if not hasattr(record, "event_id"):
            return

        try:
            payload = self.format(record).encode("utf-8")
            connection_cls = http.client.HTTPSConnection if self._is_https else http.client.HTTPConnection
            connection = connection_cls(self._host, self._port, timeout=self._timeout)
            try:
                connection.request(
                    "POST", self._path, body=payload, headers={"Content-Type": "application/json"}
                )
                response = connection.getresponse()
                response.read()
                if response.status >= 300:
                    print(
                        f"detection-engine forwarding failed: HTTP {response.status}",
                        file=sys.stderr,
                    )
            finally:
                connection.close()
        except Exception as exc:
            print(f"detection-engine forwarding failed: {exc}", file=sys.stderr)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())

    root = logging.getLogger()
    handlers = [handler]

    detection_engine_url = os.environ.get("DETECTION_ENGINE_URL")
    if detection_engine_url:
        forwarder = DetectionEngineHandler(detection_engine_url)
        forwarder.setFormatter(JSONFormatter())
        handlers.append(forwarder)

    root.handlers = handlers
    root.setLevel(level.upper())