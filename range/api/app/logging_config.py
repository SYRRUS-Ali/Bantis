import json
import logging
import os
import sys
import urllib.request
from datetime import datetime, timezone

_RESERVED_ATTRS = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "message", "taskName",
}


class JSONFormatter(logging.Formatter):
    """Renders each log record as a single JSON line."""

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
        self._url = base_url.rstrip("/") + "/events"
        self._timeout = timeout

    def emit(self, record: logging.LogRecord) -> None:
        if not hasattr(record, "event_id"):
            return

        try:
            payload = self.format(record).encode("utf-8")
            request = urllib.request.Request(
                self._url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(request, timeout=self._timeout)
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

    for name in ("uvicorn", "uvicorn.error"):
        uv_logger = logging.getLogger(name)
        uv_logger.handlers = [handler]
        uv_logger.propagate = False

    logging.getLogger("uvicorn.access").disabled = True