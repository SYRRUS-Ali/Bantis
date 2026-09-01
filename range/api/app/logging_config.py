import json
import logging
import sys
from datetime import datetime, timezone

# Standard attributes every LogRecord carries. Anything else attached via
# `extra={...}` on a log call is "our" data and gets merged into the JSON
# output directly (e.g. method, path, status_code below).
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


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level.upper())

    # Route uvicorn's own log lines through the same JSON handler, so every
    # line in the output has one consistent shape instead of mixing formats.
    for name in ("uvicorn", "uvicorn.error"):
        uv_logger = logging.getLogger(name)
        uv_logger.handlers = [handler]
        uv_logger.propagate = False

    # Our own AccessLogMiddleware (app/middleware.py) replaces uvicorn's
    # built-in access log, so disable the default to avoid duplicate lines.
    logging.getLogger("uvicorn.access").disabled = True
