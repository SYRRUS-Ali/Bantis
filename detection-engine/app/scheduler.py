from __future__ import annotations

import logging
import os
import threading
from collections.abc import Callable
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.correlation import run_correlation
from app.db import SessionLocal
from app.incident_models import IncidentORM

logger = logging.getLogger("detection_engine.scheduler")

DEFAULT_INTERVAL_SECONDS = 10.0


def interval_from_env() -> float:
    """CORRELATION_INTERVAL_SECONDS; 0 turns scheduled correlation off."""
    raw = os.environ.get("CORRELATION_INTERVAL_SECONDS") or str(DEFAULT_INTERVAL_SECONDS)
    interval = float(raw)
    if interval < 0:
        raise ValueError(f"CORRELATION_INTERVAL_SECONDS must be >= 0, got {raw!r}")
    return interval


class CorrelationScheduler:
    def __init__(self, interval_seconds: float, session_factory: Callable[[], Session] = SessionLocal) -> None:
        self._interval = interval_seconds
        self._session_factory = session_factory
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def run_once(self) -> list[IncidentORM]:
        with self._session_factory() as session:
            incidents = run_correlation(session, now=datetime.now(timezone.utc))
        for incident in incidents:
            logger.info("incident %s formed: %s (%s)", incident.incident_id, incident.pattern, incident.severity)
        return incidents

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self.run_once()
            except Exception:
                # One bad pass (a locked database, a malformed event) must not
                # end correlation for the life of the process.
                logger.exception("correlation pass failed; retrying in %ss", self._interval)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="correlation-scheduler", daemon=True)
        self._thread.start()
        logger.info("correlating every %ss", self._interval)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._interval + 5)