from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import threading
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from converter import MissingEvidenceError, as_utc_datetime, build_copilot_request
from detection_client import DetectionEngineClient, DetectionEngineError
from models import CopilotResponse
from providers.base import AIProvider

logger = logging.getLogger("ai_copilot.worker")

DEFAULT_LOOKBACK_SECONDS = 60

ResultSink = Callable[[dict, CopilotResponse], None]


def print_result(incident: dict, response: CopilotResponse) -> None:
    line = {"incident": incident, "analysis": json.loads(response.model_dump_json())}
    print(json.dumps(line), flush=True)


class CopilotWorker:
    def __init__(
        self,
        client: DetectionEngineClient,
        provider: AIProvider,
        on_result: ResultSink = print_result,
        start_from: datetime | None = None,
        lookback_seconds: int = DEFAULT_LOOKBACK_SECONDS,
    ) -> None:
        self._client = client
        self._provider = provider
        self._on_result = on_result
        self._start = as_utc_datetime(start_from) if start_from else datetime.now(timezone.utc)
        self._cursor = self._start
        self._lookback = timedelta(seconds=lookback_seconds)
        self._processed: dict[str, datetime] = {}

    def poll_once(self) -> list[CopilotResponse]:
        try:
            incidents = self._client.list_incidents_since(self._cursor - self._lookback)
        except DetectionEngineError as exc:
            logger.warning("detection-engine unreachable, will retry next poll: %s", exc)
            return []

        pending = []
        for incident in incidents:
            created_at = as_utc_datetime(incident["created_at"])
            if created_at < self._start or incident["incident_id"] in self._processed:
                continue
            pending.append((created_at, incident))
        pending.sort(key=lambda pair: (pair[0], pair[1]["incident_id"]))

        results = []
        held_at: datetime | None = None
        for created_at, incident in pending:
            response = self._analyze(incident)
            if response is None:
                held_at = created_at if held_at is None else held_at
                continue
            self._deliver(incident, response)
            self._processed[incident["incident_id"]] = created_at
            if held_at is None:
                self._cursor = max(self._cursor, created_at)
            results.append(response)

        self._forget_ids_older_than(self._cursor - self._lookback)
        return results

    def _analyze(self, incident: dict) -> CopilotResponse | None:
        incident_id = incident["incident_id"]
        try:
            events = self._client.get_incident_events(incident_id)
        except DetectionEngineError as exc:
            logger.warning("could not fetch events for %s, will retry next poll: %s", incident_id, exc)
            return None

        try:
            return self._provider.analyze(build_copilot_request(incident, events))
        except MissingEvidenceError as exc:
            return CopilotResponse.analysis_failed(incident_id, "none (not sent to a provider)", str(exc))
        except Exception as exc:
            logger.exception("unexpected error analyzing %s", incident_id)
            return CopilotResponse.analysis_failed(incident_id, "none (worker error)", f"{type(exc).__name__}: {exc}")

    def _deliver(self, incident: dict, response: CopilotResponse) -> None:
        try:
            self._on_result(incident, response)
        except Exception:
            logger.exception("result sink failed for %s; analysis follows", incident["incident_id"])
            print(response.model_dump_json(), file=sys.stderr, flush=True)

    def _forget_ids_older_than(self, horizon: datetime) -> None:
        self._processed = {i: t for i, t in self._processed.items() if t >= horizon}

    def run_forever(self, interval_seconds: float, stop: threading.Event | None = None) -> None:
        stop = stop or threading.Event()
        logger.info("watching for incidents created at or after %s", self._start.isoformat())
        while not stop.is_set():
            self.poll_once()
            stop.wait(interval_seconds)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze new detection-engine incidents with the AI Copilot.")
    parser.add_argument(
        "--detection-engine-url",
        default=os.environ.get("DETECTION_ENGINE_URL", "http://localhost:8000"),
    )
    parser.add_argument("--interval", type=float, default=30.0, help="Seconds between polls (default 30).")
    parser.add_argument(
        "--since",
        type=datetime.fromisoformat,
        help="Also analyze incidents created at or after this ISO 8601 time (default: only ones created after startup).",
    )
    parser.add_argument("--once", action="store_true", help="Poll a single time and exit.")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(asctime)s %(levelname)s %(message)s")

    from providers.claude import ClaudeProvider

    worker = CopilotWorker(DetectionEngineClient(args.detection_engine_url), ClaudeProvider(), start_from=args.since)
    if args.once:
        worker.poll_once()
    else:
        worker.run_forever(args.interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())