from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import socket
import threading
import uuid
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from budget import DEFAULT_MAX_TOKENS_PER_DAY, TokenBudget
from converter import MissingEvidenceError, as_utc_datetime, build_copilot_request
from decision_log import DEFAULT_PATH as DEFAULT_DECISION_LOG_PATH
from decision_log import DecisionLog, DecisionRecord, DuplicateDecisionError
from detection_client import DetectionEngineClient, DetectionEngineError
from models import CopilotResponse
from providers.base import AIProvider, ProviderUnavailableError

logger = logging.getLogger("ai_copilot.worker")

DEFAULT_LOOKBACK_SECONDS = 60
DEFAULT_PROVIDER_RETRY_SECONDS = 30.0
MAX_PROVIDER_RETRY_SECONDS = 600.0

ResultSink = Callable[[dict, CopilotResponse], None]
UnanalyzedSink = Callable[[dict, str], None]

_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}
_RATE_WINDOW = timedelta(hours=1)


@dataclass(frozen=True)
class ThrottlePolicy:
    min_correlated_events: int = 2
    max_analyses_per_hour: int | None = 30

    def skip_reason(self, incident: dict) -> str | None:
        count = len(incident.get("correlated_event_ids") or [])
        if count < self.min_correlated_events:
            return f"not correlated: {count} event(s), policy requires at least {self.min_correlated_events}"
        return None


def print_result(incident: dict, response: CopilotResponse) -> None:
    line = {"incident": incident, "analysis": json.loads(response.model_dump_json())}
    print(json.dumps(line), flush=True)


def print_unanalyzed(incident: dict, reason: str) -> None:
    line = {"incident": incident, "analysis": None, "analysis_pending": reason}
    print(json.dumps(line), flush=True)


class CopilotWorker:
    def __init__(
        self,
        client: DetectionEngineClient,
        provider: AIProvider,
        on_result: ResultSink = print_result,
        start_from: datetime | None = None,
        lookback_seconds: int = DEFAULT_LOOKBACK_SECONDS,
        decision_log: DecisionLog | None = None,
        policy: ThrottlePolicy | None = None,
        budget: TokenBudget | None = None,
        on_unanalyzed: UnanalyzedSink = print_unanalyzed,
        provider_retry_seconds: float = DEFAULT_PROVIDER_RETRY_SECONDS,
    ) -> None:
        self._client = client
        self._on_unanalyzed = on_unanalyzed
        self._provider_retry = timedelta(seconds=provider_retry_seconds)
        self._provider_backoff = timedelta(0)
        self._provider_down_until: datetime | None = None
        self._provider_down_reason = ""
        self._announced: dict[str, datetime] = {}
        self._decision_log = decision_log
        self._policy = policy or ThrottlePolicy()
        self._budget = budget or TokenBudget(decision_log=decision_log)
        self._owner = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
        self._recent_analyses: deque[datetime] = deque()
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
        pending.sort(
            key=lambda pair: (-_SEVERITY_RANK.get(pair[1].get("severity"), -1), pair[0], pair[1]["incident_id"])
        )

        results = []
        deferred: list[datetime] = []
        newest_done = self._cursor
        throttled = 0
        over_budget = 0
        unanalyzed = 0
        for created_at, incident in pending:
            incident_id = incident["incident_id"]
            if self._already_logged(incident_id):
                pass
            elif reason := self._policy.skip_reason(incident):
                self._record_skip(incident_id, reason)
            elif self._provider_down():
                unanalyzed += 1
                self._deliver_unanalyzed(incident, created_at)
                deferred.append(created_at)
                continue
            elif self._budget.status().exhausted:
                over_budget += 1
                deferred.append(created_at)
                continue
            elif not self._within_rate_limit():
                throttled += 1
                deferred.append(created_at)
                continue
            elif not self._claim(incident_id):
                deferred.append(created_at)
                continue
            else:
                try:
                    record = self._analyze(incident)
                except ProviderUnavailableError as exc:
                    self._release_claim(incident_id)
                    self._mark_provider_down(str(exc))
                    unanalyzed += 1
                    self._deliver_unanalyzed(incident, created_at)
                    deferred.append(created_at)
                    continue
                if record is None:
                    deferred.append(created_at)
                    continue
                self._mark_provider_up()
                self._record(incident, record)
                self._budget.record(record.attempts)
                if record.attempts:
                    self._recent_analyses.append(datetime.now(timezone.utc))
                if record.response is not None:
                    results.append(record.response)
            self._processed[incident_id] = created_at
            self._announced.pop(incident_id, None)
            newest_done = max(newest_done, created_at)

        if over_budget:
            status = self._budget.status()
            logger.warning(
                "daily token budget of %s exhausted (%s used today); %d incident(s) deferred until %s",
                f"{status.limit:,}",
                f"{status.used.total_tokens:,}",
                over_budget,
                status.resets_at.isoformat(),
            )
        if unanalyzed:
            logger.warning(
                "AI provider unavailable; %d incident(s) delivered without AI analysis, next try at %s",
                unanalyzed,
                self._provider_down_until.isoformat(),
            )
        if throttled:
            logger.warning(
                "rate limit of %s analyses/hour reached; %d incident(s) deferred to a later poll",
                self._policy.max_analyses_per_hour,
                throttled,
            )
        self._cursor = min([newest_done, *deferred])
        self._forget_ids_older_than(self._cursor - self._lookback)
        return results

    def _provider_down(self) -> bool:
        return self._provider_down_until is not None and datetime.now(timezone.utc) < self._provider_down_until

    def _mark_provider_down(self, reason: str) -> None:
        # Back off exponentially so a long outage costs one failed call per
        # interval, not one per incident per poll.
        self._provider_backoff = min(
            max(self._provider_backoff * 2, self._provider_retry), timedelta(seconds=MAX_PROVIDER_RETRY_SECONDS)
        )
        self._provider_down_until = datetime.now(timezone.utc) + self._provider_backoff
        self._provider_down_reason = reason
        logger.error(
            "AI provider unavailable (%s); incidents continue without AI analysis and are retried after %ds",
            reason,
            self._provider_backoff.total_seconds(),
        )

    def _mark_provider_up(self) -> None:
        if self._provider_down_until is not None:
            logger.info("AI provider reachable again; analyzing deferred incidents")
        self._provider_down_until = None
        self._provider_backoff = timedelta(0)

    def _deliver_unanalyzed(self, incident: dict, created_at: datetime) -> None:
        """Hand the incident on without an analysis, once, so an outage delays
        the AI's opinion but never the incident itself. It stays deferred and
        is analyzed (and delivered again, with the analysis) on recovery.
        """
        incident_id = incident["incident_id"]
        if incident_id in self._announced:
            return
        self._announced[incident_id] = created_at
        try:
            self._on_unanalyzed(incident, f"AI analysis unavailable: {self._provider_down_reason}")
        except Exception:
            logger.exception("unanalyzed sink failed for %s", incident_id)

    def _release_claim(self, incident_id: str) -> None:
        if self._decision_log is None:
            return
        try:
            self._decision_log.release_claim(incident_id, self._owner)
        except Exception:
            logger.exception("could not release the claim on %s; it expires with its lease", incident_id)

    def _within_rate_limit(self) -> bool:
        limit = self._policy.max_analyses_per_hour
        if limit is None:
            return True
        window_start = datetime.now(timezone.utc) - _RATE_WINDOW
        if self._decision_log is not None:
            return self._decision_log.count_analyses_since(window_start) < limit
        while self._recent_analyses and self._recent_analyses[0] < window_start:
            self._recent_analyses.popleft()
        return len(self._recent_analyses) < limit

    def _claim(self, incident_id: str) -> bool:
        if self._decision_log is None:
            return True
        return self._decision_log.try_claim(incident_id, self._owner)

    def _record_skip(self, incident_id: str, reason: str) -> None:
        logger.info("not sending %s to the AI: %s", incident_id, reason)
        if self._decision_log is None:
            return
        try:
            self._decision_log.append(DecisionRecord.skipped(incident_id, reason))
        except DuplicateDecisionError:
            pass
        except Exception:
            logger.exception("decision log write failed for skipped incident %s", incident_id)

    def _already_logged(self, incident_id: str) -> bool:
        return self._decision_log is not None and self._decision_log.has_incident(incident_id)

    def _analyze(self, incident: dict) -> DecisionRecord | None:
        incident_id = incident["incident_id"]
        try:
            events = self._client.get_incident_events(incident_id)
        except DetectionEngineError as exc:
            logger.warning("could not fetch events for %s, will retry next poll: %s", incident_id, exc)
            return None

        request = None
        try:
            request = build_copilot_request(incident, events)
            return DecisionRecord.from_trace(incident_id, request, self._provider.analyze_traced(request))
        except ProviderUnavailableError:
            raise
        except MissingEvidenceError as exc:
            response = CopilotResponse.analysis_failed(incident_id, "none (not sent to a provider)", str(exc))
            return DecisionRecord.without_provider_call(incident_id, None, response, "evidence incomplete; not sent to the AI")
        except Exception as exc:
            logger.exception("unexpected error analyzing %s", incident_id)
            response = CopilotResponse.analysis_failed(incident_id, "none (worker error)", f"{type(exc).__name__}: {exc}")
            return DecisionRecord.without_provider_call(incident_id, request, response, "worker error during analysis")

    def _record(self, incident: dict, record: DecisionRecord) -> None:
        if self._decision_log is not None:
            try:
                self._decision_log.append(record)
            except DuplicateDecisionError:
                # Claims should make this unreachable; if it happens, a
                # second paid call already did, so say so loudly.
                logger.error("duplicate analysis of %s: a decision was already recorded; record follows", record.incident_id)
                print(record.model_dump_json(), file=sys.stderr, flush=True)
            except Exception:
                logger.exception("decision log write failed for %s; record follows", record.incident_id)
                print(record.model_dump_json(), file=sys.stderr, flush=True)
        try:
            self._on_result(incident, record.response)
        except Exception:
            logger.exception("result sink failed for %s; analysis follows", incident["incident_id"])
            print(record.response.model_dump_json(), file=sys.stderr, flush=True)

    def _forget_ids_older_than(self, horizon: datetime) -> None:
        self._processed = {i: t for i, t in self._processed.items() if t >= horizon}
        self._announced = {i: t for i, t in self._announced.items() if t >= horizon}

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
    parser.add_argument(
        "--min-correlated-events",
        type=int,
        default=ThrottlePolicy.min_correlated_events,
        help="Skip incidents built from fewer events than this (default 2; 1 sends every incident).",
    )
    parser.add_argument(
        "--max-analyses-per-hour",
        type=int,
        default=ThrottlePolicy.max_analyses_per_hour,
        help="Incidents sent to the model per rolling hour, across every worker sharing the log (default 30).",
    )
    parser.add_argument("--no-rate-limit", action="store_true", help="Disable the hourly limit.")
    parser.add_argument(
        "--max-tokens-per-day",
        type=int,
        default=DEFAULT_MAX_TOKENS_PER_DAY,
        help="Daily token budget per UTC day, shared with the follow-up API through the decision log (default 500,000).",
    )
    parser.add_argument("--no-token-budget", action="store_true", help="Disable the daily token budget.")
    parser.add_argument(
        "--decision-log",
        default=DEFAULT_DECISION_LOG_PATH,
        help="SQLite file every analysis is recorded in (default: ai-copilot/decision_log.db, or $BANTIS_DECISION_LOG).",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(asctime)s %(levelname)s %(message)s")

    from providers.claude import from_environment

    provider = from_environment()
    if reason := getattr(provider, "reason", None):
        logger.error("AI provider not configured (%s): incidents will be delivered without AI analysis", reason)
    decision_log = DecisionLog(args.decision_log)
    worker = CopilotWorker(
        DetectionEngineClient(args.detection_engine_url),
        provider,
        start_from=args.since,
        decision_log=decision_log,
        budget=TokenBudget(None if args.no_token_budget else args.max_tokens_per_day, decision_log),
        policy=ThrottlePolicy(
            min_correlated_events=args.min_correlated_events,
            max_analyses_per_hour=None if args.no_rate_limit else args.max_analyses_per_hour,
        ),
    )
    if args.once:
        worker.poll_once()
    else:
        worker.run_forever(args.interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())