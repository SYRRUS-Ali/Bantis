from datetime import datetime, timedelta, timezone

import pytest

from converter import as_utc_datetime
from detection_client import DetectionEngineError
from models import AnalysisTrace, AttemptRecord, CopilotResponse, ProposedAction
from providers.base import AIProvider
from worker import CopilotWorker

_START = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)


def _at(seconds: float) -> str:
    return (_START + timedelta(seconds=seconds)).replace(tzinfo=None).isoformat()


def _incident(incident_id: str, seconds: float, event_ids=("e1", "e2")) -> dict:
    return {
        "incident_id": incident_id,
        "created_at": _at(seconds),
        "pattern": "same-source-burst",
        "window_seconds": 60,
        "correlated_event_ids": list(event_ids),
        "mitre_techniques": ["T1195.001"],
        "severity": "medium",
        "confidence": 0.3,
        "summary": "test",
    }


def _event(event_id: str) -> dict:
    return {
        "event_id": event_id,
        "timestamp": _at(0),
        "level": "INFO",
        "logger": "attack_sim",
        "source": "attack-sim",
        "event_type": "attack_scenario_run",
        "message": "m",
        "details": {"scenario": "typosquatting", "status": "success", "mitre_technique": "T1195.001"},
        "received_at": _at(0),
    }


class FakeClient:
    def __init__(self, incidents=(), events=None):
        self.incidents = list(incidents)
        self.events = events if events is not None else {"e1": _event("e1"), "e2": _event("e2")}
        self.since_queries: list[datetime] = []
        self.fail_listing = False
        self.fail_events_for: set[str] = set()

    def list_incidents_since(self, since):
        self.since_queries.append(since)
        if self.fail_listing:
            raise DetectionEngineError("connection refused")
        return [i for i in self.incidents if as_utc_datetime(i["created_at"]) >= since]

    def get_incident_events(self, incident_id):
        if incident_id in self.fail_events_for:
            raise DetectionEngineError("timed out")
        incident = next(i for i in self.incidents if i["incident_id"] == incident_id)
        return [self.events[e] for e in incident["correlated_event_ids"] if e in self.events]


class FakeProvider(AIProvider):
    def __init__(self, raise_for: set[str] = frozenset()):
        self.analyzed: list[str] = []
        self.raise_for = raise_for

    def analyze_traced(self, request):
        incident_id = request.incident.incident_id
        self.analyzed.append(incident_id)
        if incident_id in self.raise_for:
            raise RuntimeError("provider bug")
        response = CopilotResponse(
            incident_id=incident_id,
            reasoning="fine",
            confidence=0.5,
            proposed_action=ProposedAction(type="flag_for_review", description="d"),
            model="fake",
            generated_at=_START,
        )
        return AnalysisTrace(
            response=response,
            attempts=[
                AttemptRecord(number=1, raw_output="not json", error="the response did not contain a JSON object"),
                AttemptRecord(number=2, raw_output='{"reasoning": "fine"}', input_tokens=120, output_tokens=40),
            ],
            system_prompt="fake system prompt",
        )


def _worker(client, provider=None, sink=None, **kwargs):
    delivered = []
    worker = CopilotWorker(
        client,
        provider or FakeProvider(),
        on_result=sink or (lambda incident, response: delivered.append((incident["incident_id"], response))),
        start_from=_START,
        **kwargs,
    )
    return worker, delivered


def test_a_new_incident_is_analyzed_and_delivered():
    client = FakeClient([_incident("inc-1", 5)])
    worker, delivered = _worker(client)

    results = worker.poll_once()

    assert [r.incident_id for r in results] == ["inc-1"]
    assert [incident_id for incident_id, _ in delivered] == ["inc-1"]


def test_incidents_are_analyzed_oldest_first():
    client = FakeClient([_incident("newer", 20), _incident("older", 10)])  # API returns newest first
    worker, delivered = _worker(client)

    worker.poll_once()

    assert [incident_id for incident_id, _ in delivered] == ["older", "newer"]


def test_an_incident_is_never_analyzed_twice_across_polls():
    client = FakeClient([_incident("inc-1", 5)])
    provider = FakeProvider()
    worker, _ = _worker(client, provider)

    worker.poll_once()
    worker.poll_once()
    worker.poll_once()

    assert provider.analyzed == ["inc-1"]


def test_incidents_created_before_the_worker_started_are_not_analyzed():
    client = FakeClient([_incident("old", -30), _incident("new", 5)])
    provider = FakeProvider()
    worker, _ = _worker(client, provider)

    worker.poll_once()

    assert provider.analyzed == ["new"]


def test_an_incident_committed_late_is_still_picked_up():
    client = FakeClient([_incident("b", 30)])
    provider = FakeProvider()
    worker, _ = _worker(client, provider)
    worker.poll_once()

    client.incidents.append(_incident("a", 20))  # older created_at, visible only now
    worker.poll_once()

    assert provider.analyzed == ["b", "a"]


def test_each_poll_queries_from_the_cursor_minus_the_lookback():
    client = FakeClient([_incident("inc-1", 100)])
    worker, _ = _worker(client, lookback_seconds=60)

    worker.poll_once()
    worker.poll_once()

    assert client.since_queries[0] == _START - timedelta(seconds=60)
    assert client.since_queries[1] == _START + timedelta(seconds=100) - timedelta(seconds=60)


def test_an_unreachable_detection_engine_doesnt_crash_and_recovers():
    client = FakeClient([_incident("inc-1", 5)])
    client.fail_listing = True
    worker, delivered = _worker(client)

    assert worker.poll_once() == []

    client.fail_listing = False
    worker.poll_once()
    assert [incident_id for incident_id, _ in delivered] == ["inc-1"]


def test_failing_to_fetch_events_retries_that_incident_next_poll():
    client = FakeClient([_incident("inc-1", 5), _incident("inc-2", 6)])
    client.fail_events_for = {"inc-1"}
    provider = FakeProvider()
    worker, _ = _worker(client, provider)

    worker.poll_once()
    assert provider.analyzed == ["inc-2"]

    client.fail_events_for = set()
    worker.poll_once()
    assert provider.analyzed == ["inc-2", "inc-1"]


def test_missing_evidence_records_analysis_failed_without_calling_the_provider():
    client = FakeClient([_incident("inc-1", 5, event_ids=("e1", "gone"))])
    provider = FakeProvider()
    worker, delivered = _worker(client, provider)

    worker.poll_once()

    assert provider.analyzed == []
    response = delivered[0][1]
    assert response.proposed_action.type == "analysis_failed"
    assert "gone" in response.reasoning


def test_an_unexpected_provider_error_is_recorded_and_the_worker_moves_on():
    client = FakeClient([_incident("bad", 5), _incident("good", 6)])
    provider = FakeProvider(raise_for={"bad"})
    worker, delivered = _worker(client, provider)

    worker.poll_once()
    worker.poll_once()

    assert [(i, r.proposed_action.type) for i, r in delivered] == [
        ("bad", "analysis_failed"),
        ("good", "flag_for_review"),
    ]
    assert provider.analyzed == ["bad", "good"]  # "bad" is not retried and re-billed every poll


def test_a_failing_sink_doesnt_lose_the_analysis_or_rerun_it(capsys):
    def broken_sink(incident, response):
        raise OSError("disk full")

    client = FakeClient([_incident("inc-1", 5)])
    provider = FakeProvider()
    worker, _ = _worker(client, provider, sink=broken_sink)

    worker.poll_once()
    worker.poll_once()

    assert provider.analyzed == ["inc-1"]
    assert '"incident_id":"inc-1"' in capsys.readouterr().err


def test_remembered_ids_are_pruned_once_outside_the_query_window():
    client = FakeClient([_incident(f"inc-{n}", n * 100) for n in range(1, 6)])
    worker, _ = _worker(client, lookback_seconds=60)

    worker.poll_once()

    # cursor is now at +500s; only ids within the last 60s can come back
    assert set(worker._processed) == {"inc-5"}


@pytest.mark.parametrize("bad_url", ["file:///etc/passwd", "ftp://host", "localhost:8000"])
def test_the_client_rejects_non_http_urls(bad_url):
    from detection_client import DetectionEngineClient

    with pytest.raises(ValueError, match="must be http or https"):
        DetectionEngineClient(bad_url)


def test_an_incident_waiting_on_a_retry_is_not_lost_when_the_outage_outlasts_the_lookback():
    client = FakeClient([_incident("inc-1", 5)])
    client.fail_events_for = {"inc-1"}
    provider = FakeProvider()
    worker, _ = _worker(client, provider, lookback_seconds=60)

    worker.poll_once()
    for n in range(2, 6):  # newer incidents, minutes later, keep succeeding
        client.incidents.append(_incident(f"inc-{n}", n * 300))
        worker.poll_once()

    client.fail_events_for = set()
    worker.poll_once()

    assert "inc-1" in provider.analyzed
    assert provider.analyzed.count("inc-1") == 1
    assert sorted(provider.analyzed) == sorted(["inc-1", "inc-2", "inc-3", "inc-4", "inc-5"])
    assert len(provider.analyzed) == 5  # nothing analyzed twice while the cursor was held

# ---- Decision log ------------------------------------------------------------


def _logged_worker(tmp_path, client, provider=None, **kwargs):
    from decision_log import DecisionLog

    log = DecisionLog(tmp_path / "decisions.db")
    worker, delivered = _worker(client, provider, decision_log=log, **kwargs)
    return worker, delivered, log


def test_every_analysis_is_recorded_with_its_full_trace(tmp_path):
    client = FakeClient([_incident("inc-1", 5)])
    worker, _, log = _logged_worker(tmp_path, client)

    worker.poll_once()

    [stored] = log.for_incident("inc-1")
    assert stored.record.outcome == "flag_for_review"
    assert stored.record.system_prompt == "fake system prompt"
    assert [a.error for a in stored.record.attempts] == ["the response did not contain a JSON object", None]
    assert stored.record.request.incident.incident_id == "inc-1"


def test_a_restarted_worker_never_reanalyzes_a_logged_incident(tmp_path):
    """The worker's in-memory set doesn't survive a restart; the decision
    log does. Even a --since backfill reaching back over an incident that
    was already analyzed must not pay for it again.
    """
    client = FakeClient([_incident("inc-1", 5)])
    first_provider = FakeProvider()
    first, _, _ = _logged_worker(tmp_path, client, first_provider)
    first.poll_once()

    second_provider = FakeProvider()
    second, delivered, log = _logged_worker(tmp_path, client, second_provider)
    second.poll_once()

    assert first_provider.analyzed == ["inc-1"]
    assert second_provider.analyzed == []
    assert delivered == []
    assert len(log.for_incident("inc-1")) == 1


def test_missing_evidence_is_recorded_without_a_provider_call(tmp_path):
    client = FakeClient([_incident("inc-1", 5, event_ids=("e1", "gone"))])
    provider = FakeProvider()
    worker, _, log = _logged_worker(tmp_path, client, provider)

    worker.poll_once()

    [stored] = log.for_incident("inc-1")
    assert provider.analyzed == []
    assert stored.record.outcome == "analysis_failed"
    assert stored.record.attempts == []
    assert stored.record.note == "evidence incomplete; not sent to the AI"


def test_a_failing_log_write_puts_the_record_on_stderr_and_doesnt_rerun(tmp_path, capsys):
    client = FakeClient([_incident("inc-1", 5)])
    provider = FakeProvider()
    worker, _, log = _logged_worker(tmp_path, client, provider)

    def broken_append(record):
        raise OSError("disk full")

    log.append = broken_append
    worker.poll_once()
    worker.poll_once()

    assert provider.analyzed == ["inc-1"]
    err = capsys.readouterr().err
    assert '"incident_id":"inc-1"' in err and '"attempts"' in err


def test_a_secret_in_the_stored_evidence_never_reaches_the_decision_log_file(tmp_path):
    """The log stores the allowlisted request -- what the provider saw --
    never detection-engine's raw events. Checked against the file's raw
    bytes, not a parsed view, so no field can hide it.
    """
    secret = "AKIAFAKEBANTISATSIM1"
    event = _event("e1")
    event["details"]["tool_output_tail"] = f"Secret: {secret}"
    event["message"] = f"found {secret}"
    client = FakeClient([_incident("inc-1", 5)], events={"e1": event, "e2": _event("e2")})
    worker, _, log = _logged_worker(tmp_path, client)

    worker.poll_once()

    [stored] = log.for_incident("inc-1")
    assert [e.event_id for e in stored.record.request.evidence_timeline] == ["e1", "e2"]
    raw = (tmp_path / "decisions.db").read_bytes()
    assert secret.encode() not in raw
    assert b"tool_output_tail" not in raw

# ---- Throttling --------------------------------------------------------------

def _policy(**overrides):
    from worker import ThrottlePolicy

    return ThrottlePolicy(**overrides)


def test_a_single_event_incident_is_skipped_and_recorded_not_sent(tmp_path):
    client = FakeClient([_incident("single", 5, event_ids=("e1",))])
    provider = FakeProvider()
    worker, delivered, log = _logged_worker(tmp_path, client, provider)

    worker.poll_once()
    worker.poll_once()

    assert provider.analyzed == []
    assert delivered == []
    [stored] = log.for_incident("single")
    assert stored.record.outcome == "skipped"
    assert stored.record.response is None
    assert "not correlated: 1 event(s)" in stored.record.note


def test_the_correlation_threshold_is_configurable(tmp_path):
    client = FakeClient([_incident("single", 5, event_ids=("e1",))])
    provider = FakeProvider()
    worker, _, _ = _logged_worker(tmp_path, client, provider, policy=_policy(min_correlated_events=1))

    worker.poll_once()

    assert provider.analyzed == ["single"]


def test_the_rate_limit_defers_rather_than_drops(tmp_path):
    client = FakeClient([_incident(f"inc-{n}", n) for n in range(1, 5)])
    provider = FakeProvider()
    worker, _, _ = _logged_worker(tmp_path, client, provider, policy=_policy(max_analyses_per_hour=2))

    worker.poll_once()
    worker.poll_once()
    assert len(provider.analyzed) == 2  # the limit holds across polls

    worker._policy = _policy(max_analyses_per_hour=None)  # budget frees up
    worker.poll_once()
    assert sorted(provider.analyzed) == ["inc-1", "inc-2", "inc-3", "inc-4"]  # nothing was lost


def test_the_rate_limit_is_shared_through_the_log_and_survives_a_restart(tmp_path):
    client = FakeClient([_incident(f"inc-{n}", n) for n in range(1, 5)])
    first_provider, second_provider = FakeProvider(), FakeProvider()
    first, _, _ = _logged_worker(tmp_path, client, first_provider, policy=_policy(max_analyses_per_hour=2))
    first.poll_once()

    second, _, _ = _logged_worker(tmp_path, client, second_provider, policy=_policy(max_analyses_per_hour=2))
    second.poll_once()

    assert len(first_provider.analyzed) == 2
    assert second_provider.analyzed == []


def test_only_real_model_calls_count_against_the_rate_limit(tmp_path):
    client = FakeClient(
        [
            _incident("single", 1, event_ids=("e1",)),  # skipped: no call
            _incident("missing", 2, event_ids=("e1", "gone")),  # missing evidence: no call
            _incident("real", 3),
        ]
    )
    provider = FakeProvider()
    worker, _, _ = _logged_worker(tmp_path, client, provider, policy=_policy(max_analyses_per_hour=1))

    worker.poll_once()

    assert provider.analyzed == ["real"]


def test_under_the_rate_limit_the_most_severe_incident_goes_first(tmp_path):
    flood = dict(_incident("flood", 1), severity="medium")
    critical = dict(_incident("critical", 9), severity="critical")
    client = FakeClient([flood, critical])
    provider = FakeProvider()
    worker, _, _ = _logged_worker(tmp_path, client, provider, policy=_policy(max_analyses_per_hour=1))

    worker.poll_once()

    assert provider.analyzed == ["critical"]


# ---- Duplicate calls ---------------------------------------------------------

def test_two_workers_never_both_pay_for_the_same_incident(tmp_path):
    import threading
    import time

    from decision_log import DecisionLog

    class SlowProvider(FakeProvider):
        def analyze_traced(self, request):
            time.sleep(0.3)
            return super().analyze_traced(request)

    path = tmp_path / "decisions.db"
    client = FakeClient([_incident("inc-1", 5)])
    providers = [SlowProvider() for _ in range(4)]
    workers = [
        CopilotWorker(client, p, on_result=lambda i, r: None, start_from=_START, decision_log=DecisionLog(path))
        for p in providers
    ]
    barrier = threading.Barrier(len(workers))

    def poll(worker):
        barrier.wait()
        worker.poll_once()

    threads = [threading.Thread(target=poll, args=(w,)) for w in workers]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sum(len(p.analyzed) for p in providers) == 1
    assert len(DecisionLog(path).for_incident("inc-1")) == 1

    for w in workers:
        w.poll_once()
    assert sum(len(p.analyzed) for p in providers) == 1

# ---- Daily token budget ------------------------------------------------------
# FakeProvider's trace costs 160 tokens per analysis (120 input + 40 output
# on its one billed attempt; the rejected first attempt has no usage).


def _budget(log, limit):
    from budget import TokenBudget

    return TokenBudget(limit, log)


def test_an_exhausted_budget_defers_incidents_rather_than_dropping_them(tmp_path):
    from decision_log import DecisionLog

    log = DecisionLog(tmp_path / "decisions.db")
    client = FakeClient([_incident(f"inc-{n}", n) for n in range(1, 5)])
    provider = FakeProvider()
    worker, _ = _worker(client, provider, decision_log=log, budget=_budget(log, 300))

    worker.poll_once()
    worker.poll_once()
    analyzed_under_budget = list(provider.analyzed)

    worker._budget = _budget(log, None)  # e.g. the next UTC day
    worker.poll_once()

    assert len(analyzed_under_budget) == 2
    assert sorted(provider.analyzed) == ["inc-1", "inc-2", "inc-3", "inc-4"]


def test_the_budget_can_be_overshot_by_at_most_one_analysis(tmp_path):
    from decision_log import DecisionLog

    log = DecisionLog(tmp_path / "decisions.db")
    client = FakeClient([_incident(f"inc-{n}", n) for n in range(1, 5)])
    worker, _ = _worker(client, FakeProvider(), decision_log=log, budget=_budget(log, 300))

    worker.poll_once()

    used = _budget(log, 300).status().used.total_tokens
    assert used == 320
    assert used - 300 < 160


def test_followup_spending_counts_against_the_worker_budget(tmp_path):
    from decision_log import DecisionLog, FollowupRecord

    log = DecisionLog(tmp_path / "decisions.db")
    log.append_followup(
        FollowupRecord(
            incident_id="other", question="q", answer="a", model="m",
            attempts=[AttemptRecord(number=1, raw_output="a", input_tokens=900, output_tokens=100)],
        )
    )
    provider = FakeProvider()
    worker, _ = _worker(FakeClient([_incident("inc-1", 5)]), provider, decision_log=log, budget=_budget(log, 1000))

    worker.poll_once()

    assert provider.analyzed == []


def test_running_out_of_budget_is_logged_with_the_reset_time(tmp_path, caplog):
    from decision_log import DecisionLog

    log = DecisionLog(tmp_path / "decisions.db")
    worker, _ = _worker(FakeClient([_incident("a", 1), _incident("b", 2)]), FakeProvider(), decision_log=log, budget=_budget(log, 100))

    worker.poll_once()

    [message] = [r.getMessage() for r in caplog.records if "token budget" in r.getMessage()]
    assert "daily token budget of 100 exhausted (160 used today); 1 incident(s) deferred until" in message