from datetime import datetime, timedelta, timezone

import pytest

from converter import as_utc_datetime
from detection_client import DetectionEngineError
from models import CopilotResponse, ProposedAction
from providers.base import AIProvider
from worker import CopilotWorker

_START = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)


def _at(seconds: float) -> str:
    return (_START + timedelta(seconds=seconds)).replace(tzinfo=None).isoformat()


def _incident(incident_id: str, seconds: float, event_ids=("e1",)) -> dict:
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
        self.events = events if events is not None else {"e1": _event("e1")}
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

    def analyze(self, request):
        incident_id = request.incident.incident_id
        self.analyzed.append(incident_id)
        if incident_id in self.raise_for:
            raise RuntimeError("provider bug")
        return CopilotResponse(
            incident_id=incident_id,
            reasoning="fine",
            confidence=0.5,
            proposed_action=ProposedAction(type="flag_for_review", description="d"),
            model="fake",
            generated_at=_START,
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