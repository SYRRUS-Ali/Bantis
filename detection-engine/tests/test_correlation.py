from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.orm import Session

from app.correlation import COMPOSITE_WINDOW_SECONDS, SAME_SOURCE_WINDOW_SECONDS, correlate, run_correlation
from app.event_models import EventORM

_T0 = datetime(2026, 9, 25, 12, 0, 0, tzinfo=timezone.utc)


def _event(event_id, source, event_type, seconds_after_t0=0, scenario=None, status="success", mitre="T1195.001"):
    details = {"status": status, "mitre_technique": mitre}
    if scenario is not None:
        details["scenario"] = scenario
    return EventORM(
        event_id=event_id,
        timestamp=_T0 + timedelta(seconds=seconds_after_t0),
        level="INFO",
        logger="attack_sim",
        source=source,
        event_type=event_type,
        message="test event",
        details=details,
    )


def _image_pull_event(event_id, seconds_after_t0=0, registry="docker.io", image="library/python:3.12-slim"):
    details = {"image": image}
    if registry is not None:
        details["registry"] = registry
    return EventORM(
        event_id=event_id,
        timestamp=_T0 + timedelta(seconds=seconds_after_t0),
        level="INFO",
        logger="ci",
        source="ci",
        event_type="container_image_pull",
        message="test event",
        details=details,
    )


def _http_event(event_id, source, seconds_after_t0=0, status_code=200):
    return EventORM(
        event_id=event_id,
        timestamp=_T0 + timedelta(seconds=seconds_after_t0),
        level="INFO",
        logger=f"{source}.access",
        source=source,
        event_type="http_request",
        message="request handled",
        details={"method": "GET", "path": "/health", "status_code": status_code},
    )


# ---- Pattern 1: same-source burst -----------------------------------------


def test_two_same_source_events_within_the_window_form_one_incident():
    events = [
        _event("e1", "attack-sim", "attack_scenario_run", 0),
        _event("e2", "attack-sim", "attack_scenario_run", 30),
    ]

    incidents = correlate(events)

    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.pattern == "same-source-burst"
    assert incident.window_seconds == SAME_SOURCE_WINDOW_SECONDS
    assert incident.correlated_event_ids == ["e1", "e2"]


def test_same_source_events_outside_the_window_form_no_incident():
    events = [
        _event("e1", "attack-sim", "attack_scenario_run", 0),
        _event("e2", "attack-sim", "attack_scenario_run", SAME_SOURCE_WINDOW_SECONDS + 1),
    ]

    incidents = correlate(events)

    assert incidents == []


def test_a_single_isolated_event_produces_no_incident():
    events = [_event("only", "attack-sim", "attack_scenario_run", 0)]

    incidents = correlate(events)

    assert incidents == []


def test_events_from_different_sources_do_not_cluster_even_if_close_in_time():
    events = [
        _event("e1", "api", "http_request", 0),
        _event("e2", "attack-sim", "attack_scenario_run", 1),
    ]

    incidents = correlate(events)

    assert incidents == []


def test_same_source_incident_escalates_severity_and_confidence_on_success():
    all_failed = [
        _event("e1", "attack-sim", "attack_scenario_run", 0, status="failure"),
        _event("e2", "attack-sim", "attack_scenario_run", 10, status="failure"),
    ]
    one_succeeded = [
        _event("e3", "attack-sim", "attack_scenario_run", 0, status="success"),
        _event("e4", "attack-sim", "attack_scenario_run", 10, status="failure"),
    ]

    failed_incident = correlate(all_failed)[0]
    success_incident = correlate(one_succeeded)[0]

    assert failed_incident.severity == "medium"
    assert failed_incident.confidence == 0.3
    assert success_incident.severity == "high"
    assert success_incident.confidence == 0.5


def test_same_source_confidence_stays_capped_with_more_than_one_success_in_a_larger_burst():
    events = [
        _event("e1", "attack-sim", "attack_scenario_run", 0, status="success"),
        _event("e2", "attack-sim", "attack_scenario_run", 10, status="success"),
        _event("e3", "attack-sim", "attack_scenario_run", 20, status="failure"),
    ]

    incident = correlate(events)[0]

    assert incident.severity == "high"
    assert incident.confidence == 0.5


def test_mitre_techniques_are_not_deduplicated():
    events = [
        _event("e1", "attack-sim", "attack_scenario_run", 0, mitre="T1195.001"),
        _event("e2", "attack-sim", "attack_scenario_run", 10, mitre="T1195.001"),
    ]

    incident = correlate(events)[0]

    assert incident.mitre_techniques == ["T1195.001", "T1195.001"]


# ---- False positives: ordinary traffic is not a same-source burst ----------


def test_ordinary_api_traffic_bursts_never_form_a_same_source_incident():
    events = [
        _http_event("r1", "api", 0),
        _http_event("r2", "api", 5),
        _http_event("r3", "api", 10),
    ]

    incidents = correlate(events)

    assert incidents == []


def test_ordinary_nginx_traffic_bursts_never_form_a_same_source_incident():
    events = [
        _http_event("r1", "nginx", 0),
        _http_event("r2", "nginx", 5),
    ]

    incidents = correlate(events)

    assert incidents == []


def test_attack_scenario_bursts_still_form_incidents_after_excluding_http_request():
    events = [
        _event("e1", "attack-sim", "attack_scenario_run", 0),
        _event("e2", "attack-sim", "attack_scenario_run", 10),
    ]

    incidents = correlate(events)

    assert len(incidents) == 1
    assert incidents[0].pattern == "same-source-burst"


# ---- Pattern 2: composite dependency+secret --------------------------------


def test_dependency_and_secret_within_the_composite_window_form_an_incident():
    events = [
        _event("dep", "attack-sim", "attack_scenario_run", 0, scenario="malicious-dependency"),
        _event("sec", "attack-sim", "attack_scenario_run", 200, scenario="leaked-secret"),
    ]

    incidents = correlate(events)

    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.pattern == "composite-dependency-secret"
    assert incident.window_seconds == COMPOSITE_WINDOW_SECONDS
    assert set(incident.correlated_event_ids) == {"dep", "sec"}


def test_dependency_and_secret_outside_the_composite_window_form_no_incident():
    events = [
        _event("dep", "attack-sim", "attack_scenario_run", 0, scenario="malicious-dependency"),
        _event("sec", "attack-sim", "attack_scenario_run", COMPOSITE_WINDOW_SECONDS + 1, scenario="leaked-secret"),
    ]

    incidents = correlate(events)

    assert incidents == []


def test_composite_severity_escalates_to_critical_when_both_succeed():
    both_succeeded = [
        _event("dep", "attack-sim", "attack_scenario_run", 0, scenario="malicious-dependency", status="success"),
        _event("sec", "attack-sim", "attack_scenario_run", 50, scenario="leaked-secret", status="success"),
    ]
    only_one_succeeded = [
        _event("dep2", "attack-sim", "attack_scenario_run", 0, scenario="malicious-dependency", status="success"),
        _event("sec2", "attack-sim", "attack_scenario_run", 50, scenario="leaked-secret", status="failure"),
    ]

    critical_incident = correlate(both_succeeded)[0]
    high_incident = correlate(only_one_succeeded)[0]

    assert critical_incident.severity == "critical"
    assert critical_incident.confidence == 0.9
    assert high_incident.severity == "high"
    assert high_incident.confidence == 0.75


def test_a_composite_pair_is_not_also_reported_as_a_same_source_burst():
    events = [
        _event("dep", "attack-sim", "attack_scenario_run", 0, scenario="malicious-dependency"),
        _event("sec", "attack-sim", "attack_scenario_run", 40, scenario="leaked-secret"),
    ]

    incidents = correlate(events)

    assert len(incidents) == 1
    assert incidents[0].pattern == "composite-dependency-secret"


def test_unrelated_scenario_types_never_form_a_composite_incident():
    events = [
        _event("a", "attack-sim", "attack_scenario_run", 0, scenario="compromised-ci-step"),
        _event("b", "attack-sim", "attack_scenario_run", 10, scenario="typosquatting"),
    ]

    incidents = correlate(events)

    assert len(incidents) == 1
    assert incidents[0].pattern == "same-source-burst"


# ---- Event ordering: deterministic under timestamp ties --------------------


def test_composite_pairing_is_deterministic_when_two_candidates_tie_on_timestamp():
    dep_a = _event("dep-a", "attack-sim", "attack_scenario_run", 0, scenario="malicious-dependency")
    dep_b = _event("dep-b", "attack-sim", "attack_scenario_run", 0, scenario="malicious-dependency")
    secret = _event("secret", "attack-sim", "attack_scenario_run", 50, scenario="leaked-secret")

    forward = correlate([dep_a, dep_b, secret])
    reversed_input = correlate([dep_b, dep_a, secret])

    assert len(forward) == 1 and len(reversed_input) == 1
    assert sorted(forward[0].correlated_event_ids) == sorted(reversed_input[0].correlated_event_ids)
    # dep-a sorts before dep-b, so it's the deterministic winner either way
    assert "dep-a" in forward[0].correlated_event_ids
    assert "dep-a" in reversed_input[0].correlated_event_ids


def test_same_source_cluster_order_is_deterministic_when_timestamps_tie():
    e_a = _event("a-event", "attack-sim", "attack_scenario_run", 0)
    e_b = _event("b-event", "attack-sim", "attack_scenario_run", 0)

    forward = correlate([e_a, e_b])
    reversed_input = correlate([e_b, e_a])

    assert forward[0].correlated_event_ids == reversed_input[0].correlated_event_ids == ["a-event", "b-event"]


# ---- Pattern 3: untrusted registry pull ------------------------------------


def test_a_pull_from_an_untrusted_registry_forms_its_own_incident():
    events = [_image_pull_event("pull1", registry="evil-registry.example.com")]

    incidents = correlate(events)

    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.pattern == "untrusted-registry-pull"
    assert incident.window_seconds == 0
    assert incident.correlated_event_ids == ["pull1"]
    assert incident.severity == "high"
    assert incident.confidence == 0.7


def test_a_pull_from_a_trusted_registry_forms_no_incident():
    events = [_image_pull_event("pull1", registry="docker.io")]

    incidents = correlate(events)

    assert incidents == []


def test_a_pull_from_the_other_trusted_registry_forms_no_incident():
    events = [_image_pull_event("pull1", registry="ghcr.io")]

    incidents = correlate(events)

    assert incidents == []


def test_a_pull_with_no_registry_field_is_treated_as_untrusted():
    events = [_image_pull_event("pull1", registry=None)]

    incidents = correlate(events)

    assert len(incidents) == 1
    assert incidents[0].pattern == "untrusted-registry-pull"


def test_two_untrusted_registry_pulls_form_two_separate_incidents():
    events = [
        _image_pull_event("pull1", 0, registry="evil-registry.example.com"),
        _image_pull_event("pull2", 10, registry="another-bad-registry.example.com"),
    ]

    incidents = correlate(events)

    assert len(incidents) == 2
    assert {incident.pattern for incident in incidents} == {"untrusted-registry-pull"}
    assert {tuple(incident.correlated_event_ids) for incident in incidents} == {("pull1",), ("pull2",)}


def test_an_untrusted_registry_pull_is_not_also_reported_as_a_same_source_burst():
    events = [
        _image_pull_event("pull1", 0, registry="evil-registry.example.com"),
        _event("e2", "ci", "attack_scenario_run", 10),
    ]

    incidents = correlate(events)

    assert len(incidents) == 1
    assert incidents[0].pattern == "untrusted-registry-pull"
    assert incidents[0].correlated_event_ids == ["pull1"]


# ---- Malformed data: an ERROR-status event is not a real attack signal ----


def test_an_error_status_event_is_never_part_of_a_composite_incident():

    events = [
        _event("dep", "attack-sim", "attack_scenario_run", 0, scenario="malicious-dependency", status="failure"),
        _event("sec", "attack-sim", "attack_scenario_run", 50, scenario="leaked-secret", status="error"),
    ]

    incidents = correlate(events)

    assert incidents == []


def test_an_error_status_event_is_never_part_of_a_same_source_burst():
    events = [
        _event("e1", "attack-sim", "attack_scenario_run", 0, status="failure"),
        _event("e2", "attack-sim", "attack_scenario_run", 10, status="error"),
    ]

    incidents = correlate(events)

    assert incidents == []


def test_two_error_status_events_form_no_incident_at_all():
    events = [
        _event("e1", "attack-sim", "attack_scenario_run", 0, status="error"),
        _event("e2", "attack-sim", "attack_scenario_run", 10, status="error"),
    ]

    incidents = correlate(events)

    assert incidents == []


# ---- run_correlation(): wired to a real database ---------------------------


@pytest.fixture
def db_session(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")

    from app.db import Base, SessionLocal, engine

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    session = SessionLocal()
    yield session
    session.close()


def test_run_correlation_persists_new_incidents(db_session):
    db_session.add(_event("e1", "attack-sim", "attack_scenario_run", 0))
    db_session.add(_event("e2", "attack-sim", "attack_scenario_run", 30))
    db_session.commit()

    incidents = run_correlation(db_session)

    assert len(incidents) == 1
    from app.incident_models import IncidentORM

    stored = db_session.query(IncidentORM).all()
    assert len(stored) == 1
    assert stored[0].incident_id == incidents[0].incident_id


def test_run_correlation_stores_every_incident_field_completely(db_session):
    db_session.add(
        _event("dep", "attack-sim", "attack_scenario_run", 0, scenario="malicious-dependency", status="success")
    )
    db_session.add(
        _event("sec", "attack-sim", "attack_scenario_run", 50, scenario="leaked-secret", status="success")
    )
    db_session.commit()

    incidents = run_correlation(db_session)
    assert len(incidents) == 1
    created = incidents[0]

    from app.db import engine
    from app.incident_models import IncidentORM

    with Session(engine) as fresh_session:
        stored = fresh_session.get(IncidentORM, created.incident_id)

        assert stored is not None
        assert stored.pattern == created.pattern == "composite-dependency-secret"
        assert stored.window_seconds == created.window_seconds == COMPOSITE_WINDOW_SECONDS
        assert stored.correlated_event_ids == created.correlated_event_ids == ["dep", "sec"]
        assert stored.mitre_techniques == created.mitre_techniques
        assert stored.severity == created.severity == "critical"
        assert stored.confidence == created.confidence == 0.9
        assert stored.summary == created.summary
        assert stored.created_at is not None


def test_run_correlation_does_not_reprocess_already_correlated_events(db_session):
    db_session.add(_event("e1", "attack-sim", "attack_scenario_run", 0))
    db_session.add(_event("e2", "attack-sim", "attack_scenario_run", 30))
    db_session.commit()

    first_run = run_correlation(db_session)
    second_run = run_correlation(db_session)

    assert len(first_run) == 1
    assert second_run == []

    from app.incident_models import IncidentORM

    assert db_session.query(IncidentORM).count() == 1

def test_run_correlation_records_a_claim_for_every_correlated_event(db_session):
    from app.incident_models import IncidentEventClaimORM

    db_session.add(_event("e1", "attack-sim", "attack_scenario_run", 0))
    db_session.add(_event("e2", "attack-sim", "attack_scenario_run", 30))
    db_session.commit()

    [incident] = run_correlation(db_session)

    claims = {c.event_id: c.incident_id for c in db_session.query(IncidentEventClaimORM).all()}
    assert claims == {"e1": incident.incident_id, "e2": incident.incident_id}


def test_an_event_already_claimed_is_never_correlated_again(db_session):
    from app.incident_models import IncidentEventClaimORM

    db_session.add(_event("e1", "attack-sim", "attack_scenario_run", 0))
    db_session.add(_event("e2", "attack-sim", "attack_scenario_run", 30))
    db_session.add(IncidentEventClaimORM(event_id="e1", incident_id="claimed-elsewhere"))
    db_session.commit()

    assert run_correlation(db_session) == []

# ---- Scheduled (incremental) correlation ---------------------------------------
#
# A scheduled pass runs while events are still arriving, so it can't treat
# what it sees as complete the way a one-off batch run can. Each event here
# arrives (received_at) when it happens.


def _arrived(event):
    event.received_at = event.timestamp
    return event


def _at(seconds):
    return _T0 + timedelta(seconds=seconds)


def _pass(events, seconds, already=()):
    """One scheduled pass at T0+seconds over the events that have arrived and
    aren't already in an incident."""
    taken = {e for incident in already for e in incident.correlated_event_ids}
    visible = [e for e in events if e.received_at <= _at(seconds) and e.event_id not in taken]
    return correlate(visible, now=_at(seconds))


def test_a_pass_mid_attack_does_not_hand_half_a_composite_to_a_burst():
    """Batch correlation finds composites first, but a pass that runs before
    the secret arrives would let the burst rule take the dependency event --
    and the composite could then never form.
    """
    events = [
        _arrived(_event("ci", "attack-sim", "attack_scenario_run", 0, scenario="compromised-ci-step")),
        _arrived(_event("dep", "attack-sim", "attack_scenario_run", 10, scenario="malicious-dependency")),
        _arrived(_event("sec", "attack-sim", "attack_scenario_run", 40, scenario="leaked-secret")),
    ]

    first = _pass(events, 20)
    second = _pass(events, 50, already=first)

    assert first == []
    assert [(i.pattern, sorted(i.correlated_event_ids)) for i in second] == [
        ("composite-dependency-secret", ["dep", "sec"])
    ]


def test_a_pass_mid_burst_does_not_split_it():
    events = [
        _arrived(_event("a", "attack-sim", "attack_scenario_run", 0, scenario="typosquatting")),
        _arrived(_event("b", "attack-sim", "attack_scenario_run", 10, scenario="compromised-ci-step")),
        _arrived(_event("c", "attack-sim", "attack_scenario_run", 40, scenario="typosquatting")),
    ]

    first = _pass(events, 20)
    second = _pass(events, 40 + SAME_SOURCE_WINDOW_SECONDS + 1, already=first)

    assert first == []
    assert [sorted(i.correlated_event_ids) for i in second] == [["a", "b", "c"]]


def test_a_composite_candidate_without_a_partner_joins_a_burst_once_its_window_closes():
    events = [
        _arrived(_event("dep", "attack-sim", "attack_scenario_run", 0, scenario="malicious-dependency")),
        _arrived(_event("typo", "attack-sim", "attack_scenario_run", 10, scenario="typosquatting")),
    ]

    assert _pass(events, 100) == []
    later = _pass(events, COMPOSITE_WINDOW_SECONDS + 1)
    assert [(i.pattern, sorted(i.correlated_event_ids)) for i in later] == [("same-source-burst", ["dep", "typo"])]


def test_a_burst_that_keeps_growing_is_still_reported():
    """Without a cap, a source sending an event every 50s would hold its own
    burst open -- and out of the incident list -- indefinitely.
    """
    from app.correlation import MAX_HOLD_SECONDS

    events = [
        _arrived(_event(f"e{n}", "attack-sim", "attack_scenario_run", n * 50, scenario="typosquatting"))
        for n in range(MAX_HOLD_SECONDS // 50 + 2)
    ]

    incidents = _pass(events, events[-1].timestamp.timestamp() - _T0.timestamp())

    assert len(incidents) == 1 and len(incidents[0].correlated_event_ids) == len(events)


def test_untrusted_registry_pulls_are_reported_without_waiting():
    events = [_arrived(_image_pull_event("pull", 0, registry="evil.example"))]

    assert [i.pattern for i in _pass(events, 1)] == ["untrusted-registry-pull"]


def test_without_a_time_a_pass_is_a_complete_batch_as_before():
    events = [
        _arrived(_event("a", "attack-sim", "attack_scenario_run", 0, scenario="typosquatting")),
        _arrived(_event("b", "attack-sim", "attack_scenario_run", 10, scenario="compromised-ci-step")),
    ]

    assert [sorted(i.correlated_event_ids) for i in correlate(events)] == [["a", "b"]]


def test_a_sender_claiming_future_timestamps_cannot_hold_its_burst_back():
    """POST /events is unauthenticated and timestamp is the sender's claim;
    waiting is measured on received_at, which this server sets.
    """
    events = []
    for n, event_id in enumerate(["a", "b"]):
        event = _event(event_id, "attack-sim", "attack_scenario_run", 3600 + n * 10, scenario="typosquatting")
        event.received_at = _at(n * 10)
        events.append(event)

    incidents = correlate(events, now=_at(10 + SAME_SOURCE_WINDOW_SECONDS))

    assert [sorted(i.correlated_event_ids) for i in incidents] == [["a", "b"]]