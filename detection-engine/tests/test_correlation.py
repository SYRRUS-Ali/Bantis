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