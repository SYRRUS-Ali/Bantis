import pytest

from converter import SUMMARY_FIELDS_ALLOWLIST, MissingEvidenceError, build_copilot_request

_FAKE_SECRET = "AKIAFAKEBANTISATSIM1"


def _incident(correlated_event_ids=("dep-1", "sec-1")):
    return {
        "incident_id": "inc-1",
        "created_at": "2026-10-08T12:05:00",
        "pattern": "composite-dependency-secret",
        "window_seconds": 300,
        "correlated_event_ids": list(correlated_event_ids),
        "mitre_techniques": ["T1195.001", "T1552.001"],
        "severity": "high",
        "confidence": 0.6,
        "summary": "malicious-dependency + leaked-secret within 300s (0/2 succeeded)",
    }


def _event(event_id, timestamp, scenario, mitre, **extra_details):
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "level": "INFO",
        "logger": "attack_sim",
        "source": "attack-sim",
        "event_type": "attack_scenario_run",
        "message": f"{scenario} ran",
        "details": {"scenario": scenario, "status": "failure", "mitre_technique": mitre, **extra_details},
        "received_at": timestamp,
    }


def _dep_event(timestamp="2026-10-08T12:00:00"):
    return _event(
        "dep-1", timestamp, "malicious-dependency", "T1195.001",
        artifact="fake-package==0.0.0", tool_returncode=1, tool_output_tail="no matching distribution",
    )


def _sec_event(timestamp="2026-10-08T12:00:50"):
    event = _event(
        "sec-1", timestamp, "leaked-secret", "T1552.001",
        artifact="config.py", tool_returncode=1,
        tool_output_tail=f'Finding: AWS_ACCESS_KEY_ID = "{_FAKE_SECRET}"\nRuleID: aws-access-token',
    )
    event["message"] = f"MESSAGE-MARKER {_FAKE_SECRET} detected"
    return event


def test_builds_a_request_carrying_the_incident_unchanged():
    request = build_copilot_request(_incident(), [_dep_event(), _sec_event()])

    assert request.incident.incident_id == "inc-1"
    assert request.incident.pattern == "composite-dependency-secret"
    assert request.incident.correlated_event_ids == ["dep-1", "sec-1"]


def test_lifts_scenario_status_and_technique_to_the_top_level():
    request = build_copilot_request(_incident(), [_dep_event(), _sec_event()])
    entry = request.evidence_timeline[0]

    assert entry.scenario == "malicious-dependency"
    assert entry.status == "failure"
    assert entry.mitre_technique == "T1195.001"


def test_summary_fields_contain_only_allowlisted_keys():
    request = build_copilot_request(_incident(), [_dep_event(), _sec_event()])

    for entry in request.evidence_timeline:
        assert set(entry.summary_fields) <= SUMMARY_FIELDS_ALLOWLIST
    assert request.evidence_timeline[1].summary_fields == {"artifact": "config.py", "tool_returncode": 1}


def test_a_secret_in_tool_output_or_message_never_reaches_the_request():
    """docs/threat-model.md: never raw secrets or credentials to the AI
    provider. Checked against the exact string the provider would
    receive -- ClaudeProvider sends request.model_dump_json() verbatim.
    """
    request = build_copilot_request(_incident(), [_dep_event(), _sec_event()])
    serialized = request.model_dump_json()

    assert _FAKE_SECRET not in serialized
    assert "tool_output_tail" not in serialized
    assert "MESSAGE-MARKER" not in serialized  # the free-text `message` field isn't forwarded either


def test_an_unknown_details_field_is_dropped_not_forwarded():
    event = _dep_event()
    event["details"]["some_future_field"] = "anything"

    request = build_copilot_request(_incident(), [event, _sec_event()])

    assert "some_future_field" not in request.model_dump_json()


def test_timeline_is_ordered_by_timestamp_not_by_incident_order():
    incident = _incident(correlated_event_ids=("sec-1", "dep-1"))
    events = [_sec_event("2026-10-08T12:00:50"), _dep_event("2026-10-08T12:00:00")]

    request = build_copilot_request(incident, events)

    assert [entry.event_id for entry in request.evidence_timeline] == ["dep-1", "sec-1"]


def test_timestamp_ties_are_broken_by_event_id():
    same_time = "2026-10-08T12:00:00"
    incident = _incident(correlated_event_ids=("sec-1", "dep-1"))

    request = build_copilot_request(incident, [_sec_event(same_time), _dep_event(same_time)])

    assert [entry.event_id for entry in request.evidence_timeline] == ["dep-1", "sec-1"]


def test_naive_and_aware_timestamps_can_be_mixed():
    """detection-engine's SQLite backend returns naive timestamps; a
    caller could also pass aware ones. Without normalizing, sorting a
    mix raises TypeError.
    """
    events = [_dep_event("2026-10-08T12:00:00"), _sec_event("2026-10-08T12:00:50Z")]

    request = build_copilot_request(_incident(), events)

    assert [entry.event_id for entry in request.evidence_timeline] == ["dep-1", "sec-1"]
    assert all(entry.timestamp.tzinfo is not None for entry in request.evidence_timeline)


def test_incident_created_at_is_normalized_to_utc_like_the_timeline():
    """The model compares created_at against event timestamps to reason
    about timing -- both must carry the same timezone notation.
    """
    request = build_copilot_request(_incident(), [_dep_event(), _sec_event()])

    assert request.incident.created_at.tzinfo is not None
    assert '"created_at":"2026-10-08T12:05:00Z"' in request.model_dump_json()


def test_events_not_referenced_by_the_incident_are_ignored():
    unrelated = _event("other-1", "2026-10-08T12:00:10", "typosquatting", "T1195.001")

    request = build_copilot_request(_incident(), [_dep_event(), unrelated, _sec_event()])

    assert [entry.event_id for entry in request.evidence_timeline] == ["dep-1", "sec-1"]


def test_a_missing_correlated_event_raises_instead_of_sending_partial_evidence():
    with pytest.raises(MissingEvidenceError, match="sec-1"):
        build_copilot_request(_incident(), [_dep_event()])


def test_events_without_scenario_fields_still_convert():
    pull = {
        "event_id": "pull-1",
        "timestamp": "2026-10-08T12:00:00",
        "level": "INFO",
        "logger": "ci",
        "source": "ci",
        "event_type": "container_image_pull",
        "message": "pulled",
        "details": {"registry": "evil.example.com", "image": "evil.example.com/app:latest"},
        "received_at": "2026-10-08T12:00:00",
    }
    incident = dict(_incident(correlated_event_ids=("pull-1",)), pattern="untrusted-registry-pull")

    request = build_copilot_request(incident, [pull])
    entry = request.evidence_timeline[0]

    assert entry.scenario is None and entry.status is None
    assert entry.summary_fields == {"registry": "evil.example.com", "image": "evil.example.com/app:latest"}