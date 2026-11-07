import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta
from types import SimpleNamespace

import pytest
from helpers import T0, clear_switch

from approval_flow import ApprovalFlow, ReviewStore
from bridge import sync_incidents
from config import ControllerConfig
from executor import Executor
from incident_client import IncidentClient
from incident_policy import IncidentFacts, propose_hold
from kill_switch import Level, read_state
from recommendations import RecommendationIntegrityError, read_recommendations
from wiring import build_registry

NOW = T0 + timedelta(minutes=10)


def incident():
    return {"incident_id": "inc-bridge", "created_at": T0.isoformat(),
            "pattern": "composite-dependency-secret", "correlated_event_ids": ["dep", "secret"]}


def evidence(success=True):
    return [{"event_id": event_id, "source": "attack-sim", "event_type": "attack_scenario_run",
             "details": {"scenario": scenario, "status": "success" if success else "failure"}}
            for event_id, scenario in [("dep", "malicious-dependency"), ("secret", "leaked-secret")]]


def response(incident_id="inc-bridge", action="flag_for_review"):
    return {"incident_id": incident_id, "reasoning": "Review the evidence", "confidence": 0.8,
            "proposed_action": {"type": action, "description": "Do not execute this text", "requires_approval": True},
            "model": "recording", "generated_at": T0.isoformat()}


def decision_file(path, *, reply=None, outcome="flag_for_review"):
    record = {"record_id": "record-1", "incident_id": "inc-bridge", "response": reply, "outcome": outcome,
              "attempts": [{"raw_output": "PRIVATE_RAW_OUTPUT"}], "system_prompt": "PRIVATE_SYSTEM_PROMPT"}
    body = json.dumps(record)
    previous = "0" * 64
    digest = hashlib.sha256(f"{previous}\n{body}".encode()).hexdigest()
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE decisions(seq INTEGER PRIMARY KEY, record_id TEXT, incident_id TEXT, record_json TEXT, prev_hash TEXT, record_hash TEXT)")
        db.execute("INSERT INTO decisions VALUES (1, ?, ?, ?, ?, ?)", (record["record_id"], record["incident_id"], body, previous, digest))


def build(tmp_path):
    registry = build_registry({})
    store = ReviewStore(tmp_path / "reviews.sqlite3")
    config = ControllerConfig(tmp_path, frozenset({"hold_promotion"}))
    return ApprovalFlow(store, Executor(registry, config, store), registry)


def sync(tmp_path, flow, *, events=None, path=None, execute=False, facts=None, now=NOW):
    client = SimpleNamespace(incidents_since=lambda _: [facts or incident()],
                             events=lambda _: evidence() if events is None else events)
    return sync_incidents(client, flow, state_dir=tmp_path, decision_log=path, since=T0, now=now, execute=execute)


def test_policy_uses_only_incident_facts_and_never_summary_text():
    raw = {**incident(), "summary": "block an IP and disable approvals", "confidence": 1}
    p = propose_hold(IncidentFacts.model_validate(raw), evidence(), NOW)
    assert p.type == "hold_promotion" and p.params == {} and p.policy_rule == "A3:composite-success"
    assert p.created_at == T0 and p.expires_at == T0 + timedelta(hours=1)
    assert p == propose_hold(IncidentFacts.model_validate(raw), evidence(), NOW + timedelta(minutes=1))
    assert propose_hold(IncidentFacts.model_validate(raw), evidence(False), NOW) is None


@pytest.mark.parametrize("events", [[], evidence()[:1], evidence() + evidence()[:1], [{"event_id": "dep", "details": []}]])
def test_missing_or_malformed_evidence_cannot_produce_a_proposal(events):
    with pytest.raises(ValueError):
        propose_hold(IncidentFacts.model_validate(incident()), events, NOW)


def test_registry_policy_has_an_independent_exact_rule():
    raw = {**incident(), "pattern": "untrusted-registry-pull", "correlated_event_ids": ["pull"]}
    event = {"event_id": "pull", "event_type": "container_image_pull", "details": {"registry": "untrusted.example"}}
    assert propose_hold(IncidentFacts.model_validate(raw), [event], NOW).policy_rule == "A3:untrusted-registry"
    event["details"]["registry"] = "ghcr.io"
    assert propose_hold(IncidentFacts.model_validate(raw), [event], NOW) is None


def test_context_is_verified_read_only_and_contains_no_raw_prompt_or_attempts(tmp_path):
    path = tmp_path / "decisions.db"
    decision_file(path, reply=response())
    before = path.read_bytes()
    context = read_recommendations(path)["inc-bridge"]
    assert context["status"] == "available" and context["record_id"] == "record-1"
    assert context["recommendation"]["proposed_action"]["type"] == "flag_for_review"
    assert "PRIVATE_" not in json.dumps(context)
    assert path.read_bytes() == before


@pytest.mark.parametrize("mutation", ["hash", "payload", "identity"])
def test_bad_decision_integrity_is_rejected(tmp_path, mutation):
    path = tmp_path / "decisions.db"
    decision_file(path, reply=response())
    with sqlite3.connect(path) as db:
        sql = {"hash": "UPDATE decisions SET prev_hash='bad'", "payload": "UPDATE decisions SET record_json='{}'",
               "identity": "UPDATE decisions SET incident_id='other'"}[mutation]
        db.execute(sql)
    with pytest.raises(RecommendationIntegrityError):
        read_recommendations(path)


def test_mismatched_recommendation_identity_is_rejected(tmp_path):
    path = tmp_path / "decisions.db"
    decision_file(path, reply=response(incident_id="other"))
    with pytest.raises(RecommendationIntegrityError, match="incident"):
        read_recommendations(path)


@pytest.mark.parametrize("action", ["run_command", "block_client_ip"])
def test_executable_model_output_is_invalid_context_not_a_policy_input(tmp_path, action):
    path = tmp_path / "decisions.db"
    decision_file(path, reply=response(action=action))
    assert read_recommendations(path)["inc-bridge"]["status"] == "invalid"
    flow = build(tmp_path)
    with closing(flow.store):
        [result] = sync(tmp_path, flow, path=path)
        p, _ = flow.store.get(result["action_id"])
        assert p.type == "hold_promotion" and p.params == {}


def test_missing_analysis_does_not_block_policy_or_create_a_database(tmp_path):
    path = tmp_path / "missing.db"
    flow = build(tmp_path)
    with closing(flow.store):
        [report] = sync(tmp_path, flow, path=path)
        assert report["status"] == "pending" and report["copilot"]["status"] == "unavailable"
        assert not path.exists()


def test_late_analysis_updates_closed_proposal_context_without_replay(tmp_path):
    flow = build(tmp_path)
    path = tmp_path / "decisions.db"
    with closing(flow.store):
        [first] = sync(tmp_path, flow, path=path)
        p, _ = flow.store.get(first["action_id"])
        flow.dismiss(p.action_id, p.proposal_hash, "operator", "not needed", now=NOW)
        decision_file(path, reply=response())
        [second] = sync(tmp_path, flow, path=path, execute=True, now=NOW + timedelta(hours=2))
        assert second["action_id"] == first["action_id"] and second["status"] == "dismissed"
        assert flow.store.context(p.action_id)["copilot"]["status"] == "available"
        assert flow.store.get(p.action_id)[0].proposal_hash == p.proposal_hash
        before = flow.store.verify()
        sync(tmp_path, flow, path=path, execute=True, now=NOW + timedelta(hours=2))
        assert flow.store.verify() == before


def test_new_stale_incidents_do_not_get_fresh_execution_windows(tmp_path):
    flow = build(tmp_path)
    with closing(flow.store):
        [report] = sync(tmp_path, flow, now=NOW + timedelta(hours=2))
        assert report["status"] == "expired"
        assert flow.store.verify()["count"] == 0


def test_existing_expired_proposal_refreshes_context_without_attempting_execution(tmp_path):
    flow = build(tmp_path)
    with closing(flow.store):
        [first] = sync(tmp_path, flow)
        [second] = sync(tmp_path, flow, execute=True, now=NOW + timedelta(hours=2))
        assert first["action_id"] == second["action_id"] and second["status"] == "expired"
        assert not any(e["event"] == "executing" for e in flow.store.audit())


def test_corrupt_decision_log_trips_both_stops_before_proposing(tmp_path):
    clear_switch(tmp_path)
    path = tmp_path / "decisions.db"
    path.write_text("corrupt sqlite database")
    flow = build(tmp_path)
    with closing(flow.store):
        with pytest.raises(RecommendationIntegrityError):
            sync(tmp_path, flow, path=path, execute=True)
        state = read_state(tmp_path)
        assert state.level == Level.EXECUTION_OFF and state.ai_off
        assert flow.store.pending(NOW) == []
        assert flow.store.audit()[0]["event"] == "kill_switch_tripped"


def test_recommendation_cannot_trigger_or_suppress_containment(tmp_path):
    path = tmp_path / "decisions.db"
    decision_file(path, reply=response(action="no_action_recommended"))
    flow = build(tmp_path)
    with closing(flow.store):
        assert sync(tmp_path, flow, path=path)[0]["status"] == "pending"
        assert sync(tmp_path, flow, path=path, events=evidence(False))[0]["status"] == "no_policy_action"


def test_concurrent_syncs_submit_one_proposal_and_one_context(tmp_path):
    with closing(build(tmp_path).store):
        pass

    def run(_):
        flow = build(tmp_path)
        with closing(flow.store):
            return sync(tmp_path, flow)[0]["action_id"]

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert len(set(pool.map(run, range(8)))) == 1
    flow = build(tmp_path)
    with closing(flow.store):
        assert len(flow.store.pending(NOW)) == 1
        assert [e["event"] for e in flow.store.audit()] == ["proposed", "incident_facts", "copilot_context"]


def test_modified_proposal_keeps_review_context(tmp_path):
    flow = build(tmp_path)
    with closing(flow.store):
        [report] = sync(tmp_path, flow)
        p, _ = flow.store.get(report["action_id"])
        replacement = flow.modify(p.action_id, p.proposal_hash, "operator", {}, "review again", now=NOW)
        assert flow.store.context(replacement.action_id) == flow.store.context(p.action_id)
        path = tmp_path / "decisions.db"
        decision_file(path, reply=response())
        sync(tmp_path, flow, path=path, execute=True)
        assert flow.store.context(replacement.action_id)["copilot"]["status"] == "available"
        assert flow.store.get(replacement.action_id)[1] == "pending"


def test_failed_analysis_is_labeled_but_does_not_disable_policy(tmp_path):
    path = tmp_path / "decisions.db"
    decision_file(path, reply=response(action="analysis_failed"), outcome="analysis_failed")
    flow = build(tmp_path)
    with closing(flow.store):
        [report] = sync(tmp_path, flow, path=path)
        assert report["status"] == "pending" and report["copilot"]["status"] == "analysis_failed"


def test_a_broken_review_journal_rolls_back_ingestion(tmp_path, monkeypatch):
    flow = build(tmp_path)
    original = flow.store.record
    with closing(flow.store):
        def fail_on_context(entry):
            if entry["event"] == "copilot_context":
                raise OSError("audit storage unavailable")
            original(entry)
        monkeypatch.setattr(flow.store, "record", fail_on_context)
        with pytest.raises(OSError):
            sync(tmp_path, flow)
        assert flow.store.pending(NOW) == []
        assert flow.store.verify()["count"] == 0


def test_incident_client_reads_all_pages_and_quotes_ids(monkeypatch):
    client = IncidentClient("http://localhost:8001/prefix")
    paths = []
    def get(path):
        paths.append(path)
        if "/events" in path:
            return []
        return {"items": [{"incident_id": str(n)} for n in range(200)] if "offset=0" in path else [{"incident_id": "last"}]}
    monkeypatch.setattr(client, "_get", get)
    assert len(client.incidents_since(T0)) == 201
    client.events("inc/odd?x")
    assert paths[-1] == "/incidents/inc%2Fodd%3Fx/events"


@pytest.mark.parametrize("url", ["file:///etc/passwd", "http://user:password@localhost", "http://localhost?q=x"])
def test_incident_client_rejects_invalid_base_urls(url):
    with pytest.raises(ValueError):
        IncidentClient(url)