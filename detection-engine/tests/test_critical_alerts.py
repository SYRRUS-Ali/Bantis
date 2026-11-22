import json
from datetime import datetime, timedelta, timezone

from cryptography.fernet import Fernet
import pytest

from app.critical_alerts import deliver_pending_critical_alerts, load_telegram_credentials
from app.correlation import run_correlation
from app.event_models import EventORM
from app.incident_models import CriticalAlertORM, IncidentORM
from app.telegram_notifier import send_message


@pytest.fixture
def db():
    from app.db import Base, SessionLocal, engine

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    return SessionLocal


def _write_encrypted(root, key_path, name, data):
    payload = json.dumps({"purpose": name, "data": data}).encode()
    envelope = {"version": 2, "ciphertext": Fernet(key_path.read_bytes()).encrypt(payload).decode()}
    (root / f"{name}.json").write_text(json.dumps(envelope))
    (root / f"{name}.json").chmod(0o600)


def _private_config(tmp_path, monkeypatch, *, allowed=True):
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    keys = tmp_path / "keys"
    keys.mkdir(mode=0o700)
    keys.chmod(0o700)
    key_path = keys / ".secrets.key"
    key_path.write_bytes(Fernet.generate_key())
    key_path.chmod(0o600)
    _write_encrypted(root, key_path, "telegram", {
        "version": 1, "enabled": True,
        "bot_token": "123456789:abcdefghijklmnopqrstuvwxyzABCDE",
        "chat_id": "123456789",
    })
    _write_encrypted(root, key_path, "permissions", {
        "version": 1, "ai_requests": False, "telegram_messages": allowed,
        "response_decisions": False,
    })
    monkeypatch.setenv("BANTIS_ORCHESTRATION_STATE", str(root))
    monkeypatch.setenv("BANTIS_SECRETS_KEY_FILE", str(key_path))
    return root, key_path


def _store_composite(session_factory):
    with session_factory() as session:
        for event_id, scenario in (("dependency", "malicious-dependency"), ("secret", "leaked-secret")):
            session.add(EventORM(
                event_id=event_id, timestamp=datetime.now(timezone.utc), level="INFO", logger="test",
                source="attack-sim", event_type="attack_scenario_run", message="test event",
                details={"scenario": scenario, "status": "success", "mitre_technique": "T1195.001"},
            ))
        session.commit()


def test_only_saved_and_permitted_telegram_credentials_are_loaded(tmp_path, monkeypatch):
    _private_config(tmp_path, monkeypatch)
    credentials = load_telegram_credentials()
    assert credentials == ("123456789:abcdefghijklmnopqrstuvwxyzABCDE", "123456789")

    monkeypatch.setenv("BANTIS_ORCHESTRATION_STATE", str(tmp_path / "missing"))
    assert load_telegram_credentials() is None


def test_revoked_telegram_permission_keeps_critical_alert_pending(db, tmp_path, monkeypatch):
    _private_config(tmp_path, monkeypatch, allowed=False)
    _store_composite(db)
    with db() as session:
        incidents = run_correlation(session)
        assert len(incidents) == 1 and incidents[0].severity == "critical"
        assert deliver_pending_critical_alerts(session) == 0
        row = session.get(CriticalAlertORM, incidents[0].incident_id)
        assert row.delivered_at is None
        assert row.attempts == 0


def test_noncritical_incidents_do_not_enter_the_telegram_outbox(db):
    with db() as session:
        now = datetime.now(timezone.utc)
        for event_id, scenario in (("first", "malicious-dependency"), ("second", "malicious-dependency")):
            session.add(EventORM(
                event_id=event_id, timestamp=now, level="INFO", logger="test", source="attack-sim",
                event_type="attack_scenario_run", message="test event",
                details={"scenario": scenario, "status": "success", "mitre_technique": "T1195.001"},
            ))
        session.commit()
        incidents = run_correlation(session)
        assert len(incidents) == 1 and incidents[0].severity == "high"
        assert session.query(CriticalAlertORM).count() == 0


def test_critical_alert_outbox_retries_until_the_notifier_confirms_delivery(db, tmp_path, monkeypatch):
    import app.critical_alerts as alerts

    _private_config(tmp_path, monkeypatch)
    _store_composite(db)
    calls = []
    results = iter((False, True))

    def fake_send(message, *, bot_token, chat_id):
        calls.append((message, bot_token, chat_id))
        return next(results)

    monkeypatch.setattr(alerts, "send_message", fake_send)
    with db() as session:
        incident = run_correlation(session)[0]
        assert deliver_pending_critical_alerts(session) == 0
        row = session.get(CriticalAlertORM, incident.incident_id)
        assert row.attempts == 1 and row.delivered_at is None
        assert deliver_pending_critical_alerts(session) == 1
        assert row.attempts == 2 and row.delivered_at is not None

    assert len(calls) == 2
    assert "Bantis critical security incident" in calls[0][0]
    assert "Severity: critical" in calls[0][0]
    assert calls[0][1:] == ("123456789:abcdefghijklmnopqrstuvwxyzABCDE", "123456789")


def test_active_delivery_lease_prevents_a_second_sender(db, tmp_path, monkeypatch):
    _private_config(tmp_path, monkeypatch)
    incident = IncidentORM(
        incident_id="critical-lease", created_at=datetime.now(timezone.utc), pattern="fixture",
        window_seconds=0, correlated_event_ids=[], mitre_techniques=[], severity="critical",
        confidence=0.9, summary="fixture critical incident",
    )
    with db() as session:
        session.add(incident)
        session.add(CriticalAlertORM(
            incident_id=incident.incident_id, created_at=incident.created_at,
            claimed_until=datetime.now(timezone.utc) + timedelta(seconds=30),
        ))
        session.commit()
        assert deliver_pending_critical_alerts(session) == 0
        row = session.get(CriticalAlertORM, incident.incident_id)
        assert row.attempts == 0 and row.delivered_at is None


def test_notifier_posts_plain_text_and_reports_api_failure(monkeypatch):
    import urllib.request

    requests = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, limit):
            assert limit == 65537
            return b'{"ok":true}'

    def fake_urlopen(request, timeout):
        requests.append((request, timeout))
        return Response()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert send_message("critical alert", bot_token="123:secret", chat_id="42") is True
    req, timeout = requests[0]
    assert req.full_url == "https://api.telegram.org/bot123:secret/sendMessage"
    assert json.loads(req.data) == {"chat_id": "42", "text": "critical alert"}
    assert timeout == 10.0