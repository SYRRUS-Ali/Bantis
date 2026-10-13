import subprocess
import sys
from pathlib import Path

_APP_ROOT = Path(__file__).resolve().parents[1]


def test_concurrent_correlation_passes_create_each_incident_once(tmp_path):
    db_path = tmp_path / "correlation_concurrency.db"
    script = f"""
import os, threading
from datetime import datetime, timedelta, timezone
os.environ["DATABASE_URL"] = "sqlite:///{db_path}"

from app.db import Base, engine, SessionLocal
from app.event_models import EventORM
from app.incident_models import IncidentEventClaimORM, IncidentORM
from app.correlation import run_correlation

Base.metadata.create_all(bind=engine)
t0 = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)
with SessionLocal() as s:
    for i, scenario in enumerate(["malicious-dependency", "leaked-secret", "typosquatting", "compromised-ci-step"]):
        s.add(EventORM(event_id=f"e{{i}}", timestamp=t0 + timedelta(seconds=i), level="INFO", logger="x",
                       source="attack-sim", event_type="attack_scenario_run", message="m",
                       details={{"scenario": scenario, "status": "failure"}}))
    s.commit()

for round_ in range(5):
    barrier = threading.Barrier(6)
    errors = []
    def run():
        s = SessionLocal(); barrier.wait()
        try:
            run_correlation(s)
        except Exception as exc:
            errors.append(repr(exc))
        finally:
            s.close()
    threads = [threading.Thread(target=run) for _ in range(6)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert not errors, errors

with SessionLocal() as s:
    incidents = s.query(IncidentORM).all()
    claimed = [event_id for incident in incidents for event_id in incident.correlated_event_ids]
    assert len(claimed) == len(set(claimed)), f"an event belongs to more than one incident: {{claimed}}"
    assert sorted(i.pattern for i in incidents) == ["composite-dependency-secret", "same-source-burst"], incidents
    assert s.query(IncidentEventClaimORM).count() == 4
print("OK")
"""
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=60, cwd=_APP_ROOT)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "OK" in result.stdout