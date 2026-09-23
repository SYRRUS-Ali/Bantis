# detection-engine

M3's Detection Engine — ingests structured events from `range/` and
`attack-sim/` (the shared envelope in
[`docs/event-schema.md`](../docs/event-schema.md)) and correlates them
into incidents, per the rules designed in
[`docs/correlation-design.md`](../docs/correlation-design.md).

This is a separate, independently-deployable component, same
relationship to `range/` and `attack-sim/` that those two already have
to each other.

## Structure

```
detection-engine/
├── app/
│   ├── main.py             # FastAPI app: /health, includes routers/
│   ├── db.py                # SQLAlchemy engine/session, Base, init_db()
│   ├── event_models.py       # EventORM table definition
│   ├── incident_models.py    # IncidentORM table definition
│   ├── models.py              # Pydantic schemas for the API (EventIn/EventOut)
│   └── routers/
│       └── events.py           # POST /events — the ingestion endpoint
├── tests/
│   ├── test_events_endpoint.py
│   └── requirements.txt
└── requirements.txt
```

## Status

Ingestion only. `events` and `incidents` tables both exist; only
`events` is written to so far — nothing yet correlates rows in `events`
into rows in `incidents`. That's separate, later work, building directly
on [`docs/correlation-design.md`](../docs/correlation-design.md)'s two
patterns.

## Database

No `docker-compose`/`.env` setup exists for this service yet (unlike
`range/`), so `DATABASE_URL` defaults to a local SQLite file
(`detection_engine.db`, gitignored) rather than failing loudly the way
`range/api` does — this keeps the service runnable today without
inventing that infrastructure just to start it. Set `DATABASE_URL`
explicitly to point at a real Postgres instance instead:

```bash
export DATABASE_URL=postgresql://user:pass@host:5432/dbname
```

## Running it

```bash
cd detection-engine
pip install -r requirements.txt
uvicorn app.main:app --reload
curl http://localhost:8000/health
```

## Running the tests

```bash
cd detection-engine
pip install -r requirements.txt -r tests/requirements.txt
python -m pytest tests -v
```

Tests never touch the default SQLite file or a real database — each
test gets an isolated `sqlite:///:memory:` database via `DATABASE_URL`
overridden per test, with all tables dropped and recreated before every
test to guarantee isolation even though the underlying engine object is
cached and shared across the whole test run (a Python module-import
quirk, not a design choice — see the comment at the top of
`tests/test_events_endpoint.py`).