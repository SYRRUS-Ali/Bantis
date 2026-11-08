import logging
import socket
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def detection_stack(request, tmp_path, monkeypatch):
    """Give each in-process integration test its own database and listener."""
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "detection-engine"))
    database = tmp_path / "e2e.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{database}")
    monkeypatch.setenv("CORRELATION_INTERVAL_SECONDS", getattr(request, "param", "0"))

    import uvicorn
    from app import db
    from app.main import app
    from sqlalchemy import create_engine

    engine = create_engine(f"sqlite:///{database}", connect_args={"check_same_thread": False})
    previous_bind = db.SessionLocal.kw["bind"]
    monkeypatch.setattr(db, "engine", engine)
    # Keep the factory object: the scheduler captures it as a default argument.
    db.SessionLocal.configure(bind=engine)
    root = logging.getLogger()
    previous_handlers, previous_level = root.handlers[:], root.level
    server = thread = None
    try:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
            server = uvicorn.Server(uvicorn.Config(app, log_level="warning"))
            thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
            thread.start()
            deadline = time.monotonic() + 5
            while not server.started and thread.is_alive() and time.monotonic() < deadline:
                time.sleep(0.05)
            if not server.started:
                pytest.fail("detection-engine server did not start in time")
            with db.SessionLocal() as session:
                assert Path(session.get_bind().url.database) == database
            try:
                yield SimpleNamespace(engine=engine, url=f"http://127.0.0.1:{port}")
            finally:
                server.should_exit = True
                thread.join(timeout=5)
                assert not thread.is_alive(), "detection-engine server did not stop in time"
    finally:
        if server is not None:
            server.should_exit = True
        if thread is not None and thread.is_alive():
            thread.join(timeout=5)
        db.SessionLocal.configure(bind=previous_bind)
        engine.dispose()
        for handler in root.handlers:
            if handler not in previous_handlers:
                handler.close()
        root.handlers = previous_handlers
        root.setLevel(previous_level)