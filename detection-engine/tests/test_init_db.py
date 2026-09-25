import subprocess
import sys
from pathlib import Path

_APP_ROOT = Path(__file__).resolve().parents[1]


def test_a_real_app_startup_creates_both_tables(tmp_path):
    db_path = tmp_path / "startup_check.db"
    script = f"""
import os
os.environ["DATABASE_URL"] = "sqlite:///{db_path}"

from fastapi.testclient import TestClient
from app.main import app

with TestClient(app):
    pass

import sqlalchemy
from app.db import engine
tables = set(sqlalchemy.inspect(engine).get_table_names())
assert {{"events", "incidents"}} <= tables, f"missing tables: {{tables}}"
print("OK")
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=_APP_ROOT,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "OK" in result.stdout