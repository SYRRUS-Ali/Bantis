import os
import uuid

import httpx
import pytest

# Defaults to nginx on port 80 — the same entry point a real client would use.
# Override with API_BASE_URL if you're testing against a different host/port.
BASE_URL = os.environ.get("API_BASE_URL", "http://localhost")


@pytest.fixture(scope="session")
def client() -> httpx.Client:
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        yield client


@pytest.fixture
def auth_headers(client: httpx.Client) -> dict[str, str]:
    """Registers a fresh, unique user and returns an Authorization header.

    A new username per test run avoids collisions with data left behind by
    previous runs — these tests hit a real, persistent database, not an
    ephemeral one.
    """
    username = f"testuser_{uuid.uuid4().hex[:10]}"
    password = "a-strong-test-password"

    register = client.post("/auth/register", json={"username": username, "password": password})
    assert register.status_code == 201, register.text

    login = client.post("/auth/login", data={"username": username, "password": password})
    assert login.status_code == 200, login.text

    token = login.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
