import uuid

import httpx


def test_register_new_user(client: httpx.Client) -> None:
    username = f"testuser_{uuid.uuid4().hex[:10]}"
    response = client.post(
        "/auth/register", json={"username": username, "password": "a-strong-password"}
    )
    assert response.status_code == 201
    body = response.json()
    assert body["username"] == username
    assert "id" in body
    assert "password" not in body  # never leak the password back


def test_register_duplicate_username_rejected(client: httpx.Client) -> None:
    username = f"testuser_{uuid.uuid4().hex[:10]}"
    payload = {"username": username, "password": "a-strong-password"}

    first = client.post("/auth/register", json=payload)
    assert first.status_code == 201

    second = client.post("/auth/register", json=payload)
    assert second.status_code == 400


def test_login_wrong_password_rejected(client: httpx.Client) -> None:
    username = f"testuser_{uuid.uuid4().hex[:10]}"
    client.post("/auth/register", json={"username": username, "password": "correct-password"})

    response = client.post("/auth/login", data={"username": username, "password": "wrong-password"})
    assert response.status_code == 401


def test_tasks_requires_authentication(client: httpx.Client) -> None:
    response = client.get("/tasks")
    assert response.status_code == 401
