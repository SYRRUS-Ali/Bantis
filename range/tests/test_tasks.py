import httpx


def test_task_crud_lifecycle(client: httpx.Client, auth_headers: dict[str, str]) -> None:
    # Create
    create = client.post("/tasks", json={"title": "Integration test task"}, headers=auth_headers)
    assert create.status_code == 201
    task = create.json()
    task_id = task["id"]
    assert task["title"] == "Integration test task"
    assert task["completed"] is False

    # Appears in the list
    listed = client.get("/tasks", headers=auth_headers)
    assert listed.status_code == 200
    assert any(t["id"] == task_id for t in listed.json())

    # Fetch by id
    fetched = client.get(f"/tasks/{task_id}", headers=auth_headers)
    assert fetched.status_code == 200
    assert fetched.json()["id"] == task_id

    # Update
    updated = client.put(f"/tasks/{task_id}", json={"completed": True}, headers=auth_headers)
    assert updated.status_code == 200
    assert updated.json()["completed"] is True

    # Re-read confirms the cache was invalidated, not serving stale data
    refetched = client.get(f"/tasks/{task_id}", headers=auth_headers)
    assert refetched.json()["completed"] is True

    # Delete
    deleted = client.delete(f"/tasks/{task_id}", headers=auth_headers)
    assert deleted.status_code == 204

    # Gone
    missing = client.get(f"/tasks/{task_id}", headers=auth_headers)
    assert missing.status_code == 404


def test_get_nonexistent_task_returns_404(client: httpx.Client, auth_headers: dict[str, str]) -> None:
    response = client.get("/tasks/999999999", headers=auth_headers)
    assert response.status_code == 404
