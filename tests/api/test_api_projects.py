"""Tests for the /api/v1/projects routes."""


def test_list_projects_empty(client):
    response = client.get("/api/v1/projects")

    assert response.status_code == 200
    assert response.get_json() == {"projects": []}


def test_create_project(client, user):
    response = client.post(
        "/api/v1/projects",
        json={
            "name": "smart_air",
            "display_name": "Smart Air",
            "description": "Air quality sensors",
            "created_by": user.id,
        },
    )

    assert response.status_code == 201
    payload = response.get_json()
    assert payload["name"] == "smart_air"
    assert payload["display_name"] == "Smart Air"
    assert payload["created_by"] == user.id
    assert payload["is_active"] is True


def test_create_project_defaults(client, user):
    response = client.post(
        "/api/v1/projects",
        json={"name": "minimal", "created_by": user.id},
    )

    assert response.status_code == 201
    payload = response.get_json()
    assert payload["display_name"] == ""
    assert payload["description"] == ""


def test_create_project_duplicate_conflict(client, project, user):
    response = client.post(
        "/api/v1/projects",
        json={"name": project.name, "created_by": user.id},
    )

    assert response.status_code == 409


def test_create_project_unknown_user(client):
    response = client.post(
        "/api/v1/projects",
        json={"name": "orphan", "created_by": 999},
    )

    assert response.status_code == 400


def test_create_project_missing_created_by(client):
    response = client.post("/api/v1/projects", json={"name": "orphan"})

    assert response.status_code == 400


def test_get_project(client, project):
    response = client.get(f"/api/v1/projects/{project.id}")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["id"] == project.id
    assert payload["name"] == project.name


def test_get_project_not_found(client):
    response = client.get("/api/v1/projects/999")

    assert response.status_code == 404


def test_patch_project(client, project):
    response = client.patch(
        f"/api/v1/projects/{project.id}",
        json={"display_name": "New Name", "description": "updated"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["display_name"] == "New Name"
    assert payload["description"] == "updated"
    assert payload["name"] == project.name


def test_patch_project_no_fields(client, project):
    response = client.patch(f"/api/v1/projects/{project.id}", json={})

    assert response.status_code == 400


def test_patch_project_not_found(client):
    response = client.patch("/api/v1/projects/999", json={"name": "x"})

    assert response.status_code == 404


def test_patch_project_name_conflict(client, make_project, user):
    first = make_project(name="first", created_by=user.id)
    make_project(name="second", created_by=user.id)

    response = client.patch(f"/api/v1/projects/{first.id}", json={"name": "second"})

    assert response.status_code == 409


def test_delete_project_deactivates(client, project, db):
    response = client.delete(f"/api/v1/projects/{project.id}")

    assert response.status_code == 200
    assert response.get_json()["is_active"] is False
    assert db.project_get_by_id(project.id).is_active is False


def test_delete_project_twice_conflicts(client, project):
    assert client.delete(f"/api/v1/projects/{project.id}").status_code == 200

    response = client.delete(f"/api/v1/projects/{project.id}")

    assert response.status_code == 409


def test_activate_project(client, project, db):
    db.project_disable_by_id(project.id)

    response = client.post(f"/api/v1/projects/{project.id}/activate")

    assert response.status_code == 200
    assert response.get_json()["is_active"] is True
    assert db.project_get_by_id(project.id).is_active is True


def test_deactivate_project_not_found(client):
    response = client.post("/api/v1/projects/999/deactivate")

    assert response.status_code == 404


def test_list_projects_filters(client, make_user, make_project):
    alice = make_user(username="alice")
    bob = make_user(username="bob")
    make_project(name="alpha", created_by=alice.id)
    make_project(name="beta", created_by=alice.id, is_active=False)
    make_project(name="gamma", created_by=bob.id)

    response = client.get(f"/api/v1/projects?userid={alice.id}")
    assert {p["name"] for p in response.get_json()["projects"]} == {"alpha", "beta"}

    response = client.get("/api/v1/projects?username=bob")
    assert {p["name"] for p in response.get_json()["projects"]} == {"gamma"}

    response = client.get("/api/v1/projects?state=disabled")
    assert {p["name"] for p in response.get_json()["projects"]} == {"beta"}

    response = client.get(f"/api/v1/projects?username=alice&state=enabled")
    assert {p["name"] for p in response.get_json()["projects"]} == {"alpha"}

    response = client.get("/api/v1/projects")
    assert len(response.get_json()["projects"]) == 3

    # list items expose the creator username
    item = response.get_json()["projects"][0]
    assert "created_by" in item


def test_list_projects_mutually_exclusive_user_filters(client):
    response = client.get("/api/v1/projects?userid=1&username=alice")

    assert response.status_code == 400


def test_list_projects_invalid_userid(client):
    response = client.get("/api/v1/projects?userid=abc")

    assert response.status_code == 400
