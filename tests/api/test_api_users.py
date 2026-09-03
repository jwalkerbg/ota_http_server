"""Tests for the /api/v1/users routes."""

from ota_http_server.core.passwords import Passwords


def test_list_users_empty(client):
    response = client.get("/api/v1/users")

    assert response.status_code == 200
    assert response.get_json() == {"users": []}


def test_create_user(client, db):
    response = client.post(
        "/api/v1/users",
        json={
            "username": "bob",
            "password": "s3cret",
            "email": "bob@example.com",
            "role": "operator",
        },
    )

    assert response.status_code == 201
    payload = response.get_json()
    assert payload["username"] == "bob"
    assert payload["email"] == "bob@example.com"
    assert payload["role"] == "operator"
    assert payload["is_active"] is True
    assert "password_hash" not in payload

    stored = db.user_get_by_id(payload["id"])
    assert Passwords.verify("s3cret", stored.password_hash)


def test_create_user_duplicate_conflict(client, user):
    response = client.post(
        "/api/v1/users",
        json={
            "username": user.username,
            "password": "s3cret",
            "email": "other@example.com",
            "role": "viewer",
        },
    )

    assert response.status_code == 409
    assert response.get_json()["error"]["code"] == 409


def test_create_user_missing_field(client):
    response = client.post("/api/v1/users", json={"username": "bob"})

    assert response.status_code == 400


def test_create_user_rejects_unknown_field(client):
    response = client.post(
        "/api/v1/users",
        json={
            "username": "bob",
            "password": "s3cret",
            "email": "bob@example.com",
            "role": "viewer",
            "is_active": False,
        },
    )

    assert response.status_code == 400


def test_get_user(client, user):
    response = client.get(f"/api/v1/users/{user.id}")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["id"] == user.id
    assert payload["username"] == user.username
    assert "password_hash" not in payload


def test_get_user_not_found(client):
    response = client.get("/api/v1/users/999")

    assert response.status_code == 404
    assert response.get_json()["error"]["code"] == 404


def test_patch_user(client, user):
    response = client.patch(
        f"/api/v1/users/{user.id}",
        json={"email": "new@example.com", "role": "viewer"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["email"] == "new@example.com"
    assert payload["role"] == "viewer"
    assert payload["username"] == user.username


def test_patch_user_no_fields(client, user):
    response = client.patch(f"/api/v1/users/{user.id}", json={})

    assert response.status_code == 400


def test_patch_user_not_found(client):
    response = client.patch("/api/v1/users/999", json={"role": "viewer"})

    assert response.status_code == 404


def test_patch_user_conflict(client, user, make_user):
    other = make_user(username="bob")

    response = client.patch(
        f"/api/v1/users/{user.id}",
        json={"username": other.username},
    )

    assert response.status_code == 409


def test_delete_user_deactivates(client, user, db):
    response = client.delete(f"/api/v1/users/{user.id}")

    assert response.status_code == 200
    assert response.get_json()["is_active"] is False
    assert db.user_get_by_id(user.id).is_active is False


def test_delete_user_twice_conflicts(client, user):
    assert client.delete(f"/api/v1/users/{user.id}").status_code == 200

    response = client.delete(f"/api/v1/users/{user.id}")

    assert response.status_code == 409


def test_activate_user(client, user, db):
    db.user_disable_by_id(user.id)

    response = client.post(f"/api/v1/users/{user.id}/activate")

    assert response.status_code == 200
    assert response.get_json()["is_active"] is True
    assert db.user_get_by_id(user.id).is_active is True


def test_activate_user_already_active_conflicts(client, user):
    response = client.post(f"/api/v1/users/{user.id}/activate")

    assert response.status_code == 409


def test_deactivate_user_not_found(client):
    response = client.post("/api/v1/users/999/deactivate")

    assert response.status_code == 404


def test_set_user_password(client, user, db):
    response = client.post(
        f"/api/v1/users/{user.id}/password",
        json={"password": "new-password"},
    )

    assert response.status_code == 200
    stored = db.user_get_by_id(user.id)
    assert Passwords.verify("new-password", stored.password_hash)


def test_set_user_password_not_found(client):
    response = client.post("/api/v1/users/999/password", json={"password": "x"})

    assert response.status_code == 404


def test_list_users_state_filter(client, make_user):
    make_user(username="active1")
    make_user(username="active2")
    make_user(username="disabled1", is_active=False)
    make_user(username="disabled2", is_active=False)

    response = client.get("/api/v1/users?state=enabled")
    assert response.status_code == 200
    usernames = {u["username"] for u in response.get_json()["users"]}
    assert usernames == {"active1", "active2"}

    response = client.get("/api/v1/users?state=disabled")
    assert response.status_code == 200
    usernames = {u["username"] for u in response.get_json()["users"]}
    assert usernames == {"disabled1", "disabled2"}

    response = client.get("/api/v1/users")
    assert len(response.get_json()["users"]) == 4


def test_list_users_invalid_state(client):
    response = client.get("/api/v1/users?state=bogus")

    assert response.status_code == 400
