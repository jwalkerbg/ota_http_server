"""Tests for password management routes (/api/v1/users/me/password and
/api/v1/users/<id>/password) with JWT user authentication enabled."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from ota_http_server.core.data_models import AppPaths, User
from ota_http_server.core.passwords import Passwords
from ota_http_server.core.server import create_app

MIGRATIONS_DIR = (
    Path(__file__).parents[2]
    / "src"
    / "ota_http_server"
    / "database"
    / "migrations"
    / "sqlite"
)

JWT_SECRET = "test-secret"
JWT_ALG = "HS256"
JWT_ISSUER = "issuer"
JWT_AUDIENCE = "audience"
JWT_USER_AUDIENCE = "users-audience"
JWT_USER_EXPIRY = 1800


@pytest.fixture()
def app(tmp_path):
    """A Flask app with REST user JWT authentication enabled."""
    cfg = SimpleNamespace()
    cfg.config = {
        "parameters": {
            "app_directory": str(tmp_path),
            "www_dir": "www",
            "firmware_dir": "firmware",
            "url_firmware": "firmware",
            "jwt_alg": JWT_ALG,
            "jwt_expiry": 60,
            "jwt_max_expiry": 120,
            "jwt_secret": JWT_SECRET,
            "jwt_issuer": JWT_ISSUER,
            "jwt_audience": JWT_AUDIENCE,
            "jwt_user_audience": JWT_USER_AUDIENCE,
            "jwt_user_expiry": JWT_USER_EXPIRY,
            "admin_secret": "admin-secret",
            "trace_sql": False,
            "init_db_migrate": True,
            "migrate_dry_run": False,
        },
        "database": {
            "dbtype": "sqlite",
            "sqlite": {
                "db_file": "test.db",
                "migrations_dir": str(MIGRATIONS_DIR),
            },
        },
    }
    cfg.config["parameters"]["app_paths"] = AppPaths(cfg)

    application = create_app(cfg)
    application.extensions["db_service"].init_db()
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def db(app):
    return app.extensions["db_service"]


@pytest.fixture()
def make_user(db):
    def _make(username="alice", password="old-secret", email=None, role="admin", is_active=True):
        return db.user_add(
            User(
                id=None,
                username=username,
                password_hash=Passwords.hash(password),
                email=email or f"{username}@example.com",
                role=role,
                is_active=is_active,
                created_at=None,
                updated_at=None,
            )
        )

    return _make


def _login(client, username="alice", password="old-secret"):
    return client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password},
    )


def _token_for(client, username="alice", password="old-secret"):
    response = _login(client, username, password)
    assert response.status_code == 200
    return response.get_json()["access_token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Self-service password change: POST /api/v1/users/me/password
# ---------------------------------------------------------------------------


def test_self_service_requires_authentication(client):
    response = client.post(
        "/api/v1/users/me/password",
        json={
            "current_password": "old-secret",
            "new_password": "new-secret",
            "confirm_password": "new-secret",
        },
    )

    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == 401


def test_self_service_rejects_invalid_jwt(client):
    response = client.post(
        "/api/v1/users/me/password",
        json={
            "current_password": "old-secret",
            "new_password": "new-secret",
            "confirm_password": "new-secret",
        },
        headers=_auth("not-a-valid-token"),
    )

    assert response.status_code == 401


def test_self_service_rejects_inactive_user(client, db, make_user):
    user = make_user()
    token = _token_for(client)
    db.user_disable_by_id(user.id)

    response = client.post(
        "/api/v1/users/me/password",
        json={
            "current_password": "old-secret",
            "new_password": "new-secret",
            "confirm_password": "new-secret",
        },
        headers=_auth(token),
    )

    assert response.status_code == 401
    assert Passwords.verify("old-secret", db.user_get_by_id(user.id).password_hash)


def test_self_service_change_success(client, db, make_user):
    user = make_user()
    token = _token_for(client)

    response = client.post(
        "/api/v1/users/me/password",
        json={
            "current_password": "old-secret",
            "new_password": "new-secret",
            "confirm_password": "new-secret",
        },
        headers=_auth(token),
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["id"] == user.id
    assert "password" not in payload
    assert "password_hash" not in payload
    assert Passwords.verify("new-secret", db.user_get_by_id(user.id).password_hash)


def test_self_service_available_to_every_role(client, db, make_user):
    user = make_user(username="viewer", role="viewer")
    token = _token_for(client, username="viewer")

    response = client.post(
        "/api/v1/users/me/password",
        json={
            "current_password": "old-secret",
            "new_password": "new-secret",
            "confirm_password": "new-secret",
        },
        headers=_auth(token),
    )

    assert response.status_code == 200
    assert Passwords.verify("new-secret", db.user_get_by_id(user.id).password_hash)


def test_self_service_rejects_incorrect_current_password(client, db, make_user):
    user = make_user()
    token = _token_for(client)

    response = client.post(
        "/api/v1/users/me/password",
        json={
            "current_password": "wrong-secret",
            "new_password": "new-secret",
            "confirm_password": "new-secret",
        },
        headers=_auth(token),
    )

    assert response.status_code == 400
    assert Passwords.verify("old-secret", db.user_get_by_id(user.id).password_hash)


def test_self_service_rejects_confirmation_mismatch(client, make_user):
    make_user()
    token = _token_for(client)

    response = client.post(
        "/api/v1/users/me/password",
        json={
            "current_password": "old-secret",
            "new_password": "new-secret",
            "confirm_password": "other-secret",
        },
        headers=_auth(token),
    )

    assert response.status_code == 400


def test_self_service_rejects_invalid_new_password(client, db, make_user):
    user = make_user()
    token = _token_for(client)

    response = client.post(
        "/api/v1/users/me/password",
        json={
            "current_password": "old-secret",
            "new_password": "short",
            "confirm_password": "short",
        },
        headers=_auth(token),
    )

    assert response.status_code == 400
    assert Passwords.verify("old-secret", db.user_get_by_id(user.id).password_hash)


def test_self_service_rejects_missing_fields(client, make_user):
    make_user()
    token = _token_for(client)

    response = client.post(
        "/api/v1/users/me/password",
        json={"new_password": "new-secret"},
        headers=_auth(token),
    )

    assert response.status_code == 400


def test_self_service_rejects_password_hash_field(client, make_user):
    make_user()
    token = _token_for(client)

    response = client.post(
        "/api/v1/users/me/password",
        json={
            "current_password": "old-secret",
            "new_password": "new-secret",
            "confirm_password": "new-secret",
            "password_hash": "$argon2id$ forged",
        },
        headers=_auth(token),
    )

    assert response.status_code == 400


def test_self_service_old_password_no_longer_works(client, make_user):
    make_user()
    token = _token_for(client)

    response = client.post(
        "/api/v1/users/me/password",
        json={
            "current_password": "old-secret",
            "new_password": "new-secret",
            "confirm_password": "new-secret",
        },
        headers=_auth(token),
    )
    assert response.status_code == 200

    assert _login(client, password="old-secret").status_code == 401
    assert _login(client, password="new-secret").status_code == 200


def test_self_service_existing_token_remains_valid_until_expiry(client, make_user):
    """Documented JWT behaviour: password changes do not revoke access tokens.

    The project has no JWT blacklist/revocation; already-issued tokens remain
    valid until they expire. This test pins that behaviour.
    """
    make_user()
    token = _token_for(client)

    response = client.post(
        "/api/v1/users/me/password",
        json={
            "current_password": "old-secret",
            "new_password": "new-secret",
            "confirm_password": "new-secret",
        },
        headers=_auth(token),
    )
    assert response.status_code == 200

    followup = client.get("/api/v1/auth/me", headers=_auth(token))
    assert followup.status_code == 200
    assert followup.get_json()["username"] == "alice"


def test_self_service_does_not_change_status_or_role(client, db, make_user):
    user = make_user(username="viewer", role="viewer")
    token = _token_for(client, username="viewer")

    response = client.post(
        "/api/v1/users/me/password",
        json={
            "current_password": "old-secret",
            "new_password": "new-secret",
            "confirm_password": "new-secret",
        },
        headers=_auth(token),
    )

    assert response.status_code == 200
    stored = db.user_get_by_id(user.id)
    assert stored.role == "viewer"
    assert stored.is_active is True


# ---------------------------------------------------------------------------
# Administrator reset: POST /api/v1/users/<id>/password
# ---------------------------------------------------------------------------


def test_admin_reset_requires_authentication(client, make_user):
    user = make_user()

    response = client.post(
        f"/api/v1/users/{user.id}/password",
        json={"new_password": "new-secret", "confirm_password": "new-secret"},
    )

    assert response.status_code == 401


def test_admin_reset_forbidden_without_users_update_permission(client, make_user):
    target = make_user(username="target")
    make_user(username="viewer", role="viewer")
    token = _token_for(client, username="viewer")

    response = client.post(
        f"/api/v1/users/{target.id}/password",
        json={"new_password": "new-secret", "confirm_password": "new-secret"},
        headers=_auth(token),
    )

    assert response.status_code == 403


def test_admin_reset_success_without_current_password(client, db, make_user):
    target = make_user(username="target")
    make_user(username="admin")
    token = _token_for(client, username="admin")

    response = client.post(
        f"/api/v1/users/{target.id}/password",
        json={"new_password": "new-secret", "confirm_password": "new-secret"},
        headers=_auth(token),
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert "password" not in payload
    assert "password_hash" not in payload

    assert _login(client, username="target", password="old-secret").status_code == 401
    assert _login(client, username="target", password="new-secret").status_code == 200


def test_admin_reset_inactive_user_does_not_activate(client, db, make_user):
    target = make_user(username="target", is_active=False)
    make_user(username="admin")
    token = _token_for(client, username="admin")

    response = client.post(
        f"/api/v1/users/{target.id}/password",
        json={"new_password": "new-secret", "confirm_password": "new-secret"},
        headers=_auth(token),
    )

    assert response.status_code == 200
    stored = db.user_get_by_id(target.id)
    assert stored.is_active is False
    assert Passwords.verify("new-secret", stored.password_hash)


def test_admin_reset_not_found(client, make_user):
    make_user(username="admin")
    token = _token_for(client, username="admin")

    response = client.post(
        "/api/v1/users/999/password",
        json={"new_password": "new-secret", "confirm_password": "new-secret"},
        headers=_auth(token),
    )

    assert response.status_code == 404


def test_admin_reset_rejects_confirmation_mismatch(client, db, make_user):
    target = make_user(username="target")
    make_user(username="admin")
    token = _token_for(client, username="admin")

    response = client.post(
        f"/api/v1/users/{target.id}/password",
        json={"new_password": "new-secret", "confirm_password": "other-secret"},
        headers=_auth(token),
    )

    assert response.status_code == 400
    assert Passwords.verify("old-secret", db.user_get_by_id(target.id).password_hash)


def test_admin_reset_rejects_invalid_new_password(client, make_user):
    target = make_user(username="target")
    make_user(username="admin")
    token = _token_for(client, username="admin")

    response = client.post(
        f"/api/v1/users/{target.id}/password",
        json={"new_password": "short", "confirm_password": "short"},
        headers=_auth(token),
    )

    assert response.status_code == 400
