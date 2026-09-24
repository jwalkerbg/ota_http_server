"""Tests for user authentication (/api/v1/auth) and its integration with
the existing role-based permission system."""

from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace

import jwt
import pytest

from ota_http_server.core.data_models import AppPaths, Device, Project, User, UserDevice
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


def _base_parameters(tmp_path) -> dict:
    return {
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
    }


@pytest.fixture()
def authed_app(tmp_path):
    """A Flask app with REST user JWT authentication enabled."""
    cfg = SimpleNamespace()
    cfg.config = {
        "parameters": _base_parameters(tmp_path),
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
def authed_client(authed_app):
    return authed_app.test_client()


@pytest.fixture()
def authed_db(authed_app):
    return authed_app.extensions["db_service"]


@pytest.fixture()
def make_authed_user(authed_db):
    def _make(username="alice", password="secret", email=None, role="admin", is_active=True):
        return authed_db.user_add(
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


@pytest.fixture()
def make_authed_project(authed_db):
    def _make(name="smart_fan", created_by=None, is_active=True):
        return authed_db.project_add(
            Project(
                id=None,
                name=name,
                display_name=name.replace("_", " ").title(),
                description=f"{name} description",
                created_by=created_by,
                is_active=is_active,
                created_at=None,
                updated_at=None,
            )
        )

    return _make


@pytest.fixture()
def make_authed_device(authed_db):
    def _make(uuid="e6f87d77-4216-4be1-ab83-b5fa6792b747", project_id=None, is_active=True):
        target = authed_db.target_get_by_name("Not defined")
        return authed_db.device_add(
            Device(
                id=None,
                uuid=uuid,
                project_id=project_id,
                target_id=target.id,
                model="ESP32S3",
                serial_number=None,
                current_version="1.0.0",
                last_seen=None,
                is_active=is_active,
                created_at=None,
                updated_at=None,
            )
        )

    return _make


@pytest.fixture()
def assign_authed_user_device(authed_db):
    def _assign(user, device, expires_at=None):
        return authed_db.user_device_add(UserDevice(user.id, device.id, None, expires_at))

    return _assign


def _login(client, username="alice", password="secret"):
    return client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password},
    )


def _decode_without_verification(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


def test_login_success(authed_client, make_authed_user):
    make_authed_user()

    response = _login(authed_client)

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["token_type"] == "Bearer"
    assert payload["expires_in"] == JWT_USER_EXPIRY
    assert isinstance(payload["access_token"], str) and payload["access_token"]


def test_login_fails_with_invalid_username(authed_client, make_authed_user):
    make_authed_user()

    response = _login(authed_client, username="does-not-exist")

    assert response.status_code == 401
    assert response.get_json()["error"]["message"] == "Invalid username or password"


def test_login_fails_with_invalid_password(authed_client, make_authed_user):
    make_authed_user()

    response = _login(authed_client, password="wrong-password")

    assert response.status_code == 401
    assert response.get_json()["error"]["message"] == "Invalid username or password"


def test_login_fails_for_inactive_user(authed_client, make_authed_user):
    make_authed_user(is_active=False)

    response = _login(authed_client)

    assert response.status_code == 401
    assert response.get_json()["error"]["message"] == "Invalid username or password"


def test_login_does_not_reveal_whether_username_exists(authed_client, make_authed_user):
    make_authed_user()

    bad_username_response = _login(authed_client, username="does-not-exist")
    bad_password_response = _login(authed_client, password="wrong-password")

    assert bad_username_response.status_code == bad_password_response.status_code == 401
    assert (
        bad_username_response.get_json()["error"]["message"]
        == bad_password_response.get_json()["error"]["message"]
    )


def test_login_returns_jwt_with_required_claims(authed_client, make_authed_user):
    user = make_authed_user(role="operator")

    response = _login(authed_client)

    token = response.get_json()["access_token"]
    payload = _decode_without_verification(token)
    assert payload["sub"] == str(user.id)
    assert payload["username"] == user.username
    assert payload["role"] == "operator"
    assert "iat" in payload
    assert "exp" in payload
    assert payload["iss"] == JWT_ISSUER
    assert payload["aud"] == JWT_USER_AUDIENCE
    assert "jti" in payload
    # Never leak sensitive data into the token.
    assert "password" not in payload
    assert "password_hash" not in payload
    assert "email" not in payload


def test_login_jwt_expires_according_to_configuration(authed_client, make_authed_user):
    make_authed_user()

    response = _login(authed_client)

    token = response.get_json()["access_token"]
    payload = _decode_without_verification(token)
    assert payload["exp"] - payload["iat"] == JWT_USER_EXPIRY


def test_login_is_public_without_authentication(authed_client, make_authed_user):
    make_authed_user()

    # No Authorization header is sent at all, and login still succeeds.
    response = _login(authed_client)

    assert response.status_code == 200


# ---------------------------------------------------------------------------
# JWT validation on protected endpoints
# ---------------------------------------------------------------------------


def _access_token(authed_client, username="alice", password="secret") -> str:
    response = _login(authed_client, username=username, password=password)
    return response.get_json()["access_token"]


def test_protected_endpoint_without_authorization_header_returns_401(authed_client):
    response = authed_client.get("/api/v1/status")

    assert response.status_code == 401


def test_protected_endpoint_with_malformed_authorization_header_returns_401(authed_client):
    response = authed_client.get(
        "/api/v1/status", headers={"Authorization": "NotBearer sometoken"}
    )

    assert response.status_code == 401


def test_protected_endpoint_with_invalid_jwt_returns_401(authed_client):
    response = authed_client.get(
        "/api/v1/status", headers={"Authorization": "Bearer not-a-real-jwt"}
    )

    assert response.status_code == 401


def test_protected_endpoint_with_expired_jwt_returns_401(authed_client, make_authed_user):
    user = make_authed_user()
    now = int(time.time())
    token = jwt.encode(
        {
            "sub": str(user.id),
            "username": user.username,
            "role": user.role,
            "iat": now - 120,
            "exp": now - 60,
            "iss": JWT_ISSUER,
            "aud": JWT_USER_AUDIENCE,
            "jti": "expired-token",
        },
        JWT_SECRET,
        algorithm=JWT_ALG,
    )

    response = authed_client.get(
        "/api/v1/status", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 401


def test_protected_endpoint_with_invalid_signature_returns_401(authed_client, make_authed_user):
    user = make_authed_user()
    now = int(time.time())
    token = jwt.encode(
        {
            "sub": str(user.id),
            "username": user.username,
            "role": user.role,
            "iat": now,
            "exp": now + 60,
            "iss": JWT_ISSUER,
            "aud": JWT_USER_AUDIENCE,
            "jti": "bad-signature",
        },
        "wrong-secret",
        algorithm=JWT_ALG,
    )

    response = authed_client.get(
        "/api/v1/status", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 401


def test_protected_endpoint_with_incorrect_issuer_returns_401(authed_client, make_authed_user):
    user = make_authed_user()
    now = int(time.time())
    token = jwt.encode(
        {
            "sub": str(user.id),
            "username": user.username,
            "role": user.role,
            "iat": now,
            "exp": now + 60,
            "iss": "someone-else",
            "aud": JWT_USER_AUDIENCE,
            "jti": "bad-issuer",
        },
        JWT_SECRET,
        algorithm=JWT_ALG,
    )

    response = authed_client.get(
        "/api/v1/status", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 401


def test_protected_endpoint_with_incorrect_audience_returns_401(authed_client, make_authed_user):
    user = make_authed_user()
    now = int(time.time())
    token = jwt.encode(
        {
            "sub": str(user.id),
            "username": user.username,
            "role": user.role,
            "iat": now,
            "exp": now + 60,
            "iss": JWT_ISSUER,
            "aud": "someone-elses-audience",
            "jti": "bad-audience",
        },
        JWT_SECRET,
        algorithm=JWT_ALG,
    )

    response = authed_client.get(
        "/api/v1/status", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 401


def test_token_for_nonexistent_user_returns_401(authed_client, make_authed_user):
    make_authed_user()
    now = int(time.time())
    token = jwt.encode(
        {
            "sub": "999999",
            "username": "ghost",
            "role": "admin",
            "iat": now,
            "exp": now + 60,
            "iss": JWT_ISSUER,
            "aud": JWT_USER_AUDIENCE,
            "jti": "ghost-token",
        },
        JWT_SECRET,
        algorithm=JWT_ALG,
    )

    response = authed_client.get(
        "/api/v1/status", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 401


def test_token_for_deactivated_user_returns_401(authed_client, make_authed_user, authed_db):
    user = make_authed_user()
    token = _access_token(authed_client)

    authed_db.user_disable_by_id(user.id)

    response = authed_client.get(
        "/api/v1/status", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 401


def test_valid_authenticated_user_reaches_permission_system(authed_client, make_authed_user):
    make_authed_user(role="admin")
    token = _access_token(authed_client)

    response = authed_client.get(
        "/api/v1/status", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200


def test_authenticated_user_without_permission_receives_403(authed_client, make_authed_user):
    make_authed_user(role="viewer")
    token = _access_token(authed_client)

    response = authed_client.get(
        "/api/v1/users", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 403


def test_admin_can_access_admin_protected_endpoint(authed_client, make_authed_user):
    make_authed_user(role="admin")
    token = _access_token(authed_client)

    response = authed_client.get(
        "/api/v1/users", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200


def test_operator_cannot_access_admin_only_endpoint(authed_client, make_authed_user):
    make_authed_user(role="operator")
    token = _access_token(authed_client)

    response = authed_client.get(
        "/api/v1/users", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 403


# ---------------------------------------------------------------------------
# /api/v1/auth/me
# ---------------------------------------------------------------------------


def test_me_returns_authenticated_user_public_info(authed_client, make_authed_user):
    user = make_authed_user(role="operator")
    token = _access_token(authed_client)

    response = authed_client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["id"] == user.id
    assert payload["username"] == user.username
    assert payload["email"] == user.email
    assert payload["role"] == "operator"
    assert payload["is_active"] is True
    assert "password_hash" not in payload
    assert "password" not in payload


# ---------------------------------------------------------------------------
# /api/v1/auth/ota
# ---------------------------------------------------------------------------


def _ota_request(client, token, device_uuid, project="smart_fan", download_vs="2.0.0"):
    return client.post(
        "/api/v1/auth/ota",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "device_id": device_uuid,
            "project": project,
            "download_vs": download_vs,
        },
    )


def test_ota_authorize_issues_token_for_assigned_device(
    authed_client,
    make_authed_user,
    make_authed_project,
    make_authed_device,
    assign_authed_user_device,
):
    user = make_authed_user(role="operator")
    project = make_authed_project(created_by=user.id)
    device = make_authed_device(project_id=project.id)
    assign_authed_user_device(user, device)
    token = _access_token(authed_client)

    response = _ota_request(authed_client, token, device.uuid, project=project.name)

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["payload"]["sub"] == device.uuid
    assert payload["payload"]["project"] == project.name
    assert isinstance(payload["token"], str) and payload["token"]


def test_ota_authorize_rejects_unassigned_device(
    authed_client,
    make_authed_user,
    make_authed_project,
    make_authed_device,
):
    user = make_authed_user(role="operator")
    project = make_authed_project(created_by=user.id)
    device = make_authed_device(project_id=project.id)
    token = _access_token(authed_client)

    response = _ota_request(authed_client, token, device.uuid, project=project.name)

    assert response.status_code == 403


def test_ota_authorize_rejects_expired_assignment(
    authed_client,
    make_authed_user,
    make_authed_project,
    make_authed_device,
    assign_authed_user_device,
):
    from datetime import UTC, datetime, timedelta

    user = make_authed_user(role="operator")
    project = make_authed_project(created_by=user.id)
    device = make_authed_device(project_id=project.id)
    assign_authed_user_device(user, device, expires_at=datetime.now(UTC) - timedelta(days=1))
    token = _access_token(authed_client)

    response = _ota_request(authed_client, token, device.uuid, project=project.name)

    assert response.status_code == 403


def test_ota_authorize_rejects_unknown_device(authed_client, make_authed_user):
    make_authed_user(role="operator")
    token = _access_token(authed_client)

    response = _ota_request(authed_client, token, "does-not-exist", project="smart_fan")

    assert response.status_code == 404


def test_ota_authorize_forbidden_for_role_without_device_ota_permission(
    authed_client,
    make_authed_user,
    make_authed_project,
    make_authed_device,
    assign_authed_user_device,
):
    user = make_authed_user(role="viewer")
    project = make_authed_project(created_by=user.id)
    device = make_authed_device(project_id=project.id)
    assign_authed_user_device(user, device)
    token = _access_token(authed_client)

    response = _ota_request(authed_client, token, device.uuid, project=project.name)

    assert response.status_code == 403


def test_ota_authorize_requires_authentication(authed_client):
    response = authed_client.post(
        "/api/v1/auth/ota",
        json={"device_id": "some-device", "project": "smart_fan", "download_vs": "2.0.0"},
    )

    assert response.status_code == 401


def test_ota_authorize_logs_admin_activity(
    authed_app,
    authed_client,
    make_authed_user,
    make_authed_project,
    make_authed_device,
    assign_authed_user_device,
):
    from unittest.mock import MagicMock

    admin_activity_logger = MagicMock()
    authed_app.extensions["admin_activity_logger"] = admin_activity_logger

    user = make_authed_user(role="operator")
    project = make_authed_project(created_by=user.id)
    device = make_authed_device(project_id=project.id)
    assign_authed_user_device(user, device)
    token = _access_token(authed_client)

    response = _ota_request(authed_client, token, device.uuid, project=project.name)

    assert response.status_code == 200
    admin_activity_logger.log_activity.assert_called_once()
    kwargs = admin_activity_logger.log_activity.call_args.kwargs
    assert kwargs["outcome"] == "success"
    assert kwargs["target"]["device_id"] == device.uuid
    assert kwargs["target"]["project"] == project.name
    assert kwargs["target"]["user_id"] == user.id



def test_me_without_authentication_returns_401(authed_client):
    response = authed_client.get("/api/v1/auth/me")

    assert response.status_code == 401
