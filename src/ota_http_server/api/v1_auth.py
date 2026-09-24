"""Authentication routes for the v1 REST API: login, current-user info, and
OTA authorization token issuance."""

from __future__ import annotations

from datetime import datetime, timezone

from flask import Blueprint, abort, current_app, jsonify, request

from ota_http_server.core.data_models import TokenResult

from .authentication import get_user_auth_service
from .authorization import AUTH_LOGIN, AUTH_SELF, DEVICE_OTA, get_current_user, require_permission
from .common import get_db, json_body, reject_unknown_fields, required_str, user_to_dict

api_v1_auth = Blueprint("api_v1_auth", __name__, url_prefix="/api/v1/auth")


def _get_auth_service():
    """Return the device-token AuthService attached to the current application."""
    return current_app.extensions["auth_service"]


def _log_admin_activity(*, outcome: str, target: dict[str, object], error: str | None = None) -> None:
    admin_activity_logger = current_app.extensions.get("admin_activity_logger")
    if admin_activity_logger is None:
        return
    admin_activity_logger.log_activity(
        interface="http",
        entity="token",
        action="generate",
        outcome=outcome,
        target=target,
        error=error,
    )


@api_v1_auth.route("/login", methods=["POST"])
@require_permission(AUTH_LOGIN)
def login():
    """Authenticate with username/password and issue a JWT access token.

    This endpoint is public; see PUBLIC_ENDPOINTS in .authentication.
    """
    data = json_body()
    reject_unknown_fields(data, {"username", "password"})

    username = required_str(data, "username")
    password = required_str(data, "password")

    auth_service = get_user_auth_service()
    user = auth_service.authenticate(username, password, get_db())
    if user is None:
        # Same generic message whether the username doesn't exist, the password
        # is wrong, or the user is inactive: never reveal which case occurred.
        return jsonify({
            "error": {
                "code": 401,
                "message": "Invalid username or password",
            }
        }), 401

    token_result = auth_service.create_access_token(user)
    return jsonify({
        "access_token": token_result.token,
        "token_type": "Bearer",
        "expires_in": auth_service.jwt_expiry,
    }), 200


@api_v1_auth.route("/me", methods=["GET"])
@require_permission(AUTH_SELF)
def me():
    """Return the currently authenticated user's public information."""
    user = get_current_user()
    return jsonify(user_to_dict(user)), 200


@api_v1_auth.route("/ota", methods=["POST"])
@require_permission(DEVICE_OTA)
def ota_authorize():
    """Issue an OTA JWT for a device the authenticated user is permitted to operate.

    Requires a valid REST API access token (see /api/v1/auth/login) instead of
    the previous X-Admin-Secret header. The authenticated user must have a
    users_devices assignment for the target device, in addition to their role
    granting the device.ota permission.

    Body JSON:
        {
          "device_id": "uuid-v4",
          "project": "project_name",
          "expires_seconds": jwt_expiry,
          "current_vs": "1.0.0",
          "download_vs": "2.0.0"
        }
    """
    user = get_current_user()
    if user is None:
        abort(401, "Authentication required")

    data = json_body()
    device_id = required_str(data, "device_id")

    db = get_db()
    device = db.device_get_by_name(device_id)
    if device is None:
        abort(404, "Device not found")

    assignment = db.user_device_get(user.id, device.id)
    if assignment is None or db.user_device_is_expired(user.id, device.id):
        abort(403, "User is not permitted to operate this device")

    target: dict[str, object] = {
        "ip": request.remote_addr,
        "device_id": data.get("device_id"),
        "project": data.get("project"),
        "user_id": user.id,
    }
    try:
        token_result: TokenResult = _get_auth_service().create_device_token(data)
    except Exception as exc:
        _log_admin_activity(outcome="failed", target=target, error=str(exc))
        raise

    target["device_id"] = token_result.payload.get("sub", target["device_id"])
    target["project"] = token_result.payload.get("project", target["project"])
    target["expires_at"] = token_result.payload.get("exp")
    _log_admin_activity(outcome="success", target=target)

    return jsonify({
        "token": token_result.token,
        "expires_at": datetime.fromtimestamp(token_result.payload["exp"], tz=timezone.utc).isoformat(),
        "payload": token_result.payload,
    })
