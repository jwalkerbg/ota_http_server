"""User management routes for the v1 REST API."""

from __future__ import annotations

from flask import Blueprint, abort, current_app, jsonify

from ota_http_server.core.data_models import User
from ota_http_server.core.password_policy import PasswordPolicyError
from ota_http_server.core.passwords import Passwords
from ota_http_server.user.user_service import (
    CurrentPasswordMismatchError,
    InactiveUserError,
    UserNotFoundError,
)

from .authorization import (
    AUTH_SELF,
    USERS_CREATE,
    USERS_DELETE,
    USERS_READ,
    USERS_UPDATE,
    ROLES,
    get_current_user,
    require_permission,
)
from .common import (
    USER_ALREADY_DISABLED,
    USER_ALREADY_ENABLED,
    USER_ALREADY_EXISTS,
    USER_NOT_FOUND,
    error_response,
    get_db,
    get_user_service,
    json_body,
    optional_str,
    parse_state_filter,
    reject_unknown_fields,
    required_str,
    user_to_dict,
)

api_v1_users = Blueprint("api_v1_users", __name__, url_prefix="/api/v1/users")


def _log_password_activity(
    *,
    action: str,
    actor_user_id: int | None,
    target_user_id: int | None,
    outcome: str,
    error: str | None = None,
) -> None:
    """Audit a password operation. Passwords and hashes are never logged."""
    activity_logger = current_app.extensions.get("admin_activity_logger")
    if activity_logger is None:
        return
    activity_logger.log_activity(
        interface="http",
        entity="user",
        action=action,
        outcome=outcome,
        target={
            "actor_user_id": actor_user_id,
            "target_user_id": target_user_id,
        },
        error=error,
    )


@api_v1_users.route("", methods=["GET"])
@api_v1_users.route("/", methods=["GET"])
@require_permission(USERS_READ)
def list_users():
    """List users, optionally filtered by ?state=enabled|disabled."""
    users = get_db().user_get_list(is_active=parse_state_filter())
    return jsonify({"users": [user_to_dict(user) for user in users]}), 200


@api_v1_users.route("", methods=["POST"])
@api_v1_users.route("/", methods=["POST"])
@require_permission(USERS_CREATE)
def create_user():
    data = json_body()
    reject_unknown_fields(data, {"username", "password", "email", "role"})

    username = required_str(data, "username")
    password = required_str(data, "password")
    email = required_str(data, "email")
    role = required_str(data, "role")
    if role not in ROLES:
        return error_response(400, f"Field 'role' must be one of: {', '.join(sorted(ROLES))}")

    user = User(
        id=None,
        username=username,
        password_hash=Passwords.hash(password),
        email=email,
        role=role,
        is_active=True,
        created_at=None,
        updated_at=None,
    )

    try:
        created = get_db().user_add(user)
    except USER_ALREADY_EXISTS as exc:
        return error_response(409, str(exc))

    return jsonify(user_to_dict(created)), 201


@api_v1_users.route("/<int:user_id>", methods=["GET"])
@require_permission(USERS_READ)
def get_user(user_id: int):
    user = get_db().user_get_by_id(user_id)
    if user is None:
        return error_response(404, f"User id={user_id} not found")
    return jsonify(user_to_dict(user)), 200


@api_v1_users.route("/<int:user_id>", methods=["PATCH"])
@require_permission(USERS_UPDATE)
def update_user(user_id: int):
    data = json_body()
    reject_unknown_fields(data, {"username", "email", "role"})

    username = optional_str(data, "username")
    email = optional_str(data, "email")
    role = optional_str(data, "role")
    if role is not None and role not in ROLES:
        return error_response(400, f"Field 'role' must be one of: {', '.join(sorted(ROLES))}")

    try:
        updated = get_db().user_update_by_id(
            user_id,
            username=username,
            email=email,
            role=role,
        )
    except ValueError as exc:
        return error_response(400, str(exc))
    except USER_NOT_FOUND as exc:
        return error_response(404, str(exc))
    except USER_ALREADY_EXISTS as exc:
        return error_response(409, str(exc))

    return jsonify(user_to_dict(updated)), 200


def _set_user_active(user_id: int, active: bool) -> tuple[object, int]:
    db = get_db()
    try:
        if active:
            db.user_enable_by_id(user_id)
        else:
            db.user_disable_by_id(user_id)
    except USER_NOT_FOUND as exc:
        return error_response(404, str(exc))
    except USER_ALREADY_ENABLED as exc:
        return error_response(409, str(exc))
    except USER_ALREADY_DISABLED as exc:
        return error_response(409, str(exc))

    state = "activated" if active else "deactivated"
    return jsonify({"id": user_id, "is_active": active, "message": f"User {state}"}), 200


@api_v1_users.route("/<int:user_id>", methods=["DELETE"])
@require_permission(USERS_DELETE)
def deactivate_user(user_id: int):
    """DELETE deactivates the user; the account and its audit history are kept."""
    return _set_user_active(user_id, False)


@api_v1_users.route("/<int:user_id>/activate", methods=["POST"])
@require_permission(USERS_UPDATE)
def activate_user(user_id: int):
    return _set_user_active(user_id, True)


@api_v1_users.route("/<int:user_id>/deactivate", methods=["POST"])
@require_permission(USERS_UPDATE)
def deactivate_user_action(user_id: int):
    return _set_user_active(user_id, False)


@api_v1_users.route("/me/password", methods=["POST"])
@require_permission(AUTH_SELF)
def change_own_password():
    """Self-service password change; requires the current password."""
    user = get_current_user()
    user_id = getattr(user, "id", None)
    if user_id is None:
        # JWT authentication always resolves a database user; this covers
        # deployments running with REST user authentication disabled.
        abort(401, "Authentication required")
    data = json_body()
    reject_unknown_fields(data, {"current_password", "new_password", "confirm_password"})

    current_password = required_str(data, "current_password")
    new_password = required_str(data, "new_password")
    confirm_password = required_str(data, "confirm_password")

    try:
        get_user_service().change_password(user_id, current_password, new_password, confirm_password)
    except CurrentPasswordMismatchError as exc:
        _log_password_activity(
            action="password-change", actor_user_id=user_id, target_user_id=user_id,
            outcome="failed", error=str(exc),
        )
        return error_response(400, str(exc))
    except InactiveUserError as exc:
        _log_password_activity(
            action="password-change", actor_user_id=user_id, target_user_id=user_id,
            outcome="failed", error=str(exc),
        )
        return error_response(401, str(exc))
    except PasswordPolicyError as exc:
        _log_password_activity(
            action="password-change", actor_user_id=user_id, target_user_id=user_id,
            outcome="failed", error=str(exc),
        )
        return error_response(400, str(exc))

    _log_password_activity(
        action="password-change", actor_user_id=user_id, target_user_id=user_id,
        outcome="success",
    )
    return jsonify({"id": user_id, "message": "Password updated"}), 200


@api_v1_users.route("/<int:user_id>/password", methods=["POST"])
@require_permission(USERS_UPDATE)
def reset_user_password(user_id: int):
    """Administrative password reset; the current password is not required."""
    data = json_body()
    reject_unknown_fields(data, {"new_password", "confirm_password"})

    new_password = required_str(data, "new_password")
    confirm_password = required_str(data, "confirm_password")

    actor = get_current_user()
    actor_user_id = getattr(actor, "id", None)

    try:
        get_user_service().reset_password(user_id, new_password, confirm_password)
    except UserNotFoundError as exc:
        _log_password_activity(
            action="password-reset", actor_user_id=actor_user_id, target_user_id=user_id,
            outcome="failed", error=str(exc),
        )
        return error_response(404, str(exc))
    except PasswordPolicyError as exc:
        _log_password_activity(
            action="password-reset", actor_user_id=actor_user_id, target_user_id=user_id,
            outcome="failed", error=str(exc),
        )
        return error_response(400, str(exc))

    _log_password_activity(
        action="password-reset", actor_user_id=actor_user_id, target_user_id=user_id,
        outcome="success",
    )
    return jsonify({"id": user_id, "message": "Password updated"}), 200
