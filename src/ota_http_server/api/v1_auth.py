"""Authentication routes for the v1 REST API: login and current-user info."""

from __future__ import annotations

from flask import Blueprint, jsonify

from .authentication import get_user_auth_service
from .authorization import AUTH_LOGIN, AUTH_SELF, get_current_user, require_permission
from .common import get_db, json_body, reject_unknown_fields, required_str, user_to_dict

api_v1_auth = Blueprint("api_v1_auth", __name__, url_prefix="/api/v1/auth")


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
