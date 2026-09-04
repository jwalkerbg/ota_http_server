"""Centralized REST API authentication for human/API users.

Extracts and validates a Bearer JWT from the Authorization header, then loads
the corresponding user from the database so the existing permission layer
(:mod:`ota_http_server.api.authorization`) can authorize the request. This is
the single place request authentication happens; individual endpoints do not
need to (and must not) implement their own authentication.
"""

from __future__ import annotations

from flask import abort, current_app, request

from ota_http_server.core.data_models import User
from ota_http_server.core.user_auth_service import UserAuthService

from .authorization import set_current_user

#: Endpoints that must remain reachable without authentication.
PUBLIC_ENDPOINTS = frozenset({"api_v1_auth.login"})


def get_user_auth_service() -> UserAuthService:
    """Return the UserAuthService attached to the current application."""
    return current_app.extensions["user_auth_service"]


def extract_bearer_token() -> str:
    """Extract the bearer token from the Authorization header.

    Aborts with 401 if the header is missing or malformed.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        abort(401, "Missing Authorization header")

    parts = auth_header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        abort(401, "Authorization header must be 'Bearer <token>'")

    return parts[1].strip()


def authenticate_request() -> User:
    """Authenticate the current request and return the authenticated user.

    On success, the user is also stashed for the permission layer via
    :func:`ota_http_server.api.authorization.set_current_user`.
    """
    token = extract_bearer_token()
    auth_service = get_user_auth_service()
    db_service = current_app.extensions["db_service"]

    user = auth_service.resolve_user(token, db_service)
    set_current_user(user)
    return user


def authenticate_request_hook() -> None:
    """before_request hook: authenticate every REST API request except public ones."""
    if not request.path.startswith("/api/"):
        return
    if request.endpoint in PUBLIC_ENDPOINTS:
        return
    # Let Flask resolve 404s for unknown routes without requiring authentication.
    if request.endpoint is None:
        return
    if not current_app.extensions.get("use_jwt_user_auth", True):
        # REST user authentication disabled (e.g. --no-jwt / tests): fall back to
        # the existing api_authenticated_user_loader extension point unchanged.
        return
    authenticate_request()
