"""Centralized authorization policy for REST API endpoints."""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import Protocol

from flask import abort, current_app, g


class AuthenticatedUser(Protocol):
    """The user identity supplied by the authentication layer."""

    role: str


SYSTEM_READ = "system.read"
USERS_READ = "users.read"
USERS_CREATE = "users.create"
USERS_UPDATE = "users.update"
USERS_DELETE = "users.delete"
PROJECTS_READ = "projects.read"
PROJECTS_CREATE = "projects.create"
PROJECTS_UPDATE = "projects.update"
PROJECTS_DELETE = "projects.delete"
DEVICES_READ = "devices.read"
DEVICES_CREATE = "devices.create"
DEVICES_UPDATE = "devices.update"
DEVICES_DELETE = "devices.delete"
FIRMWARE_READ = "firmware.read"
FIRMWARE_UPLOAD = "firmware.upload"
FIRMWARE_UPDATE = "firmware.update"
FIRMWARE_DELETE = "firmware.delete"
FIRMWARE_DOWNLOAD = "firmware.download"
AUTH_LOGIN = "auth.login"
AUTH_SELF = "auth.self"

ROLES = frozenset({"viewer", "operator", "admin"})

PERMISSIONS = frozenset({
    SYSTEM_READ,
    USERS_READ,
    USERS_CREATE,
    USERS_UPDATE,
    USERS_DELETE,
    PROJECTS_READ,
    PROJECTS_CREATE,
    PROJECTS_UPDATE,
    PROJECTS_DELETE,
    DEVICES_READ,
    DEVICES_CREATE,
    DEVICES_UPDATE,
    DEVICES_DELETE,
    FIRMWARE_READ,
    FIRMWARE_UPLOAD,
    FIRMWARE_UPDATE,
    FIRMWARE_DELETE,
    FIRMWARE_DOWNLOAD,
    AUTH_LOGIN,
    AUTH_SELF,
})

# Permissions granted to every role regardless of their other privileges:
# logging in and reading one's own identity are not privileged operations.
_COMMON_PERMISSIONS = frozenset({AUTH_LOGIN, AUTH_SELF})

ROLE_PERMISSIONS = {
    "viewer": frozenset({
        SYSTEM_READ,
        PROJECTS_READ,
        DEVICES_READ,
        FIRMWARE_READ,
        FIRMWARE_DOWNLOAD,
    }) | _COMMON_PERMISSIONS,
    "operator": frozenset({
        SYSTEM_READ,
        PROJECTS_READ,
        PROJECTS_CREATE,
        PROJECTS_UPDATE,
        DEVICES_READ,
        DEVICES_CREATE,
        DEVICES_UPDATE,
        FIRMWARE_READ,
        FIRMWARE_UPLOAD,
        FIRMWARE_UPDATE,
        FIRMWARE_DOWNLOAD,
    }) | _COMMON_PERMISSIONS,
    "admin": PERMISSIONS,
}

AuthenticatedUserLoader = Callable[[], AuthenticatedUser | None]


def set_current_user(user: AuthenticatedUser) -> None:
    """Store an authenticated REST API user for the current request."""
    g.api_authenticated_user = user


def get_current_user() -> AuthenticatedUser | None:
    """Return the identity provided by authentication, if it has run."""
    user: AuthenticatedUser | None = g.get("api_authenticated_user")
    if user is not None:
        return user

    loader: AuthenticatedUserLoader | None = current_app.extensions.get(
        "api_authenticated_user_loader"
    )
    if loader is None:
        return None
    if not callable(loader):
        raise RuntimeError("api_authenticated_user_loader must be callable")
    return loader()


def has_permission(role: str, permission: str) -> bool:
    """Return whether a defined permission is granted to the supplied role."""
    return permission in PERMISSIONS and permission in ROLE_PERMISSIONS.get(role, frozenset())


def require_permission(permission: str):
    """Require permission when an authentication layer supplied a user identity.

    Authentication remains responsible for rejecting unauthenticated requests.
    Until it is integrated, requests without an authenticated user retain the
    REST API's existing behavior.
    """
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = get_current_user()
            if user is not None and not has_permission(user.role, permission):
                abort(403, f"Permission required: {permission}")
            return view(*args, **kwargs)

        wrapped.required_permission = permission
        return wrapped

    return decorator
