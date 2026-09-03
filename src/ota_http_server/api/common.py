"""Shared helpers for the v1 REST API route modules."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from flask import abort, current_app, jsonify, request

from ota_http_server.core.data_models import (
    AppPaths,
    Device,
    DeviceListItem,
    Firmware,
    FirmwareListItem,
    Project,
    ProjectListItem,
    User,
)
from ota_http_server.database import db_mysql_service, db_sqlite_service
from ota_http_server.database.database_service import DatabaseService

from .v1 import _error_payload

# Exception tuples covering both database backends, so route handlers can
# catch database-layer failures without knowing which backend is configured.
USER_NOT_FOUND = (
    db_sqlite_service.UserNotFoundError,
    db_mysql_service.UserNotFoundError,
)
USER_ALREADY_EXISTS = (
    db_sqlite_service.UserAlreadyExistsError,
    db_mysql_service.UserAlreadyExistsError,
)
USER_ALREADY_ENABLED = (
    db_sqlite_service.UserAlreadyEnabledError,
    db_mysql_service.UserAlreadyEnabledError,
)
USER_ALREADY_DISABLED = (
    db_sqlite_service.UserAlreadyDisabledError,
    db_mysql_service.UserAlreadyDisabledError,
)
PROJECT_NOT_FOUND = (
    db_sqlite_service.ProjectNotFoundError,
    db_mysql_service.ProjectNotFoundError,
)
PROJECT_ALREADY_EXISTS = (
    db_sqlite_service.ProjectAlreadyExistsError,
    db_mysql_service.ProjectAlreadyExistsError,
)
PROJECT_ALREADY_ENABLED = (
    db_sqlite_service.ProjectAlreadyEnabledError,
    db_mysql_service.ProjectAlreadyEnabledError,
)
PROJECT_ALREADY_DISABLED = (
    db_sqlite_service.ProjectAlreadyDisabledError,
    db_mysql_service.ProjectAlreadyDisabledError,
)
TARGET_NOT_FOUND = (
    db_sqlite_service.TargetNotFoundError,
    db_mysql_service.TargetNotFoundError,
)
DEVICE_NOT_FOUND = (
    db_sqlite_service.DeviceNotFoundError,
    db_mysql_service.DeviceNotFoundError,
)
DEVICE_ALREADY_EXISTS = (
    db_sqlite_service.DeviceAlreadyExistsError,
    db_mysql_service.DeviceAlreadyExistsError,
)
DEVICE_ALREADY_ENABLED = (
    db_sqlite_service.DeviceAlreadyEnabledError,
    db_mysql_service.DeviceAlreadyEnabledError,
)
DEVICE_ALREADY_DISABLED = (
    db_sqlite_service.DeviceAlreadyDisabledError,
    db_mysql_service.DeviceAlreadyDisabledError,
)
FIRMWARE_NOT_FOUND = (
    db_sqlite_service.FirmwareNotFoundError,
    db_mysql_service.FirmwareNotFoundError,
)
FIRMWARE_ALREADY_EXISTS = (
    db_sqlite_service.FirmwareAlreadyExistsError,
    db_mysql_service.FirmwareAlreadyExistsError,
)
DATABASE_ERROR = (
    db_sqlite_service.DatabaseError,
    db_mysql_service.DatabaseError,
)


def error_response(status_code: int, message: str):
    """Build a JSON error response in the standard API envelope."""
    return jsonify(_error_payload(status_code, message)), status_code


def get_db() -> DatabaseService:
    """Return the database service attached to the current application."""
    return current_app.extensions["db_service"]


def get_app_paths() -> AppPaths:
    """Return the application paths attached to the current application."""
    return current_app.extensions["app_paths"]


def json_body() -> dict[str, Any]:
    """Return the request JSON body, requiring a top-level object."""
    data = request.get_json(silent=True)
    if data is None:
        abort(400, "Request body must be valid JSON")
    if not isinstance(data, dict):
        abort(400, "Request body must be a JSON object")
    return data


def reject_unknown_fields(data: dict[str, Any], allowed: set[str]) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        abort(400, f"Unknown field(s): {', '.join(unknown)}")


def required_str(data: dict[str, Any], field: str) -> str:
    value = data.get(field)
    if not isinstance(value, str) or not value.strip():
        abort(400, f"Field '{field}' is required and must be a non-empty string")
    return value


def optional_str(data: dict[str, Any], field: str) -> str | None:
    value = data.get(field)
    if value is None:
        return None
    if not isinstance(value, str):
        abort(400, f"Field '{field}' must be a string")
    return value


def required_int(data: dict[str, Any], field: str) -> int:
    value = data.get(field)
    if isinstance(value, bool) or not isinstance(value, int):
        abort(400, f"Field '{field}' is required and must be an integer")
    return value


def optional_int(data: dict[str, Any], field: str) -> int | None:
    value = data.get(field)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        abort(400, f"Field '{field}' must be an integer")
    return value


def parse_state_filter() -> bool | None:
    """Parse the optional ?state=enabled|disabled query parameter."""
    state = request.args.get("state")
    if state is None:
        return None
    if state == "enabled":
        return True
    if state == "disabled":
        return False
    abort(400, "Invalid 'state' filter: expected 'enabled' or 'disabled'")


def parse_int_query_param(name: str) -> int | None:
    """Parse an optional integer query parameter."""
    raw = request.args.get(name)
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        abort(400, f"Invalid '{name}' filter: expected an integer")


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def user_to_dict(user: User) -> dict[str, Any]:
    """Serialize a user. The password hash is never exposed."""
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "is_active": user.is_active,
        "created_at": _iso(user.created_at),
        "updated_at": _iso(user.updated_at),
    }


def project_to_dict(project: Project) -> dict[str, Any]:
    return {
        "id": project.id,
        "name": project.name,
        "display_name": project.display_name,
        "description": project.description,
        "created_by": project.created_by,
        "is_active": project.is_active,
        "created_at": _iso(project.created_at),
        "updated_at": _iso(project.updated_at),
    }


def project_list_item_to_dict(item: ProjectListItem) -> dict[str, Any]:
    return {
        "id": item.id,
        "name": item.name,
        "display_name": item.display_name,
        "description": item.description,
        "created_by": item.created_by_username,
        "is_active": item.is_active,
    }


def device_to_dict(device: Device) -> dict[str, Any]:
    return {
        "id": device.id,
        "uuid": device.uuid,
        "project_id": device.project_id,
        "target_id": device.target_id,
        "model": device.model,
        "serial_number": device.serial_number,
        "current_version": device.current_version,
        "last_seen": _iso(device.last_seen),
        "is_active": device.is_active,
        "created_at": _iso(device.created_at),
        "updated_at": _iso(device.updated_at),
    }


def device_list_item_to_dict(item: DeviceListItem) -> dict[str, Any]:
    return {
        "id": item.id,
        "uuid": item.uuid,
        "project": item.project_name,
        "target": item.target_name,
        "model": item.model,
        "serial_number": item.serial_number,
        "current_version": item.current_version,
        "last_seen": _iso(item.last_seen),
        "is_active": item.is_active,
    }


def firmware_to_dict(firmware: Firmware) -> dict[str, Any]:
    return {
        "id": firmware.id,
        "project_id": firmware.project_id,
        "target_id": firmware.target_id,
        "version": firmware.version,
        "filename": firmware.filename,
        "file_size": firmware.file_size,
        "checksum": firmware.checksum,
        "release_notes": firmware.release_notes,
        "channel": firmware.channel,
        "is_active": firmware.is_active,
        "created_at": _iso(firmware.created_at),
        "updated_at": _iso(firmware.updated_at),
    }


def firmware_list_item_to_dict(item: FirmwareListItem) -> dict[str, Any]:
    return {
        "id": item.id,
        "project": item.project_name,
        "target": item.target_name,
        "version": item.version,
        "filename": item.filename,
        "file_size": item.file_size,
        "channel": item.channel,
        "is_active": item.is_active,
    }
