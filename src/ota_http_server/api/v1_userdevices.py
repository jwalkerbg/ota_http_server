"""User-device permission routes for the v1 REST API."""

from __future__ import annotations

from datetime import UTC, datetime

from flask import Blueprint, abort, jsonify, request

from ota_http_server.core.data_models import UserDevice

from .authorization import (
    USERDEVICES_CREATE,
    USERDEVICES_DELETE,
    USERDEVICES_READ,
    USERDEVICES_UPDATE,
    require_permission,
)
from .common import (
    USER_DEVICE_ALREADY_EXISTS,
    USER_DEVICE_NOT_FOUND,
    error_response,
    get_db,
    json_body,
    optional_int,
    optional_str,
    parse_int_query_param,
    reject_unknown_fields,
    user_device_to_dict,
)

api_v1_userdevices = Blueprint("api_v1_userdevices", __name__, url_prefix="/api/v1/userdevices")


def _parse_expires(value: str | None) -> datetime | None:
    if value is None:
        return None
    normalized = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        timestamp = datetime.fromisoformat(normalized)
    except ValueError:
        abort(
            400,
            "Field 'expires_at' must be an ISO 8601 timestamp, for example "
            "2026-09-18T12:30:00+00:00",
        )
    return timestamp.replace(tzinfo=UTC) if timestamp.tzinfo is None else timestamp


def _resolve_ids(user_id: int | None, username: str | None, device_id: int | None, device_uuid: str | None) -> tuple[int, int]:
    """Resolve a user/device identification pair to their numeric IDs."""
    if (user_id is None) == (username is None):
        abort(400, "Exactly one of 'user_id' or 'username' must be provided")
    if (device_id is None) == (device_uuid is None):
        abort(400, "Exactly one of 'device_id' or 'device_uuid' must be provided")

    db = get_db()

    if user_id is None:
        user = db.user_get_by_username(username)
        if user is None:
            abort(404, f"User '{username}' not found")
        user_id = user.id
    elif db.user_get_by_id(user_id) is None:
        abort(404, f"User with ID {user_id} not found")

    if device_id is None:
        device = db.device_get_by_name(device_uuid)
        if device is None:
            abort(404, f"Device '{device_uuid}' not found")
        device_id = device.id
    elif db.device_get_by_id(device_id) is None:
        abort(404, f"Device with ID {device_id} not found")

    return user_id, device_id


def _resolve_ids_from_query() -> tuple[int, int]:
    return _resolve_ids(
        parse_int_query_param("userid"),
        request.args.get("username"),
        parse_int_query_param("devid"),
        request.args.get("devuuid"),
    )


@api_v1_userdevices.route("", methods=["POST"])
@api_v1_userdevices.route("/", methods=["POST"])
@require_permission(USERDEVICES_CREATE)
def create_user_device():
    data = json_body()
    reject_unknown_fields(
        data,
        {"user_id", "username", "device_id", "device_uuid", "expires_at"},
    )

    user_id, device_id = _resolve_ids(
        optional_int(data, "user_id"),
        optional_str(data, "username"),
        optional_int(data, "device_id"),
        optional_str(data, "device_uuid"),
    )
    expires_at = _parse_expires(optional_str(data, "expires_at"))

    assignment = UserDevice(user_id, device_id, None, expires_at)
    try:
        created = get_db().user_device_add(assignment)
    except USER_DEVICE_ALREADY_EXISTS as exc:
        return error_response(409, str(exc))

    return jsonify(user_device_to_dict(created)), 201


@api_v1_userdevices.route("", methods=["GET"])
@api_v1_userdevices.route("/", methods=["GET"])
@require_permission(USERDEVICES_READ)
def get_user_device():
    """Get a user-device assignment identified by ?userid=|?username= and ?devid=|?devuuid=."""
    user_id, device_id = _resolve_ids_from_query()
    assignment = get_db().user_device_get(user_id, device_id)
    if assignment is None:
        return error_response(404, "User-device assignment not found")
    return jsonify(user_device_to_dict(assignment)), 200


@api_v1_userdevices.route("/expiration", methods=["GET"])
@require_permission(USERDEVICES_READ)
def get_user_device_expiration():
    """Report whether a user-device assignment is expired."""
    user_id, device_id = _resolve_ids_from_query()
    try:
        expired = get_db().user_device_is_expired(user_id, device_id)
    except USER_DEVICE_NOT_FOUND as exc:
        return error_response(404, str(exc))
    return jsonify({"user_id": user_id, "device_id": device_id, "expired": expired}), 200


@api_v1_userdevices.route("", methods=["PATCH"])
@api_v1_userdevices.route("/", methods=["PATCH"])
@require_permission(USERDEVICES_UPDATE)
def set_user_device_expiry():
    """Set or clear the expiry of a user-device assignment.

    Identify the assignment via ?userid=|?username= and ?devid=|?devuuid=.
    Omitting 'expires_at' (or setting it to null) removes the existing expiry.
    """
    user_id, device_id = _resolve_ids_from_query()
    data = json_body()
    reject_unknown_fields(data, {"expires_at"})
    expires_at = _parse_expires(optional_str(data, "expires_at"))

    try:
        updated = get_db().user_device_set_expiry(user_id, device_id, expires_at)
    except USER_DEVICE_NOT_FOUND as exc:
        return error_response(404, str(exc))

    return jsonify(user_device_to_dict(updated)), 200


@api_v1_userdevices.route("", methods=["DELETE"])
@api_v1_userdevices.route("/", methods=["DELETE"])
@require_permission(USERDEVICES_DELETE)
def delete_user_device():
    """Delete a user-device assignment identified by ?userid=|?username= and ?devid=|?devuuid=."""
    user_id, device_id = _resolve_ids_from_query()
    try:
        get_db().user_device_delete(user_id, device_id)
    except USER_DEVICE_NOT_FOUND as exc:
        return error_response(404, str(exc))

    return jsonify({
        "user_id": user_id,
        "device_id": device_id,
        "message": "User-device assignment deleted",
    }), 200
