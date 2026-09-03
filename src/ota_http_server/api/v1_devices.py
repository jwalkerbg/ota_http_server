"""Device management routes for the v1 REST API."""

from __future__ import annotations

from flask import Blueprint, jsonify

from ota_http_server.core.data_models import Device
from ota_http_server.target.target_service import DEFAULT_TARGET_NAME

from .common import (
    DEVICE_ALREADY_DISABLED,
    DEVICE_ALREADY_ENABLED,
    DEVICE_ALREADY_EXISTS,
    DEVICE_NOT_FOUND,
    TARGET_NOT_FOUND,
    device_list_item_to_dict,
    device_to_dict,
    error_response,
    get_db,
    json_body,
    optional_int,
    optional_str,
    parse_int_query_param,
    parse_state_filter,
    reject_unknown_fields,
    required_int,
    required_str,
)

api_v1_devices = Blueprint("api_v1_devices", __name__, url_prefix="/api/v1/devices")


def _resolve_target_id(target_id: int | None) -> int:
    """Resolve an explicit target id or fall back to the default target."""
    db = get_db()
    if target_id is not None:
        target = db.target_get_by_id(target_id)
        if target is None:
            raise ValueError(f"Target with ID {target_id} does not exist")
        return target.id

    target = db.target_get_by_name(DEFAULT_TARGET_NAME)
    if target is None:
        raise ValueError(f"Target with name '{DEFAULT_TARGET_NAME}' does not exist")
    return target.id


@api_v1_devices.route("", methods=["GET"])
@api_v1_devices.route("/", methods=["GET"])
def list_devices():
    """List devices, optionally filtered by ?projectid= and ?state=."""
    devices = get_db().device_get_list(
        is_active=parse_state_filter(),
        project_id=parse_int_query_param("projectid"),
    )
    return jsonify({"devices": [device_list_item_to_dict(d) for d in devices]}), 200


@api_v1_devices.route("", methods=["POST"])
@api_v1_devices.route("/", methods=["POST"])
def create_device():
    data = json_body()
    reject_unknown_fields(
        data,
        {"uuid", "project_id", "target_id", "model", "serial_number", "current_version"},
    )

    uuid = required_str(data, "uuid")
    project_id = required_int(data, "project_id")
    model = optional_str(data, "model") or "Unknown"
    serial_number = optional_str(data, "serial_number")
    current_version = optional_str(data, "current_version") or "0.0.0"

    try:
        target_id = _resolve_target_id(optional_int(data, "target_id"))
    except ValueError as exc:
        return error_response(400, str(exc))

    device = Device(
        id=None,
        uuid=uuid,
        project_id=project_id,
        target_id=target_id,
        model=model,
        serial_number=serial_number,
        current_version=current_version,
        last_seen=None,
        is_active=True,
        created_at=None,
        updated_at=None,
    )

    try:
        created = get_db().device_add(device)
    except DEVICE_ALREADY_EXISTS as exc:
        return error_response(409, str(exc))
    except TARGET_NOT_FOUND as exc:
        # a referenced project or target foreign key does not exist
        return error_response(400, str(exc))

    return jsonify(device_to_dict(created)), 201


@api_v1_devices.route("/<int:device_id>", methods=["GET"])
def get_device(device_id: int):
    device = get_db().device_get_by_id(device_id)
    if device is None:
        return error_response(404, f"Device id={device_id} not found")
    return jsonify(device_to_dict(device)), 200


@api_v1_devices.route("/<int:device_id>", methods=["PATCH"])
def update_device(device_id: int):
    data = json_body()
    reject_unknown_fields(
        data,
        {"project_id", "target_id", "model", "serial_number", "current_version"},
    )

    try:
        updated = get_db().device_update_by_id(
            device_id,
            project_id=optional_int(data, "project_id"),
            target_id=optional_int(data, "target_id"),
            model=optional_str(data, "model"),
            serial_number=optional_str(data, "serial_number"),
            current_version=optional_str(data, "current_version"),
        )
    except ValueError as exc:
        return error_response(400, str(exc))
    except DEVICE_NOT_FOUND as exc:
        return error_response(404, str(exc))
    except DEVICE_ALREADY_EXISTS as exc:
        return error_response(409, str(exc))
    except TARGET_NOT_FOUND as exc:
        return error_response(400, str(exc))

    return jsonify(device_to_dict(updated)), 200


def _set_device_active(device_id: int, active: bool) -> tuple[object, int]:
    db = get_db()
    try:
        if active:
            db.device_enable_by_id(device_id)
        else:
            db.device_disable_by_id(device_id)
    except DEVICE_NOT_FOUND as exc:
        return error_response(404, str(exc))
    except DEVICE_ALREADY_ENABLED as exc:
        return error_response(409, str(exc))
    except DEVICE_ALREADY_DISABLED as exc:
        return error_response(409, str(exc))

    state = "activated" if active else "deactivated"
    return jsonify({"id": device_id, "is_active": active, "message": f"Device {state}"}), 200


@api_v1_devices.route("/<int:device_id>", methods=["DELETE"])
def deactivate_device(device_id: int):
    """DELETE deactivates the device; the record and its audit history are kept."""
    return _set_device_active(device_id, False)


@api_v1_devices.route("/<int:device_id>/activate", methods=["POST"])
def activate_device(device_id: int):
    return _set_device_active(device_id, True)


@api_v1_devices.route("/<int:device_id>/deactivate", methods=["POST"])
def deactivate_device_action(device_id: int):
    return _set_device_active(device_id, False)
