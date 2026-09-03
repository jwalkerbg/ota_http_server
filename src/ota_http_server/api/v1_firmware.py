"""Firmware management routes for the v1 REST API."""

from __future__ import annotations

import hashlib
from pathlib import Path

from flask import Blueprint, jsonify, request, send_file

from ota_http_server.core.data_models import Firmware
from ota_http_server.firmware.filename_validation import validate_firmware_filename
from ota_http_server.target.target_service import DEFAULT_TARGET_NAME

from .common import (
    FIRMWARE_ALREADY_EXISTS,
    FIRMWARE_NOT_FOUND,
    TARGET_NOT_FOUND,
    error_response,
    firmware_list_item_to_dict,
    firmware_to_dict,
    get_app_paths,
    get_db,
    json_body,
    optional_int,
    optional_str,
    parse_int_query_param,
    parse_state_filter,
    reject_unknown_fields,
)

api_v1_firmware = Blueprint("api_v1_firmware", __name__, url_prefix="/api/v1/firmware")

FIRMWARE_CHANNELS = ("stable", "beta", "dev")


def _save_with_sha256(stream, destination: Path) -> str:
    """Write the upload stream to destination, returning its SHA-256 hex digest."""
    digest = hashlib.sha256()
    with destination.open("wb") as out:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            out.write(chunk)
    return digest.hexdigest()


@api_v1_firmware.route("", methods=["GET"])
@api_v1_firmware.route("/", methods=["GET"])
def list_firmware():
    """List firmware versions, optionally filtered by ?projectid= and ?state=."""
    firmware = get_db().firmware_get_list(
        is_active=parse_state_filter(),
        project_id=parse_int_query_param("projectid"),
    )
    return jsonify({"firmware": [firmware_list_item_to_dict(f) for f in firmware]}), 200


@api_v1_firmware.route("", methods=["POST"])
@api_v1_firmware.route("/", methods=["POST"])
def upload_firmware():
    """Upload a firmware image as multipart/form-data with a 'file' part."""
    db = get_db()
    form = request.form

    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return error_response(400, "Form field 'file' with a firmware image is required")

    version = form.get("version")
    if not version or not version.strip():
        return error_response(400, "Form field 'version' is required")

    raw_project_id = form.get("project_id")
    try:
        project_id = int(raw_project_id) if raw_project_id is not None else None
    except ValueError:
        return error_response(400, "Form field 'project_id' must be an integer")
    if project_id is None:
        return error_response(400, "Form field 'project_id' is required")

    raw_target_id = form.get("target_id")
    try:
        target_id = int(raw_target_id) if raw_target_id is not None else None
    except ValueError:
        return error_response(400, "Form field 'target_id' must be an integer")

    channel = form.get("channel") or "stable"
    if channel not in FIRMWARE_CHANNELS:
        return error_response(
            400, f"Form field 'channel' must be one of: {', '.join(FIRMWARE_CHANNELS)}"
        )

    release_notes = form.get("release_notes") or ""

    project = db.project_get_by_id(project_id)
    if project is None:
        return error_response(400, f"Project with ID {project_id} does not exist")

    if target_id is not None:
        target = db.target_get_by_id(target_id)
        if target is None:
            return error_response(400, f"Target with ID {target_id} does not exist")
    else:
        target = db.target_get_by_name(DEFAULT_TARGET_NAME)
        if target is None:
            return error_response(500, f"Default target '{DEFAULT_TARGET_NAME}' does not exist")
        target_id = target.id

    try:
        validate_firmware_filename(upload.filename)
    except ValueError as exc:
        return error_response(400, str(exc))

    if db.firmware_get_by_project_version_target(
        project_id=project_id,
        version=version,
        target_id=target_id,
    ) is not None:
        return error_response(
            409,
            f"Firmware already exists for project_id={project_id}, version={version}, target_id={target_id}",
        )

    app_paths = get_app_paths()
    project_dir = app_paths.ensure_project_dir(project.name)
    destination_path = (project_dir / upload.filename).resolve()

    if destination_path.exists():
        return error_response(
            409, f"Firmware file already exists: {destination_path.name}"
        )

    checksum = _save_with_sha256(upload.stream, destination_path)

    firmware = Firmware(
        id=None,
        project_id=project_id,
        target_id=target_id,
        version=version,
        filename=destination_path.name,
        file_size=destination_path.stat().st_size,
        checksum=checksum,
        release_notes=release_notes,
        channel=channel,
        is_active=True,
        created_at=None,
        updated_at=None,
    )

    try:
        created = db.firmware_add(firmware)
    except FIRMWARE_ALREADY_EXISTS as exc:
        destination_path.unlink(missing_ok=True)
        return error_response(409, str(exc))
    except TARGET_NOT_FOUND as exc:
        destination_path.unlink(missing_ok=True)
        return error_response(400, str(exc))

    return jsonify(firmware_to_dict(created)), 201


@api_v1_firmware.route("/<int:firmware_id>", methods=["GET"])
def get_firmware(firmware_id: int):
    firmware = get_db().firmware_get_by_id(firmware_id)
    if firmware is None:
        return error_response(404, f"Firmware id={firmware_id} not found")
    return jsonify(firmware_to_dict(firmware)), 200


@api_v1_firmware.route("/<int:firmware_id>", methods=["PATCH"])
def update_firmware(firmware_id: int):
    """Update firmware metadata (version, release_notes, channel, target_id)."""
    data = json_body()
    reject_unknown_fields(data, {"version", "release_notes", "channel", "target_id"})

    channel = optional_str(data, "channel")
    if channel is not None and channel not in FIRMWARE_CHANNELS:
        return error_response(
            400, f"Field 'channel' must be one of: {', '.join(FIRMWARE_CHANNELS)}"
        )

    try:
        updated = get_db().firmware_update_by_id(
            firmware_id,
            version=optional_str(data, "version"),
            release_notes=optional_str(data, "release_notes"),
            channel=channel,
            target_id=optional_int(data, "target_id"),
        )
    except ValueError as exc:
        return error_response(400, str(exc))
    except FIRMWARE_NOT_FOUND as exc:
        return error_response(404, str(exc))
    except FIRMWARE_ALREADY_EXISTS as exc:
        return error_response(409, str(exc))
    except TARGET_NOT_FOUND as exc:
        return error_response(400, str(exc))

    return jsonify(firmware_to_dict(updated)), 200


@api_v1_firmware.route("/<int:firmware_id>", methods=["DELETE"])
def delete_firmware(firmware_id: int):
    """Delete a firmware release: removes the database record and the image file."""
    db = get_db()
    try:
        deleted = db.firmware_delete_by_id(firmware_id)
    except FIRMWARE_NOT_FOUND as exc:
        return error_response(404, str(exc))

    app_paths = get_app_paths()
    try:
        validate_firmware_filename(deleted.filename)
    except ValueError:
        return error_response(500, "Stored firmware filename is not safe to remove")

    project_dir = app_paths.project_dir(deleted.project_name).resolve()
    firmware_file_path = (project_dir / deleted.filename).resolve()
    if firmware_file_path.parent != project_dir:
        return error_response(500, "Stored firmware filename is not safe to remove")

    if firmware_file_path.exists():
        firmware_file_path.unlink()

    return jsonify({"id": firmware_id, "message": "Firmware deleted"}), 200


@api_v1_firmware.route("/<int:firmware_id>/download", methods=["GET"])
def download_firmware(firmware_id: int):
    db = get_db()
    firmware = db.firmware_get_by_id(firmware_id)
    if firmware is None:
        return error_response(404, f"Firmware id={firmware_id} not found")

    project = db.project_get_by_id(firmware.project_id)
    if project is None:
        return error_response(404, f"Project id={firmware.project_id} not found")

    try:
        validate_firmware_filename(firmware.filename)
    except ValueError:
        return error_response(500, "Stored firmware filename is not safe to serve")

    project_dir = get_app_paths().project_dir(project.name).resolve()
    firmware_file_path = (project_dir / firmware.filename).resolve()
    if firmware_file_path.parent != project_dir or not firmware_file_path.is_file():
        return error_response(404, "Firmware image file not found")

    return send_file(
        firmware_file_path,
        as_attachment=True,
        download_name=firmware.filename,
    )
