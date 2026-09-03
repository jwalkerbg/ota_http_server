"""Project management routes for the v1 REST API."""

from __future__ import annotations

from flask import Blueprint, abort, jsonify, request

from ota_http_server.core.data_models import Project

from .common import (
    PROJECT_ALREADY_DISABLED,
    PROJECT_ALREADY_ENABLED,
    PROJECT_ALREADY_EXISTS,
    PROJECT_NOT_FOUND,
    USER_NOT_FOUND,
    error_response,
    get_db,
    json_body,
    optional_str,
    parse_int_query_param,
    parse_state_filter,
    project_list_item_to_dict,
    project_to_dict,
    reject_unknown_fields,
    required_int,
    required_str,
)

api_v1_projects = Blueprint("api_v1_projects", __name__, url_prefix="/api/v1/projects")


@api_v1_projects.route("", methods=["GET"])
@api_v1_projects.route("/", methods=["GET"])
def list_projects():
    """List projects, optionally filtered by ?userid=, ?username= and ?state=."""
    created_by = parse_int_query_param("userid")
    created_by_username = request.args.get("username")
    if created_by is not None and created_by_username is not None:
        abort(400, "Filters 'userid' and 'username' are mutually exclusive")

    projects = get_db().project_get_list(
        is_active=parse_state_filter(),
        created_by=created_by,
        created_by_username=created_by_username,
    )
    return jsonify({"projects": [project_list_item_to_dict(p) for p in projects]}), 200


@api_v1_projects.route("", methods=["POST"])
@api_v1_projects.route("/", methods=["POST"])
def create_project():
    data = json_body()
    reject_unknown_fields(data, {"name", "display_name", "description", "created_by"})

    name = required_str(data, "name")
    display_name = optional_str(data, "display_name") or ""
    description = optional_str(data, "description") or ""
    created_by = required_int(data, "created_by")

    project = Project(
        id=None,
        name=name,
        display_name=display_name,
        description=description,
        created_by=created_by,
        is_active=True,
        created_at=None,
        updated_at=None,
    )

    try:
        created = get_db().project_add(project)
    except PROJECT_ALREADY_EXISTS as exc:
        return error_response(409, str(exc))
    except USER_NOT_FOUND + PROJECT_NOT_FOUND as exc:
        # the created_by foreign key references a missing user
        return error_response(400, str(exc))

    return jsonify(project_to_dict(created)), 201


@api_v1_projects.route("/<int:project_id>", methods=["GET"])
def get_project(project_id: int):
    project = get_db().project_get_by_id(project_id)
    if project is None:
        return error_response(404, f"Project id={project_id} not found")
    return jsonify(project_to_dict(project)), 200


@api_v1_projects.route("/<int:project_id>", methods=["PATCH"])
def update_project(project_id: int):
    data = json_body()
    reject_unknown_fields(data, {"name", "display_name", "description"})

    name = optional_str(data, "name")
    display_name = optional_str(data, "display_name")
    description = optional_str(data, "description")

    try:
        updated = get_db().project_update_by_id(
            project_id,
            name=name,
            display_name=display_name,
            description=description,
        )
    except ValueError as exc:
        return error_response(400, str(exc))
    except PROJECT_NOT_FOUND as exc:
        return error_response(404, str(exc))
    except PROJECT_ALREADY_EXISTS as exc:
        return error_response(409, str(exc))

    return jsonify(project_to_dict(updated)), 200


def _set_project_active(project_id: int, active: bool) -> tuple[object, int]:
    db = get_db()
    try:
        if active:
            db.project_enable_by_id(project_id)
        else:
            db.project_disable_by_id(project_id)
    except PROJECT_NOT_FOUND as exc:
        return error_response(404, str(exc))
    except PROJECT_ALREADY_ENABLED as exc:
        return error_response(409, str(exc))
    except PROJECT_ALREADY_DISABLED as exc:
        return error_response(409, str(exc))

    state = "activated" if active else "deactivated"
    return jsonify({"id": project_id, "is_active": active, "message": f"Project {state}"}), 200


@api_v1_projects.route("/<int:project_id>", methods=["DELETE"])
def deactivate_project(project_id: int):
    """DELETE deactivates the project; the record and its audit history are kept."""
    return _set_project_active(project_id, False)


@api_v1_projects.route("/<int:project_id>/activate", methods=["POST"])
def activate_project(project_id: int):
    return _set_project_active(project_id, True)


@api_v1_projects.route("/<int:project_id>/deactivate", methods=["POST"])
def deactivate_project_action(project_id: int):
    return _set_project_active(project_id, False)
