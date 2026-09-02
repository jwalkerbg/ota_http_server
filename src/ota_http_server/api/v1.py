"""Version 1 REST API blueprint."""

from __future__ import annotations

from datetime import UTC, datetime

from flask import Blueprint, current_app, jsonify, request
from werkzeug.exceptions import HTTPException

api_v1 = Blueprint("api_v1", __name__, url_prefix="/api/v1")


def _error_payload(status_code: int, message: str, *, error_type: str | None = None) -> dict[str, object]:
    payload: dict[str, object] = {
        "error": {
            "code": status_code,
            "message": message,
        }
    }
    if error_type is not None:
        payload["error"]["type"] = error_type
    return payload


def register_api_error_handlers(app):
    """Register API-specific JSON error handlers on the app."""

    @app.errorhandler(HTTPException)
    def handle_http_exception(exc: HTTPException):
        if not request.path.startswith("/api/"):
            return exc
        payload = _error_payload(
            exc.code or 500,
            exc.description or exc.name,
            error_type=exc.name,
        )
        return jsonify(payload), exc.code or 500

    @app.errorhandler(Exception)
    def handle_unexpected_error(exc: Exception):
        if not request.path.startswith("/api/"):
            raise exc
        current_app.logger.exception("Unhandled API error", exc_info=exc)
        payload = _error_payload(500, "Internal server error", error_type=exc.__class__.__name__)
        return jsonify(payload), 500


@api_v1.route("", methods=["GET"])
@api_v1.route("/", methods=["GET"])
def api_root() -> tuple[object, int]:
    return jsonify({
        "version": "v1",
        "status": "ok",
        "routes": {
            "status": "/api/v1/status",
        },
    }), 200


@api_v1.route("/status", methods=["GET"])
def api_status() -> tuple[object, int]:
    return jsonify({
        "status": "ok",
        "time": datetime.now(UTC).isoformat(),
    }), 200
