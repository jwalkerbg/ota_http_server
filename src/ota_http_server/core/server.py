# core/server.py

from typing import Any, Dict
import csv
import os
import sys
import re
from pathlib import Path
from datetime import datetime, timedelta, timezone
from flask import Flask, Response, send_file, request, abort, jsonify, current_app
from packaging import version
import hmac
from uuid import UUID
# Check Python version at runtime
if sys.version_info >= (3, 11):
    import tomllib as toml # Use the built-in tomllib for Python 3.11+
else:
    import tomli as toml # Use the external tomli for Python 3.7 to 3.10

from .dataclasses import TokenResult
from .auth_service import AuthService
from ota_http_server.logger import get_app_logger

logger = get_app_logger(__name__)

# -------------------------------------------------------------------
#                       APP FACTORY
# -------------------------------------------------------------------

def create_app(www_dir:str,                 # pylint: disable=too-many-positional-arguments,too-many-locals,too-many-statements
               firmware_dir:str,
               url_firmware:str,
               use_jwt:bool,
               jwt_algorithm:str,
               jwt_expiry:int,
               jwt_max_expiry:int,
               jwt_secret:str|None,
               jwt_issuer:str|None,
               jwt_audience:str|None,
               admin_secret:str|None,
               ota_audit_log:str,
               ota_db_file:str,
               ota_db_cache_ttl:int) -> Flask:

    # Print argument names and values
    logger.info("create_app() called with:")
    for name, value in locals().items():
        logger.info(f" %s = %r", name, value)

    if use_jwt and (not jwt_secret or not admin_secret):
        raise ValueError("JWT is enabled but jwt_secret or admin_secret is not set")

    authservice = AuthService(use_jwt=use_jwt,
                              jwt_secret=jwt_secret,
                              jwt_algorithm=jwt_algorithm,
                              jwt_audience=jwt_audience,
                              jwt_issuer=jwt_issuer,
                              jwt_expiry=jwt_expiry,
                              jwt_max_expiry=jwt_max_expiry
                            )

    def load_ota_db() -> Dict[str, Any]:
        app = current_app
        now = datetime.now()

        if app.config["OTA_DB"] is None or (now - app.config["OTA_DB_LAST_LOAD"]) > app.config["OTA_DB_CACHE_TTL"]:
            try:
                with open(app.config["OTA_DB_FILE"], 'rb') as f:
                    app.config["OTA_DB"] = toml.load(f)
                    app.config["OTA_DB_LAST_LOAD"] = now
            except (FileNotFoundError, toml.TOMLDecodeError) as e:
                logger.info("Failed to load OTA database: %s", e)
                return {}
        return app.config["OTA_DB"]

    #
    # Flask app factory with JWT authentication and secure admin endpoint.
    #
    app = Flask(__name__.split('.', maxsplit=1)[0])

    app.config["OTA_DB_FILE"] = ota_db_file
    app.config["OTA_DB"] = None
    app.config["OTA_DB_LAST_LOAD"] = 0
    app.config["OTA_DB_CACHE_TTL"] = timedelta(seconds=ota_db_cache_ttl)  # seconds
    with app.app_context():
        load_ota_db()

    # ---------------------------------------------------------------
    #                       HELPER FUNCTIONS
    # ---------------------------------------------------------------

    def get_sorted_versions(project:str) -> tuple[str, list[str], list[tuple[str, str]]]:
        """Return sorted list of versions for a given project."""

        project_path = (Path(www_dir) / firmware_dir / project).resolve()
        if not project_path.is_dir():
            abort(404, "Project not found")

        pattern = re.compile(r"(\d+\.\d+\.\d+)")
        versions = []
        version_files = []

        for file_path in project_path.iterdir():
            if file_path.is_file() and file_path.suffix == ".json":
                match = pattern.search(file_path.name)
                if match:
                    ver = match.group(1)
                    versions.append(ver)
                    version_files.append((file_path.name, ver))

        if not versions:
            abort(404, "No versions found")

        version_files.sort(key=lambda x: version.parse(x[1]))
        sorted_versions = [v for _, v in version_files]
        return str(project_path), sorted_versions, version_files

    def log_audit_event(ip:str|None, action:str, details:str) -> None:
        """Append a token generation audit log entry."""
        timestamp = datetime.now(timezone.utc).isoformat()
        os.makedirs(os.path.dirname(ota_audit_log) or ".", exist_ok=True)
        new_file = not os.path.exists(ota_audit_log)
        with open(ota_audit_log, "a", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            if new_file:
                writer.writerow(["timestamp", "ip", "action", "details"])
            writer.writerow([timestamp, ip, action, details])
        logger.info(f"[AUDIT] %s | %s | %s | %s", timestamp, ip, action, details)

    def is_device_in_project(db, project: str, device_id: str) -> bool:
        devices = db.get("projects", {}).get(project, {}).get("devices", [])
        return any(d["uuid"] == device_id for d in devices)

    def has_firmware_access(db, project: str, device_id: str) -> bool:
        devices = db.get("projects", {}).get(project, {}).get("devices", [])

        for d in devices:
            if d["uuid"] == device_id:
                return d.get("fw_access", False)

        return False

    # ---------------------------------------------------------------
    #                          ROUTES
    # ---------------------------------------------------------------

    @app.route(f'/{url_firmware}/<project>/<path:filename>')
    def firmware(project:str, filename:str) -> Response:
        if use_jwt:
            # 1. Decode JWT
            payload = authservice.verify_token(project, verify_sub=True)
            # 2. Extract identity
            device_id = payload["sub"]
            project = payload["project"]
            # 3. Load authorization DB
            db = load_ota_db()
            # 4. Check membership
            if not is_device_in_project(db, project, device_id):
                abort(403, "Device not registered for project")
            # 5. Check firmware permission
            if not has_firmware_access(db, project, device_id):
                abort(403, "Device not allowed to download firmware")

        file_path = (Path(www_dir) / Path(firmware_dir) / Path(project) / Path(filename)).resolve()
        logger.info("Serving firmware from: %s", file_path)
        if not file_path.is_file():
            abort(404, "Firmware file not found")
        return send_file(file_path, conditional=True)

    @app.route(f'/{url_firmware}/<project>/latest')
    def latest_firmware(project:str) -> Response:
        authservice.verify_token(project, verify_sub=False)  # Allow latest version check without device identity, but still require valid token for project
        project_dir, _, version_files = get_sorted_versions(project)
        latest_file, _ = version_files[-1]
        file_path = (Path(project_dir) / latest_file).resolve()
        return send_file(file_path, conditional=True)

    @app.route(f'/{url_firmware}/<project>/versions')
    def list_versions(project:str) -> Response:
        authservice.verify_token(project, verify_sub=False)  # Allow version listing without device identity, but still require valid token for project
        _, versions, _ = get_sorted_versions(project)
        return jsonify({
            "versions": versions,
            "count": len(versions),
            "latest": versions[-1]
        })

    @app.route("/status")
    def status() -> Response:
        return jsonify({
            "status": "ok",
            "time": datetime.now(timezone.utc).isoformat()
        })

    # ---------------------------------------------------------------
    #                      ADMIN TOKEN GENERATOR
    # ---------------------------------------------------------------

    @app.route("/admin/generate_token", methods=["POST"])
    def admin_generate_token() -> Response:
        """
        Generates a JWT dynamically for a device.
        Requires header: X-Admin-Secret=<ADMIN_SECRET>
        Body JSON:
            {
              "device_id": "uuid-v4",
              "project": "project_name",
              "expires_seconds": jwt_expiry,
              "current_vs": "1.0.0",
              "download_vs": "2.0.0"
            }
        """
        admin_header = request.headers.get("X-Admin-Secret")
        if not admin_header or not hmac.compare_digest(admin_header, admin_secret):
            abort(403, "Invalid or missing admin secret")

        data = request.get_json(silent=True)
        if not data:
            abort(400, "Missing JSON body")

        token_result = authservice.create_device_token(data)

        # Audit logging
        log_audit_event(
            ip=request.remote_addr,
            action="generate_token",
            details=f"device={token_result.payload.get('sub','')}, project={token_result.payload.get('project','')}, exp={token_result.payload.get('exp','')}"
        )

        return jsonify({
            "token": token_result.token,
            "expires_at": datetime.fromtimestamp(token_result.payload["exp"], tz=timezone.utc).isoformat(),
            "payload": token_result.payload
        })

    return app
