# core/server.py

import csv
import os
import re
from pathlib import Path
from datetime import datetime, timezone, UTC
from flask import Flask, Response, send_file, request, abort, jsonify
from packaging import version
import hmac

from .data_models import TokenResult
from .auth_service import AuthService
from ota_http_server.database.database_service import DatabaseService
from ota_http_server.logger import get_app_logger
from ota_http_server.core.config import Config

logger = get_app_logger(__name__)

# -------------------------------------------------------------------
#                       APP FACTORY
# -------------------------------------------------------------------

def create_app(cfg: Config) -> Flask:

    # Print argument names and values
    logger.info("create_app() called with:")
    for name, value in locals().items():
        logger.info(f" %s = %r", name, value)

    www_dir=cfg.config['parameters']['www_dir']
    firmware_dir=cfg.config['parameters']['firmware_dir']
    url_firmware=cfg.config['parameters']['url_firmware']
    use_jwt=not cfg.config['parameters']['no_jwt']
    jwt_algorithm=cfg.config['parameters']['jwt_alg']
    jwt_expiry=int(cfg.config['parameters']['jwt_expiry'])
    jwt_max_expiry=int(cfg.config['parameters']['jwt_max_expiry'])
    jwt_secret=cfg.config['parameters']['jwt_secret']
    jwt_issuer=cfg.config['parameters']['jwt_issuer']
    jwt_audience=cfg.config['parameters']['jwt_audience']
    admin_secret=cfg.config['parameters']['admin_secret']
    ota_audit_log=cfg.config['parameters']['ota_audit_log']

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
    dbservice = DatabaseService(cfg)  # Placeholder for future database service integration

    #
    # Flask app factory with JWT authentication and secure admin endpoint.
    #
    app = Flask(__name__.split('.', maxsplit=1)[0])

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
        timestamp = datetime.now(UTC).isoformat()
        os.makedirs(os.path.dirname(ota_audit_log) or ".", exist_ok=True)
        new_file = not os.path.exists(ota_audit_log)
        with open(ota_audit_log, "a", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            if new_file:
                writer.writerow(["timestamp", "ip", "action", "details"])
            writer.writerow([timestamp, ip, action, details])
        logger.info(f"[AUDIT] %s | %s | %s | %s", timestamp, ip, action, details)

    # ---------------------------------------------------------------
    #                          ROUTES
    # ---------------------------------------------------------------

    @app.route(f'/{url_firmware}/<project>/<version>')
    def firmware(project:str, version:str) -> Response:
        project_rec = dbservice.project_get_by_name(project)
        if project_rec is None:
            abort(404, "Project not found")
        if not project_rec.is_active:
            abort(403, "Project is disabled")

        if use_jwt:
            # 1. Decode JWT
            payload = authservice.verify_token(project, verify_sub=True)
            # 2. Extract identity
            device_id = payload["sub"]

            # 3. Check membership
            device_rec = dbservice.device_get_by_name(device_id)
            if device_rec is None or device_rec.project_id != project_rec.id:
                abort(403, "Device not registered for project")
            # 4. Check device permission
            if not device_rec.is_active:
                abort(403, "Device not allowed to download firmware")

        firmware_rec = dbservice.firmware_get_by_project_version(
            project_id=project_rec.id,
            version=version,
        )
        if firmware_rec is None:
            abort(404, "Firmware metadata not found")
        if not firmware_rec.is_active:
            abort(403, "Firmware is disabled")

        filename = firmware_rec.filename

        app_paths = cfg.config['parameters']['app_paths']
        project_dir = app_paths.project_dir(project).resolve()
        file_path = (project_dir / Path(filename)).resolve()

        logger.info("Serving firmware from: %s", file_path)
        if not file_path.is_file():
            abort(404, "Firmware file not found")
        return send_file(file_path, conditional=True)

    @app.route(f'/{url_firmware}/<project>/latest')
    def latest_firmware(project:str) -> Response:
        project_rec = dbservice.project_get_by_name(project)
        if project_rec is None:
            abort(404, "Project not found")
        if not project_rec.is_active:
            abort(403, "Project is disabled")

        if use_jwt:
            # 1. Decode JWT
            payload = authservice.verify_token(project, verify_sub=True)
            # 2. Extract identity
            device_id = payload["sub"]

            # 3. Check membership
            device_rec = dbservice.device_get_by_name(device_id)
            if device_rec is None or device_rec.project_id != project_rec.id:
                abort(403, "Device not registered for project")
            # 4. Check device permission
            if not device_rec.is_active:
                abort(403, "Device not allowed to download firmware")

        firmware_records = [
            fw for fw in dbservice.firmware_get_record()
            if fw.project_id == project_rec.id
        ]
        if not firmware_records:
            abort(404, "No firmware metadata found for project")

        latest_firmware_rec = max(firmware_records, key=lambda fw: fw.version)
        if not latest_firmware_rec.is_active:
            abort(403, "Latest firmware is disabled")

        app_paths = cfg.config['parameters']['app_paths']
        project_dir = app_paths.project_dir(project).resolve()
        file_path = (project_dir / Path(latest_firmware_rec.filename)).resolve()

        logger.info("Serving firmware from: %s", file_path)
        if not file_path.is_file():
            abort(404, "Firmware file not found")

        return send_file(file_path, conditional=True)

    @app.route(f'/{url_firmware}/<project>/versions')
    def list_versions(project:str) -> Response:
        project_rec = dbservice.project_get_by_name(project)
        if project_rec is None:
            abort(404, "Project not found")
        if not project_rec.is_active:
            abort(403, "Project is disabled")

        if use_jwt:
            authservice.verify_token(project, verify_sub=False)

        firmware_records = [
            fw for fw in dbservice.firmware_get_record()
            if fw.project_id == project_rec.id
        ]
        if not firmware_records:
            abort(404, "No firmware metadata found for project")

        versions = sorted(fw.version for fw in firmware_records)
        return jsonify({
            "versions": versions,
            "count": len(versions),
            "latest": versions[-1]
        })

    @app.route("/status")
    def status() -> Response:
        return jsonify({
            "status": "ok",
            "time": datetime.now(UTC).isoformat()
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

        token_result:TokenResult = authservice.create_device_token(data)

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
