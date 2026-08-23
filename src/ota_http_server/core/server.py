# core/server.py

import re
from pathlib import Path
from datetime import datetime, timezone, UTC
from flask import Flask, Response, send_file, request, abort, jsonify
from packaging import version
import hmac

from .data_models import TokenResult
from .auth_service import AuthService
from ota_http_server.database.database_service import DatabaseService
from ota_http_server.firmware.filename_validation import validate_firmware_filename
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
    admin_activity_logger = cfg.config.get("admin_activity_logger")
    ota_download_logger = cfg.config.get("ota_download_logger")

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

    def log_admin_activity(*, outcome: str, target: dict[str, object], error: str | None = None) -> None:
        if admin_activity_logger is None:
            return
        admin_activity_logger.log_activity(
            interface="http",
            entity="token",
            action="generate",
            outcome=outcome,
            target=target,
            error=error,
        )

    def log_ota_download_request(*, project: str | None, version: str | None, endpoint: str, outcome: str, status_code: int | None = None, error: str | None = None) -> None:
        if ota_download_logger is None:
            return

        route_action = {
            "firmware": "download",
            "latest_firmware": "latest",
            "list_versions": "versions",
        }.get(endpoint, "download")

        target: dict[str, object] = {
            "ip": request.remote_addr,
            "project": project,
            "path": request.path,
        }
        if version is not None:
            target["version"] = version
        if status_code is not None:
            target["status_code"] = status_code

        ota_download_logger.log_download(
            interface="http",
            action=route_action,
            outcome=outcome,
            target=target,
            error=error,
        )

    def get_firmware_file_path(project: str, filename: str) -> Path:
        try:
            validate_firmware_filename(filename)
        except ValueError as exc:
            logger.warning("Rejected unsafe firmware filename '%s' for project '%s': %s", filename, project, exc)
            abort(404, "Firmware file not found")

        app_paths = cfg.config['parameters']['app_paths']
        project_dir = app_paths.project_dir(project).resolve()
        return (project_dir / filename).resolve()

    @app.after_request
    def log_ota_request_response(response: Response) -> Response:
        endpoint = request.endpoint
        if endpoint not in {"firmware", "latest_firmware", "list_versions"}:
            return response

        view_args = request.view_args or {}
        project = view_args.get("project")
        version = view_args.get("version")
        status_code = response.status_code
        outcome = "success" if 200 <= status_code < 400 else "failed"
        log_ota_download_request(
            project=project,
            version=version,
            endpoint=endpoint,
            outcome=outcome,
            status_code=status_code,
        )
        return response

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

        file_path = get_firmware_file_path(project, firmware_rec.filename)

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

        file_path = get_firmware_file_path(project, latest_firmware_rec.filename)

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

        target: dict[str, object] = {
            "ip": request.remote_addr,
            "device_id": data.get("device_id"),
            "project": data.get("project"),
        }
        try:
            token_result:TokenResult = authservice.create_device_token(data)
        except Exception as exc:
            log_admin_activity(outcome="failed", target=target, error=str(exc))
            raise

        target["device_id"] = token_result.payload.get("sub", target["device_id"])
        target["project"] = token_result.payload.get("project", target["project"])
        target["expires_at"] = token_result.payload.get("exp")
        log_admin_activity(outcome="success", target=target)

        return jsonify({
            "token": token_result.token,
            "expires_at": datetime.fromtimestamp(token_result.payload["exp"], tz=timezone.utc).isoformat(),
            "payload": token_result.payload
        })

    return app
