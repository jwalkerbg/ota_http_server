# core/server.py

from typing import Any, Dict
import time
import csv
import os
import sys
import re
from datetime import datetime, time, timedelta, timezone
from flask import Flask, Response, send_from_directory, request, abort, jsonify, current_app
from packaging import version
import jwt
import hmac
from uuid import UUID
# Check Python version at runtime
if sys.version_info >= (3, 11):
    import tomllib as toml # Use the built-in tomllib for Python 3.11+
else:
    import tomli as toml # Use the external tomli for Python 3.7 to 3.10

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
               jwt_secret:str|None,
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

    def load_ota_db() -> Dict[str, Any]:
        app = current_app
        now = datetime.now()

        logger.info("load_ota_db")

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

    def check_token(project:str|None=None) -> Dict[str, Any]:
        """Verifies JWT from Authorization header or ?token= query param.
        Allows query param only for safe (GET, HEAD) requests.
        """
        if not use_jwt:
            return {}  # JWT authentication is disabled, allow all requests

        token = None
        source = None

        # 1️⃣ Try Authorization header first
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.lower().startswith("bearer "):
            token = auth_header[len("Bearer "):]
            source = "header"

        # 2️⃣ Fallback to ?token= only if header missing
        if not token:
            token = request.args.get("token")
            if token:
                source = "query"
                # Allow query tokens only for safe requests (GET, HEAD)
                if request.method not in ("GET", "HEAD"):
                    abort(405, "Query token not allowed for this method")

        # 3️⃣ If no token found at all
        if not token:
            abort(401, "Missing token (Authorization header or ?token=)")

        # 4️⃣ Decode and verify JWT
        try:
            payload = jwt.decode(token, jwt_secret, algorithms=[jwt_algorithm])
        except jwt.ExpiredSignatureError:
            abort(401, "Token expired")
        except jwt.InvalidTokenError:
            abort(401, "Invalid token")

        # 5️⃣ Verify project match
        token_project = payload.get("project")
        if not project or not hmac.compare_digest(token_project, project):
            abort(403, "Token not valid for this project")

        # 5️⃣.1️⃣ Verify "roles" claim contains "device" and "fw_download"
        roles = payload.get("roles", [])
        if not all(role in roles for role in ("device", "fw_download")):
            abort(403, "Token does not have required roles")

        # 5️⃣.2️⃣ Verify "aud" claim is "ota_api"
        aud = payload.get("aud")
        #if aud != "ota_api":
        if not aud or not hmac.compare_digest(aud, "ota_api"):
            abort(403, "Token not valid for this API")

        # 5️⃣.3️⃣ Verify issuer claim if present (optional, but good practice)
        issuer = payload.get("iss")
        expected_issuer = app.config.get("issuer_jwt", "ota_http_server")
        if issuer and not hmac.compare_digest(issuer, expected_issuer):
            abort(403, "Token issuer mismatch")

        # 6️⃣ Log successful authentication
        device_id = payload.get("sub", "unknown")
        now = datetime.now(timezone.utc).isoformat()
        logger.info(f"[%s] [AUTH] OK - Device=%s, Project=%s, Source=%s", now, device_id, token_project, source)

        return payload

    def get_sorted_versions(project:str) -> tuple[str, list[str], list[tuple[str, str]]]:
        """Return sorted list of versions for a given project."""
        project_dir = os.path.join(www_dir, firmware_dir, project)
        if not os.path.isdir(project_dir):
            abort(404, "Project not found")

        pattern = re.compile(r"(\d+\.\d+\.\d+)")
        versions = []
        version_files = []

        for filename in os.listdir(project_dir):
            if filename.endswith(".json"):
                match = pattern.search(filename)
                if match:
                    ver = match.group(1)
                    versions.append(ver)
                    version_files.append((filename, ver))

        if not versions:
            abort(404, "No versions found")

        versions.sort(key=lambda s: list(map(int, s.split('.'))))
        version_files.sort(key=lambda x: version.parse(x[1]))
        return project_dir, versions, version_files

    def generate_ota_jwt(device_id:str, project:str, current_fw:str="1.0.0", expires_minutes:int=jwt_expiry) -> tuple[str, Dict[str, Any]]:
        """Generate a timezone-aware JWT for OTA clients (devices)."""
        now = datetime.now(timezone.utc)
        payload = {
            "aud": "ota_api",
            "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
            "fw_version": current_fw,
            "iat": int(now.timestamp()),
            "iss": app.config.get("issuer_jwt", "ota_http_server"),
            "jti": f"{device_id}-{int(now.timestamp())}",
            "project": project,
            "roles": ["device", "fw_download"],
            "sub": device_id
        }
        return jwt.encode(payload, jwt_secret, algorithm=jwt_algorithm), payload

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
            payload = check_token(project)
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

        project_dir = os.path.join(www_dir, firmware_dir, project)
        return send_from_directory(project_dir, filename)

    @app.route(f'/{url_firmware}/<project>/latest')
    def latest_firmware(project:str) -> Response:
        check_token(project)
        project_dir, _, version_files = get_sorted_versions(project)
        latest_file, _ = version_files[-1]
        return send_from_directory(project_dir, latest_file, mimetype="application/json")

    @app.route(f'/{url_firmware}/<project>/versions')
    def list_versions(project:str) -> Response:
        check_token(project)
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
              "expires_minutes": jwt_expiry,
              "current_fw": "1.0.0"
            }
        """
        admin_header = request.headers.get("X-Admin-Secret")
        if not admin_header or not hmac.compare_digest(admin_header, admin_secret):
            abort(403, "Invalid or missing admin secret")

        data = request.get_json(silent=True)
        if not data:
            abort(400, "Missing JSON body")

        # validation of presence of fields "device_id", "project", "current_fw", "download_fw"

        # Device ID is validated as a UUID, but we also check it's provided before that.
        if not device_id:
            abort(400, "Missing 'device_id'")
        device_id = data.get("device_id")
        try:
            UUID(device_id)
        except ValueError:
            abort(400, "Invalid device_id format")

        # Project name validation can also be added if there are specific requirements (e.g., allowed characters), but for now we just check it's provided.
        project = data.get("project", None)
        if not project:
            abort(400, "Missing 'project'")
        current_fw = data.get("current_fw", "1.0.0")
        # download_fw is obligatory for the token generation, but we don't need to validate it here since it's just a claim in the token and doesn't affect server logic.
        download_fw = data.get("download_fw")
        if not download_fw:
            abort(400, "Missing 'download_fw'")

        expires_minutes = min(data.get("expires_minutes", jwt_expiry), 30)  # Cap expiry to 30 minutes for security
        token, payload = generate_ota_jwt(device_id, project, download_fw, expires_minutes)

        # Audit logging
        log_audit_event(
            ip=request.remote_addr,
            action="generate_token",
            details=f"device={device_id}, project={project}, exp={payload['exp']}"
        )

        return jsonify({
            "token": token,
            "expires_at": datetime.fromtimestamp(payload["exp"], tz=timezone.utc).isoformat(),
            "payload": payload
        })

    return app
