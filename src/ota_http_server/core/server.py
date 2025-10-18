# core/server.py

from typing import Any, Dict
import csv
import os
import re
from datetime import datetime, timedelta, timezone
from flask import Flask, Response, send_from_directory, request, abort, jsonify
from packaging import version
import jwt

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
               ota_audit_log:str) -> Flask:

    # Print argument names and values
    print("create_app() called with:")
    for name, value in locals().items():
        print(f"  {name} = {value!r}")

    if use_jwt and (not jwt_secret or not admin_secret):
        raise ValueError("JWT is enabled but jwt_secret or admin_secret is not set")

    #
    # Flask app factory with JWT authentication and secure admin endpoint.
    #
    app = Flask(__name__.split('.', maxsplit=1)[0])

    # ---------------------------------------------------------------
    #                       HELPER FUNCTIONS
    # ---------------------------------------------------------------

    def check_token(project:str|None=None) -> None:
        """Verifies JWT from Authorization header or ?token= query param.
        Allows query param only for safe (GET, HEAD) requests.
        """
        if not use_jwt:
            return

        token = None
        source = None

        # 1️⃣ Try Authorization header first
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
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
        if project and token_project != project:
            abort(403, "Token not valid for this project")

        # 6️⃣ Log successful authentication
        device_id = payload.get("sub", "unknown")
        now = datetime.now(timezone.utc).isoformat()
        print(f"[{now}] [AUTH] OK - Device={device_id}, Project={token_project}, Source={source}")

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
            "sub": device_id,
            "project": project,
            "roles": ["device", "ota_client"],
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
            "jti": f"{device_id}-{int(now.timestamp())}",
            "fw_version": current_fw
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
        print(f"[AUDIT] {timestamp} | {ip} | {action} | {details}")

    # ---------------------------------------------------------------
    #                          ROUTES
    # ---------------------------------------------------------------

    @app.route(f'/{url_firmware}/<project>/<path:filename>')
    def firmware(project:str, filename:str) -> Response:
        check_token(project)
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
        if not admin_header or admin_header != admin_secret:
            abort(403, "Invalid or missing admin secret")

        data = request.get_json(silent=True)
        if not data:
            abort(400, "Missing JSON body")

        device_id = data.get("device_id")
        project = data.get("project")
        expires_minutes = data.get("expires_minutes", jwt_expiry)
        current_fw = data.get("current_fw", "1.0.0")

        if not device_id or not project:
            abort(400, "Missing 'device_id' or 'project'")

        token, payload = generate_ota_jwt(device_id, project, current_fw, expires_minutes)

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
