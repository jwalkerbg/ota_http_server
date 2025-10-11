# src/cli/app.py
import argparse
from importlib.metadata import version

from flask import Flask, send_from_directory, request, abort, jsonify
import os
import ssl
import argparse
import re
from packaging import version
from datetime import datetime, timedelta, timezone
from werkzeug.middleware.proxy_fix import ProxyFix
import jwt
import csv

import ota_http_server
from ota_http_server.core.config import Config
from ota_http_server.logger import get_app_logger

logger = get_app_logger(__name__)

def parse_args():
    """Parse command-line arguments, including nested options for mqtt and MS Protocol."""
    parser = argparse.ArgumentParser(description='Secure OTA server with JWT and audit logging')

    # configuration file name
    parser.add_argument('--config', type=str, dest='config', default='config.toml',\
                        help="Name of the configuration file, default is 'config.toml'")
    parser.add_argument('--no-config', action='store_const', const='', dest='config',\
                        help="Do not use a configuration file (only defaults & options)")

    # version
    parser.add_argument('-v', dest='app_version', action='store_true',\
                        help='Show version information of the module')

    # Verbosity option
    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument('--verbose', dest='verbose', action='store_const',\
                                 const=True, help='Enable verbose mode')
    verbosity_group.add_argument('--no-verbose', dest='verbose', action='store_const',\
                                 const=False, help='Disable verbose mode')

    # application options & parameters
    parser.add_argument("--cert", default="certs/ca_cert.pem", help="Path to certificate file")
    parser.add_argument("--key", default="certs/ca_key.pem", help="Path to private key file")
    parser.add_argument("--no-certs", action="store_true", help="Disable SSL certificates (use plain HTTP)")
    parser.add_argument("--no-jwt", action="store_true", help="Disable JWT authentication (not recommended)")
    parser.add_argument("--host", default="0.0.0.0", help="Listening host")
    parser.add_argument("--port", type=int, default=8070, help="Listening port")
    parser.add_argument("--www-dir", default="www", help="Root directory for files (default 'www')")
    parser.add_argument("--firmware-dir", default="firmware", help="Subdirectory for firmware files (default 'firmware')")
    parser.add_argument("--url-firmware", default="firmware", help="The URL path segment for firmware (default 'firmware', corresponds with `firmware-dir`)")
    parser.add_argument("--log-file", default="ota_http_server.log", help="Log file name (default 'ota_http_server.log')")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Logging level (default 'INFO')")
    parser.add_argument("--audit-log-file", default="audit.log", help="Audit log file name (default 'audit.log')")

    return parser.parse_args()

def main():
    """Main entry point of the CLI."""

    # Step 1: Create config object with default configuration
    cfg = Config()

    # Step 2: Parse command-line arguments
    args = parse_args()

    # Step 3: Try to load configuration from configuration file
    config_file = args.config
    try:
        cfg.load_config_file(config_file)
    except Exception as e:
        logger.info("Error with loading configuration file. Giving up.\n%s",str(e))
        return

    # Step 4: Merge default config, config.json, and command-line arguments
    cfg.merge_options(args)

    # Step 5: Show version info or run the application with collected configuration
    if cfg.config['metadata']['version']:
        app_version = version("ota_http_server")
        print(f"ota_http_server {app_version}")
    else:
        run_app(cfg)

# This will be moved in a separate module later

# -------------------------------------------------------------------
#                   ENVIRONMENT CONFIGURATION
# -------------------------------------------------------------------

# Environment-based secrets
JWT_SECRET = os.environ.get("OTA_JWT_SECRET")
ADMIN_SECRET = os.environ.get("OTA_ADMIN_SECRET")

if not JWT_SECRET:
    raise RuntimeError("Environment variable OTA_JWT_SECRET is missing!")

if not ADMIN_SECRET:
    raise RuntimeError("Environment variable OTA_ADMIN_SECRET is missing!")

JWT_ALGORITHM = os.environ.get("OTA_JWT_ALGORITHM", "HS256")
AUDIT_LOG_FILE = os.environ.get("OTA_AUDIT_LOG", "audit_log.csv")

JWT_DEFAULT_EXPIRY_MINUTES = int(os.environ.get("OTA_JWT_EXPIRY_MINUTES", "30"))

# -------------------------------------------------------------------
#                       APP FACTORY
# -------------------------------------------------------------------

def create_app(www_dir="www",
               firmware_dir="firmware",
               url_firmware="firmware",
               use_jwt=True):
    """
    Flask app factory with JWT authentication and secure admin endpoint.
    """
    app = Flask(__name__)

    # ---------------------------------------------------------------
    #                       HELPER FUNCTIONS
    # ---------------------------------------------------------------

    def check_token(project=None):
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
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
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

    def get_sorted_versions(project):
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

    def generate_ota_jwt(device_id, project, current_fw="1.0.0", expires_minutes=JWT_DEFAULT_EXPIRY_MINUTES):
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
        return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM), payload

    def log_audit_event(ip, action, details):
        """Append a token generation audit log entry."""
        timestamp = datetime.now(timezone.utc).isoformat()
        os.makedirs(os.path.dirname(AUDIT_LOG_FILE) or ".", exist_ok=True)
        new_file = not os.path.exists(AUDIT_LOG_FILE)
        with open(AUDIT_LOG_FILE, "a", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            if new_file:
                writer.writerow(["timestamp", "ip", "action", "details"])
            writer.writerow([timestamp, ip, action, details])
        print(f"[AUDIT] {timestamp} | {ip} | {action} | {details}")

    # ---------------------------------------------------------------
    #                          ROUTES
    # ---------------------------------------------------------------

    @app.route(f'/{url_firmware}/<project>/<path:filename>')
    def firmware(project, filename):
        check_token(project)
        project_dir = os.path.join(www_dir, firmware_dir, project)
        return send_from_directory(project_dir, filename)

    @app.route(f'/{url_firmware}/<project>/latest')
    def latest_firmware(project):
        check_token(project)
        project_dir, _, version_files = get_sorted_versions(project)
        latest_file, _ = version_files[-1]
        return send_from_directory(project_dir, latest_file, mimetype="application/json")

    @app.route(f'/{url_firmware}/<project>/versions')
    def list_versions(project):
        check_token(project)
        _, versions, _ = get_sorted_versions(project)
        return jsonify({
            "versions": versions,
            "count": len(versions),
            "latest": versions[-1]
        })

    @app.route("/status")
    def status():
        return jsonify({
            "status": "ok",
            "time": datetime.now(timezone.utc).isoformat()
        })

    # ---------------------------------------------------------------
    #                      ADMIN TOKEN GENERATOR
    # ---------------------------------------------------------------

    @app.route("/admin/generate_token", methods=["POST"])
    def admin_generate_token():
        """
        Generates a JWT dynamically for a device.
        Requires header: X-Admin-Secret=<ADMIN_SECRET>
        Body JSON:
            {
              "device_id": "uuid-v4",
              "project": "project_name",
              "expires_minutes": $JWT_DEFAULT_EXPIRY_MINUTES
              "current_fw": "1.0.0"
            }
        """
        admin_header = request.headers.get("X-Admin-Secret")
        if not admin_header or admin_header != ADMIN_SECRET:
            abort(403, "Invalid or missing admin secret")

        data = request.get_json(silent=True)
        if not data:
            abort(400, "Missing JSON body")

        device_id = data.get("device_id")
        project = data.get("project")
        expires_minutes = data.get("expires_minutes", JWT_DEFAULT_EXPIRY_MINUTES)
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


# CLI application main function with collected options & configuration
def run_app(config:Config) -> None:
    try:
        # Add real application code here.
        logger.info("Running run_app")
        logger.info("config = %s",str(config.config))

        app = create_app(
            www_dir=config.config['parameters']['www-dir'],
            firmware_dir=config.config['parameters']['firmware-dir'],
            url_firmware=config.config['parameters']['url-firmware'],
            use_jwt=not config.config['parameters']['no-jwt'],
        )

        print("\n=== OTA Server Configuration ===")
        print(f"Listening on {config.config['parameters']['host']}:{config.config['parameters']['port']}")
        print(f"JWT: {'ENABLED' if not config.config['parameters']['no-jwt'] else 'DISABLED'}")
        print(f"Audit log file: {AUDIT_LOG_FILE}")
        print(f"Admin token endpoint: ENABLED (/admin/generate_token)")
        print("===========================================\n")

        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

        if config.config['parameters']['no-certs']:
            app.run(host=config.config['parameters']['host'], port=config.config['parameters']['port'])
        else:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(config.config['parameters']['cert'], config.config['parameters']['key'])
            app.run(host=config.config['parameters']['host'], port=config.config['parameters']['port'], ssl_context=context)

    finally:
        logger.info("Exiting run_app")


if __name__ == "__main__":
    main()
