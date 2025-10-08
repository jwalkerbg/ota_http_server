from flask import Flask, send_from_directory, request, abort, jsonify
import os
import ssl
import argparse
import re
from packaging import version
from datetime import datetime, timedelta, timezone
from werkzeug.middleware.proxy_fix import ProxyFix
import jwt

# --- Defaults ---
JWT_SECRET = "supersecretkey"       # Replace for production
JWT_ALGORITHM = "HS256"
ADMIN_SECRET = "admin123"           # Used for token issuing endpoint (replace for production)

# -------------------------------------------------------------------
#                       APP FACTORY
# -------------------------------------------------------------------

def create_app(www_dir="www",
               firmware_dir="firmware",
               url_firmware="firmware",
               use_jwt=True,
               jwt_secret=None,
               jwt_algorithm="HS256",
               admin_secret=None):
    """
    Flask app factory with JWT authentication and token generation endpoint.
    """
    app = Flask(__name__)

    # ---------------------------------------------------------------
    #                       HELPER FUNCTIONS
    # ---------------------------------------------------------------

    def check_token(project=None):
        """ Verifies JWT from Authorization header. """
        if not use_jwt:
            return

        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            abort(401, "Missing Authorization header")

        token = auth_header[len("Bearer "):]
        try:
            payload = jwt.decode(token, jwt_secret or JWT_SECRET, algorithms=[jwt_algorithm])
        except jwt.ExpiredSignatureError:
            abort(401, "Token expired")
        except jwt.InvalidTokenError:
            abort(401, "Invalid token")

        # Verify project
        token_project = payload.get("project")
        if project and token_project != project:
            abort(403, "Token not valid for this project")

        # Optional logging
        device_id = payload.get("sub", "unknown")
        print(f"[{datetime.now(timezone.utc).isoformat()}] [AUTH] Device={device_id}, Project={token_project} OK")

    def get_sorted_versions(project):
        """ Return sorted list of versions for a given project. """
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

    def generate_ota_jwt(device_id, project, current_fw="1.0.0", expires_hours=24):
        """ Generate a timezone-aware JWT for OTA clients (devices). """
        now = datetime.now(timezone.utc)
        payload = {
            "sub": device_id,
            "project": project,
            "roles": ["device", "ota_client"],
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(hours=expires_hours)).timestamp()),
            "jti": f"{device_id}-{int(now.timestamp())}",
            "fw_version": current_fw
        }
        return jwt.encode(payload, jwt_secret or JWT_SECRET, algorithm=jwt_algorithm), payload

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
              "device_id": "esp32-001",
              "project": "smart_air",
              "expires_hours": 24
            }
        """
        admin_header = request.headers.get("X-Admin-Secret")
        if not admin_header or admin_header != (admin_secret or ADMIN_SECRET):
            abort(403, "Invalid or missing admin secret")

        data = request.get_json(silent=True)
        if not data:
            abort(400, "Missing JSON body")

        device_id = data.get("device_id")
        project = data.get("project")
        expires_hours = data.get("expires_hours", 24)
        current_fw = data.get("current_fw", "1.0.0")

        if not device_id or not project:
            abort(400, "Missing 'device_id' or 'project'")

        token, payload = generate_ota_jwt(device_id, project, current_fw, expires_hours)
        return jsonify({
            "token": token,
            "expires_at": datetime.fromtimestamp(payload["exp"], tz=timezone.utc).isoformat(),
            "payload": payload
        })

    return app


# -------------------------------------------------------------------
#                       ENTRY POINT
# -------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(description="HTTPS OTA server with JWT + admin token generation")
    parser.add_argument("--cert", default="certs/ca_cert.pem")
    parser.add_argument("--key", default="certs/ca_key.pem")
    parser.add_argument("--no-certs", action="store_true")
    parser.add_argument("--no-jwt", action="store_true")
    parser.add_argument("--jwt-secret", default=None)
    parser.add_argument("--jwt-algorithm", default="HS256")
    parser.add_argument("--admin-secret", default=None)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8070)
    parser.add_argument("--www-dir", default="www")
    parser.add_argument("--firmware-dir", default="firmware")
    parser.add_argument("--url-firmware", default="firmware")
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    app = create_app(
        www_dir=args.www_dir,
        firmware_dir=args.firmware_dir,
        url_firmware=args.url_firmware,
        use_jwt=not args.no_jwt,
        jwt_secret=args.jwt_secret,
        jwt_algorithm=args.jwt_algorithm,
        admin_secret=args.admin_secret
    )

    print("\n=== OTA Server Configuration ===")
    print(f"Listening on {args.host}:{args.port}")
    print(f"JWT: {'ENABLED' if not args.no_jwt else 'DISABLED'}")
    print(f"Admin token endpoint: ENABLED (/admin/generate_token)")
    print("===========================================\n")

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    if args.no_certs:
        app.run(host=args.host, port=args.port)
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.cert, args.key)
        app.run(host=args.host, port=args.port, ssl_context=context)
