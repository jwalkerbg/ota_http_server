from flask import Flask, send_from_directory, request, abort, jsonify
import os
import ssl
import argparse
import re
from packaging import version
from datetime import datetime, timedelta, timezone
from werkzeug.middleware.proxy_fix import ProxyFix
import jwt

# Default secret; in production, keep this safe!
JWT_SECRET = "supersecretkey"
JWT_ALGORITHM = "HS256"

def create_app(www_dir="www",
               firmware_dir="firmware",
               url_firmware="firmware",
               use_jwt=True,
               jwt_secret=None,
               jwt_algorithm="HS256"):
    """
    Flask app factory with JWT authentication for OTA.
    """
    app = Flask(__name__)

    def check_token(project=None):
        """
        Verifies JWT from Authorization header.
        """
        if not use_jwt:
            return  # Auth disabled

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

        # Verify project claim
        token_project = payload.get("project")
        if project and token_project != project:
            abort(403, "Token not valid for this project")

    def get_sorted_versions(project):
        """
        Return sorted list of versions for a given project.
        """
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

    # Routes
    @app.route(f'/{url_firmware}/<project>/<path:filename>')
    def firmware(project, filename):
        check_token(project)
        project_dir = os.path.join(www_dir, firmware_dir, project)
        return send_from_directory(project_dir, filename)

    @app.route('/favicon.ico')
    def favicon():
        return send_from_directory(
            www_dir,
            'favicon.ico',
            mimetype='image/vnd.microsoft.icon'
        )

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
        result = {
            "versions": versions,
            "count": len(versions),
            "latest": versions[-1]
        }
        return jsonify(result)

    @app.route("/status")
    def status():
        return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()})

    return app

def parse_args():
    parser = argparse.ArgumentParser(description="HTTPS OTA server with JWT authentication")
    parser.add_argument("--cert", default="certs/ca_cert.pem", help="Path to certificate file")
    parser.add_argument("--key", default="certs/ca_key.pem", help="Path to private key file")
    parser.add_argument("--no-certs", action="store_true", help="Disable SSL (use HTTP)")
    parser.add_argument("--no-jwt", action="store_true", help="Disable JWT authentication")
    parser.add_argument("--jwt-secret", default=None, help="JWT secret key")
    parser.add_argument("--jwt-algorithm", default="HS256", help="JWT signing algorithm")
    parser.add_argument("--host", default="0.0.0.0", help="Listening host")
    parser.add_argument("--port", type=int, default=8070, help="Listening port")
    parser.add_argument("--www-dir", default="www", help="Root directory for files")
    parser.add_argument("--firmware-dir", default="firmware", help="Subdirectory for firmware")
    parser.add_argument("--url-firmware", default="firmware", help="URL path segment for firmware")
    return parser.parse_args()

def generate_jwt(project: str, expires_hours=24, secret=JWT_SECRET, algorithm=JWT_ALGORITHM):
    """
    Helper function to generate JWT tokens for devices/projects.
    """
    now = datetime.now(timezone.utc)  # timezone-aware UTC
    payload = {
        "project": project,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=expires_hours)).timestamp())
    }
    return jwt.encode(payload, secret, algorithm=algorithm)

if __name__ == '__main__':
    args = parse_args()
    use_jwt = not args.no_jwt

    app = create_app(
        www_dir=args.www_dir,
        firmware_dir=args.firmware_dir,
        url_firmware=args.url_firmware,
        use_jwt=use_jwt,
        jwt_secret=args.jwt_secret,
        jwt_algorithm=args.jwt_algorithm
    )

    print("\n=== OTA Server Configuration ===")
    print(f"  Listening on:      {args.host}:{args.port}")
    if not args.no_certs:
        print(f"  Certificate:       {args.cert}")
        print(f"  Private key:       {args.key}")
    else:
        print("  SSL:               DISABLED (plain HTTP)")
    print(f"  Root directory:    {args.www_dir}")
    print(f"  Firmware subdir:   {args.firmware_dir}")
    print(f"  URL firmware path: /{args.url_firmware}/<project>/<filename>")
    print(f"  JWT auth:          {'ENABLED' if use_jwt else 'DISABLED'}")
    print("===========================================\n")

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    jwt_token = generate_jwt("smart_fan", secret=args.jwt_secret or JWT_SECRET, algorithm=args.jwt_algorithm)
    print(f"  JWT Token:        {jwt_token}")

    if args.no_certs:
        app.run(host=args.host, port=args.port)
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.cert, args.key)
        app.run(host=args.host, port=args.port, ssl_context=context)
