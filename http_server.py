from flask import Flask, send_from_directory, request, abort, jsonify
import os
import ssl
import argparse
import re
import json
from packaging import version
from datetime import datetime
from werkzeug.middleware.proxy_fix import ProxyFix

def create_app(www_dir="www",
               firmware_dir="firmware",
               url_firmware="firmware",
               use_token=True,
               expected_token=None,
               tokens_file=None):
    """
    Flask app factory for both CLI and Apache/mod_wsgi usage.
    Supports per-project tokens from JSON file + optional global token.
    """
    app = Flask(__name__)

    def check_token(project=None):
        """
        Verifies the token from Authorization header or ?token= query param.
        Checks per-project token first, then global token as fallback.
        Reloads tokens.json every request for live updates.
        """
        if not use_token:
            return  # Token check disabled

        # Reload tokens file
        PROJECT_TOKENS = {}
        if tokens_file and os.path.isfile(tokens_file):
            try:
                with open(tokens_file, "r", encoding="utf-8") as f:
                    PROJECT_TOKENS = json.load(f)
            except Exception as e:
                print(f"[WARN] Failed to load tokens file '{tokens_file}': {e}")

        client_ip = request.remote_addr
        now_utc = datetime.now().strftime("%d/%b/%Y %H:%M:%S")

        # Get token from header or query
        header_token = request.headers.get("Authorization")
        url_token = request.args.get("token")
        if header_token and header_token.startswith("Bearer "):
            header_token = header_token[len("Bearer "):]
        token_to_check = header_token or url_token
        project_info = f" (project={project})" if project else ""

        # Check project exists in token mapping
        expected_for_project = PROJECT_TOKENS.get(project)

        if not expected_for_project and not expected_token:
            print(f"[{now_utc}] [AUTH] Unknown project '{project}' → Denied")
            abort(404, "Unknown project")

        if not token_to_check:
            print(f"[{now_utc}] [AUTH] No token provided for {client_ip}{project_info} → Denied")
            abort(401)

        # Match against project token or global fallback
        if token_to_check != expected_for_project and token_to_check != expected_token:
            print(f"[{now_utc}] [AUTH] Invalid token from {client_ip}{project_info} → Denied")
            abort(401)

        print(f"[{now_utc}] [AUTH] Valid token from {client_ip}{project_info} → Granted")

    def get_sorted_versions(project):
        """
        Return sorted list of versions for a given project.
        Raises 404 if project does not exist or no versions found.
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

    return app

def parse_args():
    parser = argparse.ArgumentParser(description="Simple HTTPS file server with optional token authentication")
    parser.add_argument("--cert", default="certs/ca_cert.pem", help="Path to certificate file")
    parser.add_argument("--key", default="certs/ca_key.pem", help="Path to private key file")
    parser.add_argument("--no-certs", action="store_true", help="Disable SSL certificates (use plain HTTP)")
    parser.add_argument("--no-token", action="store_true", help="Disable token authentication")
    parser.add_argument("--token", help="Global fallback token value to expect")
    parser.add_argument("--tokens-file", default="tokens.json", help="JSON file with per-project tokens")
    parser.add_argument("--host", default="0.0.0.0", help="Listening host")
    parser.add_argument("--port", type=int, default=8070, help="Listening port")
    parser.add_argument("--www-dir", default="www", help="Root directory for files (default 'www')")
    parser.add_argument("--firmware-dir", default="firmware", help="Subdirectory for firmware files (default 'firmware')")
    parser.add_argument("--url-firmware", default="firmware", help="The URL path segment for firmware (default 'firmware')")
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()
    use_token = not args.no_token
    expected_token = args.token  # Optional global fallback
    tokens_file = args.tokens_file

    app = create_app(
        www_dir=args.www_dir,
        firmware_dir=args.firmware_dir,
        url_firmware=args.url_firmware,
        use_token=use_token,
        expected_token=expected_token,
        tokens_file=tokens_file
    )

    print("\n=== Firmware Server Configuration ===")
    print(f"  Listening on:      {args.host}:{args.port}")
    if not args.no_certs:
        print(f"  Certificate:       {args.cert}")
        print(f"  Private key:       {args.key}")
    else:
        print("  SSL:               DISABLED (plain HTTP)")
    print(f"  Root directory:    {args.www_dir}")
    print(f"  Firmware subdir:   {args.firmware_dir}")
    print(f"  URL firmware path: /{args.url_firmware}/<project>/<filename>")
    print(f"  Token auth:        {'ENABLED' if use_token else 'DISABLED'}")
    if use_token:
        print(f"  Tokens file:       {tokens_file}")
        if expected_token:
            print(f"  Global token:      {expected_token}")
        print("  Token sources:     Authorization header OR ?token= in URL")
    print("===========================================\n")

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    if args.no_certs:
        app.run(host=args.host, port=args.port)
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.cert, args.key)
        app.run(host=args.host, port=args.port, ssl_context=context)
