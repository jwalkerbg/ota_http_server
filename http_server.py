from flask import Flask, send_from_directory, request, abort
import os
import ssl
import argparse
import re
from packaging import version
from datetime import datetime, timezone
from werkzeug.middleware.proxy_fix import ProxyFix

def create_app(www_dir="www",
               firmware_dir="firmware",
               url_firmware="firmware",
               use_token=True,
               expected_token="bimbo"):
    """
    Flask app factory for both CLI and Apache/mod_wsgi usage.
    """
    app = Flask(__name__)

    def check_token(project=None):
        """
        Verifies the token from Authorization header or ?token= query param.
        Aborts with HTTP 401 if token is missing or invalid.
        Logs success/failure with project name for auditing.
        """
        if not use_token:
            return  # Token check disabled   [%d/%b/%Y %H:%M:%S]

        client_ip = request.remote_addr  # After ProxyFix, this will be the real external IP
        # Timestamp in ISO 8601 UTC with milliseconds
        now_utc = datetime.now().strftime("%d/%b/%Y %H:%M:%S")
        
        # Try header first
        header_token = request.headers.get("Authorization")
        # Then try URL query    
        url_token = request.args.get("token")

        # Normalize header Bearer token
        if header_token and header_token.startswith("Bearer "):
            header_token = header_token[len("Bearer "):]

        token_to_check = header_token or url_token
        
        project_info = f" (project={project})" if project else ""

        if not token_to_check:
            print(f"[{now_utc}] [AUTH] No token provided for {client_ip}{project_info} → Denied")
            abort(401)
        elif token_to_check != expected_token:
            print(f"[{now_utc}] [AUTH] Invalid token from {client_ip}{project_info} → Denied")
            abort(401)

        # If we get here → token valid
        print(f"[{now_utc}] [AUTH] Valid token from {client_ip}{project_info} → Granted")

    @app.route(f'/{url_firmware}/<project>/<path:filename>')
    def firmware(project, filename):
        check_token(project)
        # Build the physical path dynamically
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
        """
        Return the JSON manifest of the latest firmware for a project.
        """
        project_dir = os.path.join(www_dir, firmware_dir, project)
        if not os.path.isdir(project_dir):
            abort(404, "Project not found")

        # Match files like: prefix01.00.01.json
        json_files = [f for f in os.listdir(project_dir) if f.endswith(".json")]

        versions = []
        pattern = re.compile(r"(\d+\.\d+\.\d+)")  # extract version like 01.00.01
        for f in json_files:
            m = pattern.search(f)
            if m:
                versions.append((f, m.group(1)))

        if not versions:
            abort(404, "No versions found")

        # Sort by version using packaging.version
        latest_file, latest_ver = max(versions, key=lambda x: version.parse(x[1]))

        return send_from_directory(project_dir, latest_file, mimetype="application/json")


    @app.route(f'/{url_firmware}/<project>/versions')
    def list_versions(project):
        check_token(project)
        """
        Return a JSON object with a list of all available versions.
        """
        project_dir = os.path.join(www_dir, firmware_dir, project)
        if not os.path.isdir(project_dir):
            abort(404, "Project not found")

        json_files = [f for f in os.listdir(project_dir) if f.endswith(".json")]

        versions = []
        pattern = re.compile(r"(\d+\.\d+\.\d+)")
        for f in json_files:
            m = pattern.search(f)
            if m:
                versions.append(m.group(1))

        versions_sorted = sorted(versions, key=version.parse, reverse=True)

        return {"versions": versions_sorted}

    return app


def parse_args():
    parser = argparse.ArgumentParser(description="Simple HTTPS file server with optional token authentication")
    parser.add_argument("--cert", default="certs/ca_cert.pem", help="Path to certificate file")
    parser.add_argument("--key", default="certs/ca_key.pem", help="Path to private key file")
    parser.add_argument("--no-certs", action="store_true", help="Disable SSL certificates (use plain HTTP)")
    parser.add_argument("--no-token", action="store_true", help="Disable token authentication")
    parser.add_argument("--token", help="Token value to expect (if not provided, use default)")
    parser.add_argument("--host", default="0.0.0.0", help="Listening host")
    parser.add_argument("--port", type=int, default=8070, help="Listening port")
    parser.add_argument("--www-dir", default="www", help="Root directory for files (default 'www')")
    parser.add_argument("--firmware-dir", default="firmware", help="Subdirectory for firmware files (default 'firmware')")
    parser.add_argument("--url-firmware", default="firmware", help="The URL path segment for firmware (default 'firmware')")
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    use_token = not args.no_token
    expected_token = args.token or "bimbo"

    # Create app
    app = create_app(
        www_dir=args.www_dir,
        firmware_dir=args.firmware_dir,
        url_firmware=args.url_firmware,
        use_token=use_token,
        expected_token=expected_token
    )

    # Show configuration at startup
    print("\n=== Firmware Server Configuration ===")
    print(f"  Listening on:      {args.host}:{args.port}")
    if not args.no_certs:
        print(f"  Certificate:       {args.cert}")
        print(f"  Private key:       {args.key}")
    else:
        print(f"  SSL:               DISABLED (plain HTTP)")
    print(f"  Root directory:    {args.www_dir}")
    print(f"  Firmware subdir:   {args.firmware_dir}")
    print(f"  URL firmware path: /{args.url_firmware}/<project>/<filename>")
    print(f"  Token auth:        {'ENABLED' if use_token else 'DISABLED'}")
    if use_token:
        print(f"  Expected token:    {expected_token}")
        print("  Token sources:     Authorization header OR ?token= in URL")
    print("===========================================\n")
    
    # Make Flask respect X-Forwarded-For from Apache
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    if args.no_certs:
        # Plain HTTP
        app.run(host=args.host, port=args.port)
    else:
        # HTTPS
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.cert, args.key)
        app.run(host=args.host, port=args.port, ssl_context=context)
