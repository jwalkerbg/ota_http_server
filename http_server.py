from flask import Flask, send_from_directory, request, abort
import os
import ssl
import argparse


def create_app(www_dir="www",
               firmware_dir="firmware",
               url_firmware="firmware",
               use_token=True,
               expected_token="bimbo"):
    """
    Flask app factory for both CLI and Apache/mod_wsgi usage.
    """
    app = Flask(__name__)

    @app.route(f'/{url_firmware}/<project>/<path:filename>')
    def firmware(project, filename):
        if use_token:
            # Try header first
            header_token = request.headers.get("Authorization")
            # Then try URL query
            url_token = request.args.get("token")

            # Normalize header Bearer token
            if header_token and header_token.startswith("Bearer "):
                header_token = header_token[len("Bearer "):]

            token_to_check = header_token or url_token

            if not token_to_check:
                print(f"[AUTH] No token provided for {request.remote_addr} → Denied")
                abort(401)
            elif token_to_check != expected_token:
                print(f"[AUTH] Invalid token from {request.remote_addr} → Denied")
                abort(401)

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

    if args.no_certs:
        # Plain HTTP
        app.run(host=args.host, port=args.port)
    else:
        # HTTPS
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.cert, args.key)
        app.run(host=args.host, port=args.port, ssl_context=context)
