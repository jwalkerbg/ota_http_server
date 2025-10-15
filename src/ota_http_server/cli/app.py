# src/cli/app.py
import argparse
from importlib.metadata import version

import ssl
import argparse
from werkzeug.middleware.proxy_fix import ProxyFix
from importlib.metadata import version as pkg_version

from ota_http_server.core.config import Config
from ota_http_server.core.server import create_app
from ota_http_server.logger import get_app_logger

logger = get_app_logger(__name__)

def parse_args() -> argparse.Namespace:
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

    certs_group = parser.add_argument_group("Certificates")
    certs_ex_group = certs_group.add_mutually_exclusive_group()
    certs_ex_group.add_argument("--no-certs", dest="no_certs", action="store_const", const=True, help="Disable SSL certificates (use plain HTTP)")
    certs_ex_group.add_argument("--certs", dest="no_certs", action="store_const", const=False, help="Enable SSL certificates (use plain HTTP)")
    certs_group.add_argument("--cert", dest="cert", help="Path to certificate file")
    certs_group.add_argument("--key", dest="key", help="Path to private key file")

    jwt_group = parser.add_argument_group("JWT")
    jwt_ex_group = jwt_group.add_mutually_exclusive_group()
    jwt_ex_group.add_argument("--no-jwt", dest="no_jwt", action="store_const", const=True, help="Disable JWT authentication (not recommended)")
    jwt_ex_group.add_argument("--jwt", dest="no_jwt", action="store_const", const=False, help="Enable JWT authentication")
    jwt_group.add_argument("--jwt-alg", dest="jwt_alg", type=str, help="JWT algorithm to use (default 'HS256'), overrides OTA_JWT_ALGORITHM environment variable")
    jwt_group.add_argument("--jwt-expiry", dest="jwt_expiry", type=int, help="JWT expiry time in minutes (default 30), overrides OTA_JWT_EXPIRY_MINUTES environment variable")
    jwt_group.add_argument("--jwt-secret", dest="jwt_secret", type=str, help="JWT secret key, overrides OTA_JWT_SECRET environment variable")
    jwt_group.add_argument("--admin-secret", dest="admin_secret", type=str, help="Admin secret key, overrides OTA_ADMIN_SECRET environment variable")

    server_group = parser.add_argument_group("Server")
    server_group.add_argument("--host", dest="host", help="Listening host")
    server_group.add_argument("--port", dest="port", type=int, help="Listening port")
    server_group.add_argument("--www-dir", dest="www_dir", help="Root directory for files (default 'www')")
    server_group.add_argument("--firmware-dir", dest="firmware_dir", help="Subdirectory for firmware files (default 'firmware')")
    server_group.add_argument("--url-firmware", dest="url_firmware", help="The URL path segment for firmware (default 'firmware', corresponds with `firmware-dir`)")

    logging_group = parser.add_argument_group("Logging")
    logging_group.add_argument("--ota-audit-log", dest="ota_audit_log", help="Path to the OTA audit log file (default 'ota_audit_log.csv'), overrides OTA_AUDIT_LOG environment variable")

    return parser.parse_args()

def main() -> None:
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

    # Load config from environment variables (if set)
    try:
        cfg.load_config_env()
    except Exception as e:
        logger.info("Error with loading environment variables. Giving up.\n%s",str(e))
        return

    # Step 4: Merge default config, config.json, and command-line arguments
    cfg.merge_options(args)

    # Step 5: Show version info or run the application with collected configuration
    if cfg.config['metadata']['version']:
        app_version = pkg_version("ota_http_server")
        print(f"ota_http_server {app_version}")
    else:
        run_app(cfg)

# This will be moved in a separate module later

# CLI application main function with collected options & configuration
def run_app(cfg:Config) -> None:
    try:
        # Add real application code here.
        logger.info("Running run_app")
        logger.info("config = %s",str(cfg.config))

        app = create_app(
            www_dir=cfg.config['parameters']['www-dir'],
            firmware_dir=cfg.config['parameters']['firmware-dir'],
            url_firmware=cfg.config['parameters']['url-firmware'],
            use_jwt=not cfg.config['parameters']['no-jwt'],
            jwt_algorithm=cfg.config['parameters']['jwt-alg'],
            jwt_expiry=cfg.config['parameters']['jwt-expiry'],
            jwt_secret=cfg.config['parameters']['jwt-secret'],
            admin_secret=cfg.config['parameters']['admin-secret'],
            ota_audit_log=cfg.config['parameters']['ota-audit-log']
        )

        print("\n=== OTA Server Configuration ===")
        print(f"Listening on {cfg.config['parameters']['host']}:{cfg.config['parameters']['port']}")
        print(f"JWT: {'ENABLED' if not cfg.config['parameters']['no-jwt'] else 'DISABLED'}")
        print(f"Audit log file: {cfg.config['parameters']['ota-audit-log']}")
        print(f"Admin token endpoint: ENABLED (/admin/generate_token)")
        print("===========================================\n")

        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)   # type: ignore[method-assign]

        if cfg.config['parameters']['no-certs']:
            app.run(host=cfg.config['parameters']['host'], port=cfg.config['parameters']['port'])
        else:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cfg.config['parameters']['cert'], cfg.config['parameters']['key'])
            app.run(host=cfg.config['parameters']['host'], port=cfg.config['parameters']['port'], ssl_context=context)
    except ValueError as e:
        logger.error("Error in application run: %s",str(e))
    except Exception as e:
        logger.error("Unexpected error in application run: %s",str(e))
    finally:
        logger.info("Exiting run_app")

if __name__ == "__main__":
    main()
