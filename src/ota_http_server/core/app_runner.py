# app_runner.py

import ssl

from werkzeug.middleware.proxy_fix import ProxyFix
from ota_http_server.core.config import Config
from ota_http_server.core.server import create_app

from ota_http_server.logger import get_app_logger

logger = get_app_logger(__name__)

# CLI application main function with collected options & configuration
# This function is application specific and should be modified to run the actual application logic.
# Because it is started with configuration object, it does not depend on how the application is started.
def run_app(cfg:Config) -> None:
    try:
        # Add real application code here.
        logger.info("Running run_app")
        logger.info("config = %s",str(cfg.config))

        app = create_app(
            www_dir=cfg.config['parameters']['www_dir'],
            firmware_dir=cfg.config['parameters']['firmware_dir'],
            url_firmware=cfg.config['parameters']['url_firmware'],
            use_jwt=not cfg.config['parameters']['no_jwt'],
            jwt_algorithm=cfg.config['parameters']['jwt_alg'],
            jwt_expiry=int(cfg.config['parameters']['jwt_expiry']),
            jwt_secret=cfg.config['parameters']['jwt_secret'],
            admin_secret=cfg.config['parameters']['admin_secret'],
            ota_audit_log=cfg.config['parameters']['ota_audit_log']
        )

        print("\n=== OTA Server Configuration ===")
        print(f"Listening on {cfg.config['parameters']['host']}:{cfg.config['parameters']['port']}")
        print(f"JWT: {'ENABLED' if not cfg.config['parameters']['no_jwt'] else 'DISABLED'}")
        print(f"Audit log file: {cfg.config['parameters']['ota_audit_log']}")
        print("Admin token endpoint: ENABLED (/admin/generate_token)")
        print("===========================================\n")

        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)   # type: ignore[method-assign]

        if cfg.config['parameters']['no_certs']:
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
