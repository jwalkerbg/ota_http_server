# app_runner.py

import ssl

from werkzeug.middleware.proxy_fix import ProxyFix
from ota_http_server.core.config import Config
from ota_http_server.core.server import create_app
from ota_http_server.database.database_service import DatabaseService
from ota_http_server.user.user_service import UserService
from ota_http_server.project.project_service import ProjectService
from ota_http_server.device.device_service import DeviceService
from ota_http_server.firmware.firmware_service import FirmwareService
from ota_http_server.logger import get_app_logger
from ota_http_server.logger.admin_activity_logger import build_admin_activity_logger
from ota_http_server.core.data_models import AppPaths

logger = get_app_logger(__name__)

# CLI application main function with collected options & configuration
def run_app(cfg:Config) -> None:

    # ensure app directories exist
    logger.verbose("Creating AppPaths object")
    app_paths = AppPaths(cfg)
    # store app_paths in the configuration so as to access it elsewhere
    cfg.config['parameters']['app_paths'] = app_paths
    cfg.config["admin_activity_logger"] = build_admin_activity_logger(cfg)
    db_service = DatabaseService(cfg)
    cfg.config["db_service"] = db_service
    user_service = UserService(cfg)
    cfg.config["user_service"] = user_service
    project_service = ProjectService(cfg)
    cfg.config["project_service"] = project_service
    device_service = DeviceService(cfg)
    cfg.config["device_service"] = device_service
    firmware_service = FirmwareService(cfg)
    cfg.config["firmware_service"] = firmware_service

    if cfg.config['command'] == 'runserver':
        try:
            # Add real application code here.
            logger.info("Starting OTA HTTP Server")
            logger.verbose("config = %s",str(cfg.config))

            app = create_app(cfg)

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
            logger.error("Error in application run: %s",str(e), exc_info=cfg.config['logging']['exc_full_stack'])
        except Exception as e:
            logger.error("Unexpected error in application run: %s",str(e), exc_info=cfg.config['logging']['exc_full_stack'])
        finally:
            logger.info("Exiting runserver")

    elif cfg.config['command'] == 'db':
        logger.info("Starting OTA Database CLI")
        # Add database CLI code here, e.g. using click or argparse for subcommands
        logger.verbose("config = %s",str(cfg.config))
        try:
            db_service.db_command_handler()
        except:
            logger.error("%s", str(e), exc_info=cfg.config['logging']['exc_full_stack'])
        finally:
            logger.info("Exiting db CLI")
    elif cfg.config['command'] == 'user':
        try:
            user_service.command_handler()
        except Exception as e:
            logger.error("%s", str(e), exc_info=cfg.config['logging']['exc_full_stack'])
        finally:
            logger.info("Exiting user CLI")
    elif cfg.config['command'] == 'project':
        try:
            project_service.command_handler()
        except Exception as e:
            logger.error("%s", str(e), exc_info=cfg.config['logging']['exc_full_stack'])
        finally:
            logger.info("Exiting project CLI")
    elif cfg.config['command'] == 'device':
        try:
            device_service.command_handler()
        except Exception as e:
            logger.error("%s", str(e), exc_info=cfg.config['logging']['exc_full_stack'])
        finally:
            logger.info("Exiting device CLI")
    elif cfg.config['command'] == 'firmware':
        try:
            firmware_service.command_handler()
        except Exception as e:
            logger.error("%s", str(e), exc_info=cfg.config['logging']['exc_full_stack'])
        finally:
            logger.info("Exiting firmware CLI")
    else:
        logger.warning("Unknown command '%s' specified, no action taken", cfg.config['command'])
