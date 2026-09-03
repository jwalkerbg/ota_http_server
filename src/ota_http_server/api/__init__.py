"""Versioned REST API package."""

from flask import Flask

from .v1 import api_v1, register_api_error_handlers
from .v1_devices import api_v1_devices
from .v1_firmware import api_v1_firmware
from .v1_projects import api_v1_projects
from .v1_users import api_v1_users


def register_api_blueprints(app: Flask) -> None:
    """Register current API versions on the application."""
    register_api_error_handlers(app)
    app.register_blueprint(api_v1)
    app.register_blueprint(api_v1_users)
    app.register_blueprint(api_v1_projects)
    app.register_blueprint(api_v1_devices)
    app.register_blueprint(api_v1_firmware)


__all__ = ["api_v1", "register_api_blueprints"]
