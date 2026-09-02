"""Versioned REST API package."""

from flask import Flask

from .v1 import api_v1, register_api_error_handlers


def register_api_blueprints(app: Flask) -> None:
    """Register current API versions on the application."""
    register_api_error_handlers(app)
    app.register_blueprint(api_v1)


__all__ = ["api_v1", "register_api_blueprints"]
