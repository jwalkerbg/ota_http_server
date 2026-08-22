from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from ota_http_server.core.data_models import TokenResult


def _make_server_config(tmp_path, admin_activity_logger):
    return SimpleNamespace(
        config={
            "parameters": {
                "www_dir": str(tmp_path),
                "firmware_dir": "firmware",
                "url_firmware": "firmware",
                "no_jwt": True,
                "jwt_alg": "HS256",
                "jwt_expiry": 60,
                "jwt_max_expiry": 120,
                "jwt_secret": None,
                "jwt_issuer": "issuer",
                "jwt_audience": "audience",
                "admin_secret": "super-admin-secret",
                "ota_audit_log": "audit.csv",
                "app_paths": SimpleNamespace(
                    project_dir=lambda project_name: tmp_path / project_name,
                    logs_dir=tmp_path,
                ),
            },
            "admin_activity_logger": admin_activity_logger,
        }
    )


def test_admin_generate_token_logs_admin_activity_success(tmp_path, monkeypatch):
    pytest.importorskip("flask")

    from ota_http_server.core import server as server_module
    from ota_http_server.core.server import create_app

    class FakeAuthService:
        def create_device_token(self, data):
            return TokenResult(
                token="jwt-token",
                payload={
                    "sub": data["device_id"],
                    "project": data["project"],
                    "exp": 1760000000,
                },
            )

    monkeypatch.setattr(server_module, "DatabaseService", lambda cfg: MagicMock())
    monkeypatch.setattr(server_module, "AuthService", lambda **kwargs: FakeAuthService())

    admin_activity_logger = MagicMock()
    cfg = _make_server_config(tmp_path=tmp_path, admin_activity_logger=admin_activity_logger)
    app = create_app(cfg)
    client = app.test_client()

    response = client.post(
        "/admin/generate_token",
        headers={"X-Admin-Secret": "super-admin-secret"},
        json={"device_id": "device-1", "project": "project-1"},
    )

    assert response.status_code == 200
    admin_activity_logger.log_activity.assert_called_once()
    kwargs = admin_activity_logger.log_activity.call_args.kwargs
    assert kwargs["interface"] == "http"
    assert kwargs["entity"] == "token"
    assert kwargs["action"] == "generate"
    assert kwargs["outcome"] == "success"
    assert kwargs["target"]["device_id"] == "device-1"
    assert kwargs["target"]["project"] == "project-1"
    assert kwargs["target"]["expires_at"] == 1760000000
    assert kwargs["target"]["ip"] is not None
    assert kwargs["error"] is None


def test_admin_generate_token_logs_admin_activity_failure(tmp_path, monkeypatch):
    pytest.importorskip("flask")

    from ota_http_server.core import server as server_module
    from ota_http_server.core.server import create_app

    class FakeAuthService:
        def create_device_token(self, data):
            raise RuntimeError("token generation failed")

    monkeypatch.setattr(server_module, "DatabaseService", lambda cfg: MagicMock())
    monkeypatch.setattr(server_module, "AuthService", lambda **kwargs: FakeAuthService())

    admin_activity_logger = MagicMock()
    cfg = _make_server_config(tmp_path=tmp_path, admin_activity_logger=admin_activity_logger)
    app = create_app(cfg)
    client = app.test_client()

    response = client.post(
        "/admin/generate_token",
        headers={"X-Admin-Secret": "super-admin-secret"},
        json={"device_id": "device-1", "project": "project-1"},
    )

    assert response.status_code == 500
    admin_activity_logger.log_activity.assert_called_once()
    kwargs = admin_activity_logger.log_activity.call_args.kwargs
    assert kwargs["interface"] == "http"
    assert kwargs["entity"] == "token"
    assert kwargs["action"] == "generate"
    assert kwargs["outcome"] == "failed"
    assert kwargs["target"]["device_id"] == "device-1"
    assert kwargs["target"]["project"] == "project-1"
    assert kwargs["target"]["ip"] is not None
    assert kwargs["error"] == "token generation failed"
