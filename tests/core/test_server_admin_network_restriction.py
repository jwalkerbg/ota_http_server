from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from ota_http_server.core.data_models import TokenResult


def _make_server_config(tmp_path, admin_networks=None):
    parameters = {
        "www_dir": str(tmp_path),
        "firmware_dir": "firmware",
        "url_firmware": "firmware",
        "jwt_alg": "HS256",
        "jwt_expiry": 60,
        "jwt_max_expiry": 120,
        "jwt_secret": "secret",
        "jwt_issuer": "issuer",
        "jwt_audience": "audience",
        "admin_secret": "super-admin-secret",
        "app_paths": SimpleNamespace(
            project_dir=lambda project_name: tmp_path / project_name,
            logs_dir=tmp_path,
        ),
    }
    if admin_networks is not None:
        parameters["admin_networks"] = admin_networks
    return SimpleNamespace(config={"parameters": parameters, "admin_activity_logger": None})


def _build_app(tmp_path, monkeypatch, admin_networks=None):
    pytest.importorskip("flask")

    from ota_http_server.core import server as server_module
    from ota_http_server.core.server import create_app

    class FakeAuthService:
        def create_device_token(self, data):
            return TokenResult(
                token="jwt-token",
                payload={"sub": data["device_id"], "project": data["project"], "exp": 1760000000},
            )

    monkeypatch.setattr(server_module, "DatabaseService", lambda cfg: MagicMock())
    monkeypatch.setattr(server_module, "AuthService", lambda **kwargs: FakeAuthService())

    cfg = _make_server_config(tmp_path=tmp_path, admin_networks=admin_networks)
    return create_app(cfg)


def test_admin_generate_token_allows_default_localhost(tmp_path, monkeypatch):
    app = _build_app(tmp_path, monkeypatch)
    client = app.test_client()

    response = client.post(
        "/admin/generate_token",
        headers={"X-Admin-Secret": "super-admin-secret"},
        json={"device_id": "device-1", "project": "project-1"},
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert response.status_code == 200


def test_admin_generate_token_rejects_disallowed_network_by_default(tmp_path, monkeypatch):
    app = _build_app(tmp_path, monkeypatch)
    client = app.test_client()

    response = client.post(
        "/admin/generate_token",
        headers={"X-Admin-Secret": "super-admin-secret"},
        json={"device_id": "device-1", "project": "project-1"},
        environ_overrides={"REMOTE_ADDR": "8.8.8.8"},
    )

    assert response.status_code == 403


def test_admin_generate_token_honors_configured_networks(tmp_path, monkeypatch):
    app = _build_app(tmp_path, monkeypatch, admin_networks=["192.168.20.0/24"])
    client = app.test_client()

    allowed = client.post(
        "/admin/generate_token",
        headers={"X-Admin-Secret": "super-admin-secret"},
        json={"device_id": "device-1", "project": "project-1"},
        environ_overrides={"REMOTE_ADDR": "192.168.20.42"},
    )
    assert allowed.status_code == 200

    denied = client.post(
        "/admin/generate_token",
        headers={"X-Admin-Secret": "super-admin-secret"},
        json={"device_id": "device-1", "project": "project-1"},
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert denied.status_code == 403
