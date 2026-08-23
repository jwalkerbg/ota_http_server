import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from ota_http_server.logger.admin_activity_logger import build_ota_download_logger


def test_build_ota_download_logger_writes_event_to_logs_directory(tmp_path):
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()

    cfg = SimpleNamespace()
    cfg.config = {
        "parameters": {
            "app_paths": SimpleNamespace(logs_dir=logs_dir),
            "ota_download_log": "ota_download.log",
            "log_rotation_strategy": "hybrid",
            "log_rotation_max_bytes": 1024,
            "log_rotation_backup_count": 2,
            "log_rotation_when": "midnight",
            "log_rotation_interval": 1,
        }
    }

    ota_logger = build_ota_download_logger(cfg)
    ota_logger.log_download(
        interface="http",
        action="download",
        outcome="success",
        target={"project": "smart_air", "version": "1.2.3"},
    )

    log_path = logs_dir / "ota_download.log"
    assert log_path.exists()
    payload = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert payload["interface"] == "http"
    assert payload["entity"] == "firmware"
    assert payload["action"] == "download"
    assert payload["target"]["project"] == "smart_air"


def test_server_download_routes_log_ota_download_requests(tmp_path, monkeypatch):
    pytest.importorskip("flask")

    from ota_http_server.core import server as server_module
    from ota_http_server.core.server import create_app

    class FakeProjectRecord:
        id = 1
        is_active = True

    class FakeDeviceRecord:
        project_id = 1
        is_active = True

    class FakeFirmwareRecord:
        id = 1
        project_id = 1
        version = "1.0.0"
        filename = "project-1-1.0.0.bin"
        is_active = True

    class FakeDBService:
        def project_get_by_name(self, project):
            return FakeProjectRecord()

        def device_get_by_name(self, device_id):
            return FakeDeviceRecord()

        def firmware_get_by_project_version(self, project_id, version):
            return FakeFirmwareRecord()

    class FakeAuthService:
        def verify_token(self, project, verify_sub=True):
            return {"sub": "device-1", "project": project}

    monkeypatch.setattr(server_module, "DatabaseService", lambda cfg: FakeDBService())
    monkeypatch.setattr(server_module, "AuthService", lambda **kwargs: FakeAuthService())

    project_dir = tmp_path / "project-1"
    project_dir.mkdir()
    file_path = project_dir / "project-1-1.0.0.bin"
    file_path.write_bytes(b"test-firmware")

    ota_download_logger = MagicMock()
    cfg = SimpleNamespace(
        config={
            "parameters": {
                "www_dir": str(tmp_path),
                "firmware_dir": "firmware",
                "url_firmware": "firmware",
                "no_jwt": False,
                "jwt_alg": "HS256",
                "jwt_expiry": 60,
                "jwt_max_expiry": 120,
                "jwt_secret": "secret",
                "jwt_issuer": "issuer",
                "jwt_audience": "audience",
                "admin_secret": "admin-secret",
                "app_paths": SimpleNamespace(
                    project_dir=lambda project_name: tmp_path / project_name,
                    logs_dir=tmp_path,
                ),
            },
            "admin_activity_logger": None,
            "ota_download_logger": ota_download_logger,
        }
    )

    app = create_app(cfg)
    client = app.test_client()
    response = client.get("/firmware/project-1/1.0.0", headers={"Authorization": "Bearer test-token"})

    assert response.status_code == 200
    ota_download_logger.log_download.assert_called_once()
    kwargs = ota_download_logger.log_download.call_args.kwargs
    assert kwargs["interface"] == "http"
    assert kwargs["action"] == "download"
    assert kwargs["outcome"] == "success"
    assert kwargs["target"]["project"] == "project-1"
