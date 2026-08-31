"""
Tests for target-aware firmware selection when JWT authentication is disabled.

Task 404: Support target-aware firmware selection when JWT authentication is disabled
Tests cover both JWT and --no-jwt modes with target-specific firmware lookup.
"""

import pytest
from types import SimpleNamespace
from unittest.mock import MagicMock

from ota_http_server.core.data_models import Firmware, Project, Device


class TestNoJWTTargetAwareFirmwareSelection:
    """Test target-aware firmware selection in --no-jwt mode"""

    def _create_app(self, tmp_path, monkeypatch, use_jwt=False, device_mock=None, firmware_mock=None):
        """Helper to create a Flask app for testing."""
        pytest.importorskip("flask")
        from ota_http_server.core import server as server_module
        from ota_http_server.core.server import create_app

        project_dir = tmp_path / "proj"
        project_dir.mkdir()

        db_service = MagicMock()
        db_service.project_get_by_name.return_value = Project(
            id=12,
            name="proj",
            display_name="Proj",
            description="",
            created_by=1,
            is_active=True,
            created_at=None,
            updated_at=None,
        )
        db_service.device_get_by_name.return_value = device_mock
        db_service.firmware_get_by_project_version_target.return_value = firmware_mock
        db_service.firmware_get_record.return_value = []

        monkeypatch.setattr(server_module, "DatabaseService", lambda cfg: db_service)

        cfg = SimpleNamespace()
        cfg.config = {
            "parameters": {
                "www_dir": str(tmp_path),
                "firmware_dir": "firmware",
                "url_firmware": "firmware",
                "no_jwt": not use_jwt,
                "jwt_alg": "HS256",
                "jwt_expiry": 60,
                "jwt_max_expiry": 120,
                "jwt_secret": "secret" if use_jwt else None,
                "jwt_issuer": "issuer",
                "jwt_audience": "audience",
                "admin_secret": None,
                "app_paths": SimpleNamespace(project_dir=lambda project_name: project_dir, logs_dir=tmp_path),
            }
        }

        app = create_app(cfg)
        return app

    def test_no_jwt_missing_device_id_header_returns_400(self, tmp_path, monkeypatch):
        """In --no-jwt mode, missing X-Device-ID header should return 400 Bad Request."""
        app = self._create_app(tmp_path, monkeypatch, use_jwt=False)
        response = app.test_client().get("/firmware/proj/1.0.0")
        assert response.status_code == 400

    def test_no_jwt_missing_device_id_query_param_returns_400(self, tmp_path, monkeypatch):
        """In --no-jwt mode, missing device_id query param should return 400 Bad Request."""
        app = self._create_app(tmp_path, monkeypatch, use_jwt=False)
        response = app.test_client().get("/firmware/proj/1.0.0")
        assert response.status_code == 400

    def test_no_jwt_device_id_from_query_param(self, tmp_path, monkeypatch):
        """In --no-jwt mode, device_id can be provided via query parameter."""
        device_mock = Device(
            id=1,
            uuid="device-1",
            project_id=12,
            target_id=1,
            model="test",
            serial_number="sn",
            current_version="1.0.0",
            last_seen=None,
            is_active=True,
            created_at=None,
            updated_at=None,
        )
        firmware_mock = Firmware(
            id=1,
            project_id=12,
            target_id=1,
            version="1.0.0",
            filename="proj-1.0.0.bin",
            file_size=100,
            checksum="abc123",
            release_notes="",
            channel="stable",
            is_active=True,
            created_at=None,
            updated_at=None,
        )

        app = self._create_app(tmp_path, monkeypatch, use_jwt=False, device_mock=device_mock, firmware_mock=firmware_mock)
        
        # Create firmware file
        project_dir = tmp_path / "proj"
        (project_dir / "proj-1.0.0.bin").write_bytes(b"firmware-content")
        
        response = app.test_client().get("/firmware/proj/1.0.0?device_id=device-1")
        assert response.status_code == 200

    def test_no_jwt_device_id_from_header(self, tmp_path, monkeypatch):
        """In --no-jwt mode, device_id can be provided via X-Device-ID header."""
        device_mock = Device(
            id=1,
            uuid="device-1",
            project_id=12,
            target_id=1,
            model="test",
            serial_number="sn",
            current_version="1.0.0",
            last_seen=None,
            is_active=True,
            created_at=None,
            updated_at=None,
        )
        firmware_mock = Firmware(
            id=1,
            project_id=12,
            target_id=1,
            version="1.0.0",
            filename="proj-1.0.0.bin",
            file_size=100,
            checksum="abc123",
            release_notes="",
            channel="stable",
            is_active=True,
            created_at=None,
            updated_at=None,
        )

        app = self._create_app(tmp_path, monkeypatch, use_jwt=False, device_mock=device_mock, firmware_mock=firmware_mock)
        
        # Create firmware file
        project_dir = tmp_path / "proj"
        (project_dir / "proj-1.0.0.bin").write_bytes(b"firmware-content")
        
        response = app.test_client().get("/firmware/proj/1.0.0", headers={"X-Device-ID": "device-1"})
        assert response.status_code == 200

    def test_no_jwt_unknown_device_returns_403(self, tmp_path, monkeypatch):
        """In --no-jwt mode, unknown device should return 403 Forbidden."""
        app = self._create_app(tmp_path, monkeypatch, use_jwt=False, device_mock=None)
        response = app.test_client().get("/firmware/proj/1.0.0?device_id=unknown-device")
        assert response.status_code == 403

    def test_no_jwt_device_wrong_project_returns_403(self, tmp_path, monkeypatch):
        """In --no-jwt mode, device from different project should return 403."""
        device_mock = Device(
            id=1,
            uuid="device-1",
            project_id=99,  # Different project ID
            target_id=1,
            model="test",
            serial_number="sn",
            current_version="1.0.0",
            last_seen=None,
            is_active=True,
            created_at=None,
            updated_at=None,
        )
        app = self._create_app(tmp_path, monkeypatch, use_jwt=False, device_mock=device_mock)
        response = app.test_client().get("/firmware/proj/1.0.0?device_id=device-1")
        assert response.status_code == 403

    def test_no_jwt_inactive_device_returns_403(self, tmp_path, monkeypatch):
        """In --no-jwt mode, inactive device should return 403."""
        device_mock = Device(
            id=1,
            uuid="device-1",
            project_id=12,
            target_id=1,
            model="test",
            serial_number="sn",
            current_version="1.0.0",
            last_seen=None,
            is_active=False,  # Inactive
            created_at=None,
            updated_at=None,
        )
        app = self._create_app(tmp_path, monkeypatch, use_jwt=False, device_mock=device_mock)
        response = app.test_client().get("/firmware/proj/1.0.0?device_id=device-1")
        assert response.status_code == 403

    def test_no_jwt_firmware_uses_target_from_device(self, tmp_path, monkeypatch):
        """In --no-jwt mode, firmware lookup must use target_id from device."""
        device_mock = Device(
            id=1,
            uuid="device-1",
            project_id=12,
            target_id=99,  # Specific target
            model="test",
            serial_number="sn",
            current_version="1.0.0",
            last_seen=None,
            is_active=True,
            created_at=None,
            updated_at=None,
        )
        firmware_mock = Firmware(
            id=1,
            project_id=12,
            target_id=99,
            version="1.0.0",
            filename="proj-1.0.0.bin",
            file_size=100,
            checksum="abc123",
            release_notes="",
            channel="stable",
            is_active=True,
            created_at=None,
            updated_at=None,
        )

        app = self._create_app(tmp_path, monkeypatch, use_jwt=False, device_mock=device_mock, firmware_mock=firmware_mock)
        
        # Create firmware file
        project_dir = tmp_path / "proj"
        (project_dir / "proj-1.0.0.bin").write_bytes(b"firmware-content")
        
        response = app.test_client().get("/firmware/proj/1.0.0?device_id=device-1")
        assert response.status_code == 200

    def test_no_jwt_firmware_not_found_for_target_returns_404(self, tmp_path, monkeypatch):
        """In --no-jwt mode, firmware not available for device's target should return 404."""
        device_mock = Device(
            id=1,
            uuid="device-1",
            project_id=12,
            target_id=1,
            model="test",
            serial_number="sn",
            current_version="1.0.0",
            last_seen=None,
            is_active=True,
            created_at=None,
            updated_at=None,
        )
        # No firmware mock provided - firmware_get_by_project_version_target will return None
        app = self._create_app(tmp_path, monkeypatch, use_jwt=False, device_mock=device_mock, firmware_mock=None)
        response = app.test_client().get("/firmware/proj/1.0.0?device_id=device-1")
        assert response.status_code == 404

    def test_no_jwt_latest_firmware_requires_device(self, tmp_path, monkeypatch):
        """In --no-jwt mode, /latest endpoint must require device identification."""
        app = self._create_app(tmp_path, monkeypatch, use_jwt=False)
        response = app.test_client().get("/firmware/proj/latest")
        assert response.status_code == 400

    def test_no_jwt_latest_firmware_uses_target_specific(self, tmp_path, monkeypatch):
        """In --no-jwt mode, /latest endpoint returns firmware for device's target only."""
        pytest.importorskip("flask")
        from ota_http_server.core import server as server_module
        from ota_http_server.core.server import create_app

        project_dir = tmp_path / "proj"
        project_dir.mkdir()

        # Create two firmware records - one for target 1, one for target 2
        device_mock = Device(
            id=1,
            uuid="device-1",
            project_id=12,
            target_id=1,  # Device is for target 1
            model="test",
            serial_number="sn",
            current_version="1.0.0",
            last_seen=None,
            is_active=True,
            created_at=None,
            updated_at=None,
        )

        firmware_for_target_1 = Firmware(
            id=1,
            project_id=12,
            target_id=1,  # This firmware is for target 1
            version="2.0.0",
            filename="proj-target1-2.0.0.bin",
            file_size=100,
            checksum="abc123",
            release_notes="",
            channel="stable",
            is_active=True,
            created_at=None,
            updated_at=None,
        )

        firmware_for_target_2 = Firmware(
            id=2,
            project_id=12,
            target_id=2,  # This firmware is for target 2
            version="3.0.0",  # Higher version
            filename="proj-target2-3.0.0.bin",
            file_size=100,
            checksum="def456",
            release_notes="",
            channel="stable",
            is_active=True,
            created_at=None,
            updated_at=None,
        )

        db_service = MagicMock()
        db_service.project_get_by_name.return_value = Project(
            id=12,
            name="proj",
            display_name="Proj",
            description="",
            created_by=1,
            is_active=True,
            created_at=None,
            updated_at=None,
        )
        db_service.device_get_by_name.return_value = device_mock
        # Return all firmware records - the route should filter by target
        db_service.firmware_get_record.return_value = [firmware_for_target_1, firmware_for_target_2]

        monkeypatch.setattr(server_module, "DatabaseService", lambda cfg: db_service)

        cfg = SimpleNamespace()
        cfg.config = {
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
                "admin_secret": None,
                "app_paths": SimpleNamespace(project_dir=lambda project_name: project_dir, logs_dir=tmp_path),
            }
        }

        app = create_app(cfg)

        # Create firmware file for target 1
        (project_dir / "proj-target1-2.0.0.bin").write_bytes(b"firmware-for-target1")

        # Request /latest for device targeting target 1
        # It should return the latest firmware for target 1 (2.0.0),
        # NOT the higher version for target 2 (3.0.0)
        response = app.test_client().get("/firmware/proj/latest?device_id=device-1")
        assert response.status_code == 200
        # Verify it's the right firmware by checking the content
        assert response.data == b"firmware-for-target1"

    def test_no_jwt_disabled_firmware_returns_403(self, tmp_path, monkeypatch):
        """In --no-jwt mode, disabled firmware should return 403."""
        device_mock = Device(
            id=1,
            uuid="device-1",
            project_id=12,
            target_id=1,
            model="test",
            serial_number="sn",
            current_version="1.0.0",
            last_seen=None,
            is_active=True,
            created_at=None,
            updated_at=None,
        )
        firmware_mock = Firmware(
            id=1,
            project_id=12,
            target_id=1,
            version="1.0.0",
            filename="proj-1.0.0.bin",
            file_size=100,
            checksum="abc123",
            release_notes="",
            channel="stable",
            is_active=False,  # Disabled
            created_at=None,
            updated_at=None,
        )

        app = self._create_app(tmp_path, monkeypatch, use_jwt=False, device_mock=device_mock, firmware_mock=firmware_mock)
        response = app.test_client().get("/firmware/proj/1.0.0?device_id=device-1")
        assert response.status_code == 403
