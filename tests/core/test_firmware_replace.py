import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from ota_http_server.core.config import parse_args
from ota_http_server.core.data_models import Firmware, Project, User
from ota_http_server.device.device_service import DeviceService
from ota_http_server.firmware.filename_validation import validate_firmware_filename
from ota_http_server.firmware.firmware_service import FirmwareService
from ota_http_server.user.user_service import UserService


def test_add_firmware_accepts_plain_filename(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    project_dir = tmp_path / "proj"
    project_dir.mkdir()
    source_file = tmp_path / "fresh.bin"
    source_file.write_bytes(b"new-content")

    cfg = SimpleNamespace()
    cfg.config = {
        "parameters": {
            "firmware_pid": 12,
            "firmware_version": "1.2.3",
            "firmware_file": source_file.name,
            "firmware_release_notes": "notes",
            "firmware_release_channel": "stable",
            "app_paths": SimpleNamespace(ensure_project_dir=lambda project_name: project_dir),
        },
        "db_service": MagicMock(),
    }
    cfg.config["db_service"].project_get_by_id.return_value = Project(
        id=12,
        name="proj",
        display_name="Proj",
        description="",
        created_by=1,
        is_active=True,
        created_at=None,
        updated_at=None,
    )
    cfg.config["db_service"].firmware_get_record.return_value = []

    service = FirmwareService(cfg)
    service._add_firmware()

    assert (project_dir / "fresh.bin").read_bytes() == b"new-content"
    cfg.config["db_service"].firmware_add.assert_called_once()
    stored_firmware = cfg.config["db_service"].firmware_add.call_args.args[0]
    assert stored_firmware.filename == "fresh.bin"


def test_add_firmware_rejects_path_traversal_filename(tmp_path, monkeypatch):
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    monkeypatch.chdir(work_dir)

    project_dir = tmp_path / "proj"
    project_dir.mkdir()
    source_file = tmp_path / "fresh.bin"
    source_file.write_bytes(b"new-content")

    cfg = SimpleNamespace()
    cfg.config = {
        "parameters": {
            "firmware_pid": 12,
            "firmware_version": "1.2.3",
            "firmware_file": str(Path("..") / source_file.name),
            "firmware_release_notes": "notes",
            "firmware_release_channel": "stable",
            "app_paths": SimpleNamespace(ensure_project_dir=lambda project_name: project_dir),
        },
        "db_service": MagicMock(),
    }
    cfg.config["db_service"].project_get_by_id.return_value = Project(
        id=12,
        name="proj",
        display_name="Proj",
        description="",
        created_by=1,
        is_active=True,
        created_at=None,
        updated_at=None,
    )
    cfg.config["db_service"].firmware_get_record.return_value = []

    service = FirmwareService(cfg)

    with pytest.raises(ValueError, match="plain filename"):
        service._add_firmware()

    cfg.config["db_service"].firmware_add.assert_not_called()


@pytest.mark.parametrize("filename", ["../outside.bin", "..\\outside.bin", ".", "..", "nested/file.bin"])
def test_validate_firmware_filename_rejects_path_elements(filename):
    with pytest.raises(ValueError, match="plain filename"):
        validate_firmware_filename(filename)


def test_firmware_route_rejects_unsafe_stored_filename(tmp_path, monkeypatch):
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
    db_service.firmware_get_by_project_version.return_value = Firmware(
        id=7,
        project_id=12,
        version="1.2.3",
        filename="../outside.bin",
        file_size=11,
        checksum="some-sha",
        release_notes="",
        channel="stable",
        is_active=True,
        created_at=None,
        updated_at=None,
    )

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
            "ota_audit_log": "audit.csv",
            "app_paths": SimpleNamespace(project_dir=lambda project_name: project_dir, logs_dir=tmp_path),
        }
    }

    app = create_app(cfg)
    response = app.test_client().get("/firmware/proj/1.2.3")

    assert response.status_code == 404


def test_latest_firmware_route_rejects_unsafe_stored_filename(tmp_path, monkeypatch):
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
    db_service.firmware_get_record.return_value = [
        Firmware(
            id=7,
            project_id=12,
            version="1.2.3",
            filename="..\\outside.bin",
            file_size=11,
            checksum="some-sha",
            release_notes="",
            channel="stable",
            is_active=True,
            created_at=None,
            updated_at=None,
        )
    ]

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
            "ota_audit_log": "audit.csv",
            "app_paths": SimpleNamespace(project_dir=lambda project_name: project_dir, logs_dir=tmp_path),
        }
    }

    app = create_app(cfg)
    response = app.test_client().get("/firmware/proj/latest")

    assert response.status_code == 404


def test_parse_args_replace_command(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ota_http_server",
            "--dbtype",
            "sqlite",
            "firmware",
            "replace",
            "--pid",
            "12",
            "--version",
            "1.2.3",
            "--file",
            "/tmp/new.bin",
        ],
    )

    parsed = parse_args()

    assert parsed.firmware_command == "replace"
    assert parsed.firmware_pid == 12
    assert parsed.firmware_version == "1.2.3"
    assert parsed.firmware_file == "/tmp/new.bin"


def test_parse_args_replace_command_by_id(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ota_http_server",
            "--dbtype",
            "sqlite",
            "firmware",
            "replace",
            "--id",
            "7",
            "--file",
            "/tmp/new.bin",
        ],
    )

    parsed = parse_args()

    assert parsed.firmware_command == "replace"
    assert parsed.firmware_id == 7
    assert parsed.firmware_file == "/tmp/new.bin"


def test_replace_firmware_updates_existing_record(tmp_path):
    project_dir = tmp_path / "proj"
    project_dir.mkdir()
    old_file = project_dir / "old.bin"
    old_file.write_bytes(b"old-content")

    source_file = tmp_path / "fresh.bin"
    source_file.write_bytes(b"new-content")

    cfg = SimpleNamespace()
    cfg.config = {
        "parameters": {
            "firmware_pid": 12,
            "firmware_version": "1.2.3",
            "firmware_file": str(source_file),
            "app_paths": SimpleNamespace(ensure_project_dir=lambda project_name: project_dir),
        },
        "db_service": MagicMock(),
    }
    cfg.config["db_service"].project_get_by_id.return_value = Project(
        id=12,
        name="proj",
        display_name="Proj",
        description="",
        created_by=1,
        is_active=True,
        created_at=None,
        updated_at=None,
    )
    cfg.config["db_service"].firmware_get_by_project_version.return_value = Firmware(
        id=7,
        project_id=12,
        version="1.2.3",
        filename="old.bin",
        file_size=11,
        checksum="old-checksum",
        release_notes="",
        channel="stable",
        is_active=True,
        created_at=None,
        updated_at=None,
    )
    cfg.config["db_service"].firmware_replace.return_value = Firmware(
        id=7,
        project_id=12,
        version="1.2.3",
        filename="fresh.bin",
        file_size=11,
        checksum="some-sha",
        release_notes="",
        channel="stable",
        is_active=True,
        created_at=None,
        updated_at=None,
    )

    service = FirmwareService(cfg)
    service._replace_firmware()

    assert not old_file.exists()
    assert (project_dir / "fresh.bin").read_bytes() == b"new-content"
    cfg.config["db_service"].firmware_replace.assert_called_once()
    args = cfg.config["db_service"].firmware_replace.call_args.kwargs
    assert args["firmware_id"] == 7
    assert args["filename"] == "fresh.bin"


def test_replace_firmware_updates_existing_record_by_id(tmp_path):
    project_dir = tmp_path / "proj"
    project_dir.mkdir()
    old_file = project_dir / "old.bin"
    old_file.write_bytes(b"old-content")

    source_file = tmp_path / "fresh.bin"
    source_file.write_bytes(b"new-content")

    cfg = SimpleNamespace()
    cfg.config = {
        "parameters": {
            "firmware_id": 7,
            "firmware_file": str(source_file),
            "app_paths": SimpleNamespace(ensure_project_dir=lambda project_name: project_dir),
        },
        "db_service": MagicMock(),
    }
    cfg.config["db_service"].firmware_get_by_id.return_value = Firmware(
        id=7,
        project_id=12,
        version="1.2.3",
        filename="old.bin",
        file_size=11,
        checksum="old-checksum",
        release_notes="",
        channel="stable",
        is_active=True,
        created_at=None,
        updated_at=None,
    )
    cfg.config["db_service"].project_get_by_id.return_value = Project(
        id=12,
        name="proj",
        display_name="Proj",
        description="",
        created_by=1,
        is_active=True,
        created_at=None,
        updated_at=None,
    )
    cfg.config["db_service"].firmware_replace.return_value = Firmware(
        id=7,
        project_id=12,
        version="1.2.3",
        filename="fresh.bin",
        file_size=11,
        checksum="some-sha",
        release_notes="",
        channel="stable",
        is_active=True,
        created_at=None,
        updated_at=None,
    )

    service = FirmwareService(cfg)
    service._replace_firmware()

    assert not old_file.exists()
    assert (project_dir / "fresh.bin").read_bytes() == b"new-content"
    cfg.config["db_service"].firmware_get_by_id.assert_called_once_with(7)
    cfg.config["db_service"].firmware_replace.assert_called_once()


def test_replace_firmware_skips_if_no_existing_version(tmp_path):
    project_dir = tmp_path / "proj"
    project_dir.mkdir()
    source_file = tmp_path / "fresh.bin"
    source_file.write_bytes(b"new-content")

    cfg = SimpleNamespace()
    cfg.config = {
        "parameters": {
            "firmware_pid": 12,
            "firmware_version": "1.2.3",
            "firmware_file": str(source_file),
            "app_paths": SimpleNamespace(ensure_project_dir=lambda project_name: project_dir),
        },
        "db_service": MagicMock(),
    }
    cfg.config["db_service"].project_get_by_id.return_value = Project(
        id=12,
        name="proj",
        display_name="Proj",
        description="",
        created_by=1,
        is_active=True,
        created_at=None,
        updated_at=None,
    )
    cfg.config["db_service"].firmware_get_by_project_version.return_value = None

    service = FirmwareService(cfg)
    service._replace_firmware()

    assert not any(project_dir.iterdir())
    cfg.config["db_service"].firmware_replace.assert_not_called()


def test_parse_args_user_list_status_filters(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ota_http_server",
            "--dbtype",
            "sqlite",
            "user",
            "list",
            "--record",
            "--enabled",
        ],
    )

    parsed = parse_args()
    assert parsed.user_command == "list"
    assert parsed.user_record is True
    assert parsed.user_status == "enabled"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ota_http_server",
            "--dbtype",
            "sqlite",
            "user",
            "list",
            "--disabled",
        ],
    )

    parsed = parse_args()
    assert parsed.user_record is None
    assert parsed.user_status == "disabled"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ota_http_server",
            "--dbtype",
            "sqlite",
            "user",
            "list",
            "--enabled",
            "--disabled",
        ],
    )

    with pytest.raises(SystemExit):
        parse_args()


def test_user_service_filters_list_by_status():
    cfg = SimpleNamespace()
    cfg.config = {
        "parameters": {"user_status": "enabled", "user_record": True},
        "db_service": MagicMock(),
    }
    cfg.config["db_service"].user_get_record.return_value = [
        User(1, "alpha", "hash1", "a@example.com", "admin", True, None, None),
        User(2, "beta", "hash2", "b@example.com", "viewer", False, None, None),
    ]

    UserService(cfg)._list_users()

    cfg.config["db_service"].user_get_record.assert_called_once_with(is_active=True)


def test_parse_args_device_list_filters(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ota_http_server",
            "--dbtype",
            "sqlite",
            "device",
            "list",
            "--record",
            "--enabled",
            "--pid",
            "14",
        ],
    )

    parsed = parse_args()
    assert parsed.device_command == "list"
    assert parsed.device_record is True
    assert parsed.device_status == "enabled"
    assert parsed.device_pid == 14

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ota_http_server",
            "--dbtype",
            "sqlite",
            "device",
            "list",
            "--disabled",
        ],
    )
    parsed = parse_args()
    assert parsed.device_record is None
    assert parsed.device_status == "disabled"
    assert parsed.device_pid is None

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ota_http_server",
            "--dbtype",
            "sqlite",
            "device",
            "list",
            "--enabled",
            "--disabled",
        ],
    )
    with pytest.raises(SystemExit):
        parse_args()


def test_device_service_filters_record_list_by_status_and_project_id():
    cfg = SimpleNamespace()
    cfg.config = {
        "parameters": {
            "device_record": True,
            "device_status": "disabled",
            "device_pid": 12,
        },
        "db_service": MagicMock(),
    }
    cfg.config["db_service"].device_get_record.return_value = []

    DeviceService(cfg)._list_devices()

    cfg.config["db_service"].device_get_record.assert_called_once_with(
        is_active=False,
        project_id=12,
    )
    cfg.config["db_service"].device_get_list.assert_not_called()
