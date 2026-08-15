import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

from ota_http_server.core.config import parse_args
from ota_http_server.core.data_models import Firmware, Project
from ota_http_server.firmware.firmware_service import FirmwareService


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
