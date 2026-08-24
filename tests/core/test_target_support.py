import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

from ota_http_server.core.config import parse_args
from ota_http_server.core.data_models import Target
from ota_http_server.device.device_service import DeviceService
from ota_http_server.firmware.firmware_service import FirmwareService
from ota_http_server.target.target_service import TargetService


def test_parse_args_target_add_command(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ota_http_server",
            "--dbtype",
            "sqlite",
            "target",
            "add",
            "--name",
            "ESP32",
        ],
    )

    parsed = parse_args()

    assert parsed.command == "target"
    assert parsed.target_command == "add"
    assert parsed.target_name == "ESP32"


def test_parse_args_device_change_target_command(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ota_http_server",
            "--dbtype",
            "sqlite",
            "device",
            "change-target",
            "--uuid",
            "11111111-2222-3333-4444-555555666666",
            "--target-id",
            "4",
        ],
    )

    parsed = parse_args()

    assert parsed.command == "device"
    assert parsed.device_command == "change-target"
    assert parsed.device_uuid == "11111111-2222-3333-4444-555555666666"
    assert parsed.target_id == 4


def test_parse_args_firmware_change_target_command(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ota_http_server",
            "--dbtype",
            "sqlite",
            "firmware",
            "change-target",
            "--pid",
            "12",
            "--version",
            "1.2.3",
            "--target-name",
            "ESP32",
        ],
    )

    parsed = parse_args()

    assert parsed.command == "firmware"
    assert parsed.firmware_command == "change-target"
    assert parsed.firmware_pid == 12
    assert parsed.firmware_version == "1.2.3"
    assert parsed.target_name == "ESP32"


def test_device_add_uses_default_target_when_not_specified():
    cfg = SimpleNamespace()
    cfg.config = {
        "parameters": {
            "device_uuid": "11111111-2222-3333-4444-555555666666",
            "device_pid": 12,
            "device_model": "ESP32",
            "device_serial_number": "ABC123",
            "device_current_version": "1.2.3",
            "target_id": None,
            "target_name": None,
        },
        "db_service": MagicMock(),
    }
    cfg.config["db_service"].target_get_by_name.return_value = Target(id=1, name="Not defined")

    service = DeviceService(cfg)
    service._add_device()

    cfg.config["db_service"].device_add.assert_called_once()
    stored_device = cfg.config["db_service"].device_add.call_args.args[0]
    assert stored_device.target_id == 1


def test_device_change_target_uses_target_name_lookup():
    cfg = SimpleNamespace()
    cfg.config = {
        "parameters": {
            "device_id": None,
            "device_uuid": "11111111-2222-3333-4444-555555666666",
            "target_id": None,
            "target_name": "ESP32",
        },
        "db_service": MagicMock(),
    }
    cfg.config["db_service"].target_get_by_name.return_value = Target(id=4, name="ESP32")

    service = DeviceService(cfg)
    service._change_target()

    cfg.config["db_service"].device_change_target_by_name.assert_called_once_with(
        "11111111-2222-3333-4444-555555666666",
        4,
    )


def test_firmware_change_target_uses_target_name_lookup():
    cfg = SimpleNamespace()
    cfg.config = {
        "parameters": {
            "firmware_id": None,
            "firmware_pid": 12,
            "firmware_version": "1.2.3",
            "target_id": None,
            "target_name": "ESP32",
        },
        "db_service": MagicMock(),
    }
    cfg.config["db_service"].target_get_by_name.return_value = Target(id=4, name="ESP32")

    service = FirmwareService(cfg)
    service._change_target()

    cfg.config["db_service"].firmware_change_target_by_project_version.assert_called_once_with(
        12,
        "1.2.3",
        4,
    )


def test_target_service_adds_target():
    cfg = SimpleNamespace()
    cfg.config = {
        "parameters": {
            "target_name": "ESP32",
        },
        "db_service": MagicMock(),
    }

    service = TargetService(cfg)
    service._add_target()

    cfg.config["db_service"].target_add.assert_called_once()
    stored_target = cfg.config["db_service"].target_add.call_args.args[0]
    assert stored_target.name == "ESP32"
