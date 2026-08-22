import json
from types import SimpleNamespace
from unittest.mock import MagicMock

from ota_http_server.firmware.firmware_service import FirmwareService
from ota_http_server.logger.admin_activity_logger import build_admin_activity_logger
from ota_http_server.logger.rotation import RotationPolicy, SizeAndTimeRotatingFileHandler, create_rotating_file_handler
from ota_http_server.user.user_service import UserService


def test_build_admin_activity_logger_writes_event_to_logs_directory(tmp_path):
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()

    cfg = SimpleNamespace()
    cfg.config = {
        "parameters": {
            "app_paths": SimpleNamespace(logs_dir=logs_dir),
            "admin_activity_log": "admin_activity.log",
            "log_rotation_strategy": "hybrid",
            "log_rotation_max_bytes": 1024,
            "log_rotation_backup_count": 2,
            "log_rotation_when": "midnight",
            "log_rotation_interval": 1,
        }
    }

    activity_logger = build_admin_activity_logger(cfg)
    activity_logger.log_activity(
        interface="cli",
        entity="user",
        action="list",
        outcome="success",
        target={"username": "admin"},
    )

    log_path = logs_dir / "admin_activity.log"
    assert log_path.exists()
    payload = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert payload["interface"] == "cli"
    assert payload["entity"] == "user"
    assert payload["action"] == "list"


def test_create_rotating_file_handler_hybrid_strategy(tmp_path):
    log_path = tmp_path / "generic.log"
    policy = RotationPolicy(
        strategy="hybrid",
        max_bytes=1024,
        backup_count=3,
        when="midnight",
        interval=1,
        utc=True,
    )

    handler = create_rotating_file_handler(log_path, policy)
    assert isinstance(handler, SizeAndTimeRotatingFileHandler)


def test_user_service_logs_admin_activity_for_cli_list():
    cfg = SimpleNamespace()
    cfg.config = {
        "user_command": "list",
        "parameters": {
            "user_record": False,
            "user_status": None,
            "user_id": None,
            "username": None,
        },
        "db_service": MagicMock(),
        "admin_activity_logger": MagicMock(),
    }
    cfg.config["db_service"].user_get_list.return_value = []

    service = UserService(cfg)
    service.command_handler()

    cfg.config["admin_activity_logger"].log_activity.assert_called_once()
    kwargs = cfg.config["admin_activity_logger"].log_activity.call_args.kwargs
    assert kwargs["interface"] == "cli"
    assert kwargs["entity"] == "user"
    assert kwargs["action"] == "list"
    assert kwargs["outcome"] == "success"


def test_firmware_service_maps_delete_to_remove_for_activity_logging():
    cfg = SimpleNamespace()
    cfg.config = {
        "firmware_command": "delete",
        "parameters": {
            "firmware_id": 7,
            "firmware_pid": None,
            "firmware_version": None,
        },
        "db_service": MagicMock(),
        "admin_activity_logger": MagicMock(),
    }

    service = FirmwareService(cfg)
    service._delete_firmware = MagicMock()  # type: ignore[method-assign]
    service.command_handler()

    kwargs = cfg.config["admin_activity_logger"].log_activity.call_args.kwargs
    assert kwargs["entity"] == "firmware"
    assert kwargs["action"] == "remove"
    assert kwargs["outcome"] == "success"
