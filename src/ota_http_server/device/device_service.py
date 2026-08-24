# device_service.py

from ota_http_server.core.config import Config
from ota_http_server.core.data_models import User, Project, Device
from ota_http_server.database.database_service import DatabaseService
from ota_http_server.core.formatters import DeviceFormatter, DeviceListItemFormatter
from ota_http_server.logger import get_app_logger
from ota_http_server.logger.admin_activity_logger import normalize_admin_activity_action
from ota_http_server.target.target_service import DEFAULT_TARGET_NAME

logger = get_app_logger(__name__)

class DeviceService:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.admin_activity_logger = self.cfg.config.get("admin_activity_logger")

    # CLI command handler for user operations

    def command_handler(self) -> None:
        command = self.cfg.config.get('device_command')
        logger.verbose("Handling device command: %s", command)

        # these handlers expect their parameters in self.cfg.config
        handlers= {
            "add": self._add_device,
            "change-target": self._change_target,
            "enable": self._enable_device,
            "disable": self._disable_device,
            "get": self._get_device,
            "list": self._list_devices
        }

        handler = handlers.get(command)
        if handler is not None:
            action = normalize_admin_activity_action(command)
            try:
                handler()
                self._log_admin_activity(command=action, outcome="success")
            except Exception as exc:
                self._log_admin_activity(command=action, outcome="failed", error=str(exc))
                raise
        else:
            logger.error("Invalid device command received: %s", command)

    def _log_admin_activity(self, command: str | None, outcome: str, error: str | None = None) -> None:
        if command is None or self.admin_activity_logger is None:
            return
        self.admin_activity_logger.log_activity(
            interface="cli",
            entity="device",
            action=command,
            outcome=outcome,
            target={
                "device_id": self.cfg.config["parameters"].get("device_id"),
                "device_uuid": self.cfg.config["parameters"].get("device_uuid"),
                "project_id": self.cfg.config["parameters"].get("device_pid"),
                "target_id": self.cfg.config["parameters"].get("target_id"),
                "target_name": self.cfg.config["parameters"].get("target_name"),
            },
            error=error,
        )

    def _add_device(self) -> None:
        uuid = self.cfg.config["parameters"]["device_uuid"]
        pid = self.cfg.config["parameters"]["device_pid"]
        model = self.cfg.config["parameters"]["device_model"]
        if model is None:
            model = "Unknown"
        serial_number = self.cfg.config["parameters"]["device_serial_number"]
        current_version = self.cfg.config["parameters"]["device_current_version"]
        if current_version is None:
            current_version = "0.0.0"
        target_id = self._resolve_target_id()

        device = Device(
            id=None,
            uuid=uuid,
            project_id=pid,
            target_id=target_id,
            model=model,
            serial_number=serial_number,
            current_version=current_version,
            last_seen=None,
            is_active=True,
            created_at=None,
            updated_at=None
            )

        db_service: DatabaseService = self.cfg.config["db_service"]
        db_service.device_add(device)

    def _resolve_target_id(self) -> int:
        db_service: DatabaseService = self.cfg.config["db_service"]
        target_id = self.cfg.config["parameters"].get("target_id")
        target_name = self.cfg.config["parameters"].get("target_name")

        if target_id is not None:
            target = db_service.target_get_by_id(target_id)
            if target is None:
                raise ValueError(f"Target with ID {target_id} does not exist")
            if target.id is None:
                raise ValueError(f"Target with ID {target_id} is missing its database identifier")
            return target.id

        if target_name is not None:
            target = db_service.target_get_by_name(target_name)
            if target is None:
                raise ValueError(f"Target with name '{target_name}' does not exist")
            if target.id is None:
                raise ValueError(f"Target with name '{target_name}' is missing its database identifier")
            return target.id

        target = db_service.target_get_by_name(DEFAULT_TARGET_NAME)
        if target is None:
            raise ValueError(f"Target with name '{DEFAULT_TARGET_NAME}' does not exist")
        if target.id is None:
            raise ValueError(f"Target with name '{DEFAULT_TARGET_NAME}' is missing its database identifier")
        return target.id

    def _change_target(self) -> None:
        id = self.cfg.config["parameters"]["device_id"]
        uuid = self.cfg.config["parameters"]["device_uuid"]
        target_id = self._resolve_target_id()

        db_service: DatabaseService = self.cfg.config["db_service"]

        if id is not None:
            db_service.device_change_target_by_id(id, target_id)
            return
        if uuid is not None:
            db_service.device_change_target_by_name(uuid, target_id)
            return

        raise ValueError("Device id or uuid must be provided")

    def _enable_device(self) -> None:
        id = self.cfg.config["parameters"]["device_id"]
        uuid = self.cfg.config["parameters"]["device_uuid"]

        db_service: DatabaseService = self.cfg.config["db_service"]

        if id is not None:
            db_service.device_enable_by_id(id)
            return
        if uuid is not None:
            db_service.device_enable_by_name(uuid)
            return

        raise ValueError(
            "Device id or uuid must be provided"
        )

    def _disable_device(self) -> None:
        id = self.cfg.config["parameters"]["device_id"]
        uuid = self.cfg.config["parameters"]["device_uuid"]

        db_service: DatabaseService = self.cfg.config["db_service"]

        if id is not None:
            db_service.device_disable_by_id(id)
            return
        if uuid is not None:
            db_service.device_disable_by_name(uuid)
            return

        raise ValueError(
            "Device id or uuid must be provided"
        )

    def _get_device(self) -> None:
        id = self.cfg.config["parameters"]["device_id"]
        uuid = self.cfg.config["parameters"]["device_uuid"]

        db_service: DatabaseService = self.cfg.config["db_service"]

        if id is not None:
            device = db_service.device_get_by_id(id)
            if device:
                logger.info("Device found: %s", device)
            else:
                logger.info("Device with ID %d not found.", id)
            return

        if uuid is not None:
            device = db_service.device_get_by_name(uuid)
            if device:
                logger.info("Device found: %s", device)
            else:
                logger.info("Device with UUID %s not found", uuid)
            return

        raise ValueError(
            "Device id or uuid must be provided"
        )

    def _list_devices(self) -> None:
        db_service: DatabaseService = self.cfg.config["db_service"]
        device_status = self.cfg.config["parameters"].get("device_status")
        is_active = None if device_status is None else device_status == "enabled"
        project_id = self.cfg.config["parameters"].get("device_pid")

        if self.cfg.config["parameters"]["device_record"]:
            devices = db_service.device_get_record(
                is_active=is_active,
                project_id=project_id,
            )
            if devices:
                logger.info("\n%s",DeviceFormatter.format_list(devices))
            else:
                logger.info("No devices found.")
        else:
            devices = db_service.device_get_list(
                is_active=is_active,
                project_id=project_id,
            )
            if devices:
                logger.info("\n%s",DeviceListItemFormatter.format_list(devices))
            else:
                logger.info("No devices found.")
