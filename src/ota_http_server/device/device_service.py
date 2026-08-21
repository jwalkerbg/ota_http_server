# device_service.py

from ota_http_server.core.config import Config
from ota_http_server.core.data_models import User, Project, Device
from ota_http_server.database.database_service import DatabaseService
from ota_http_server.core.formatters import DeviceFormatter, DeviceListItemFormatter
from ota_http_server.logger import get_app_logger

logger = get_app_logger(__name__)

class DeviceService:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    # CLI command handler for user operations

    def command_handler(self) -> None:
        command = self.cfg.config.get('device_command')
        logger.verbose("Handling device command: %s", command)

        # these handlers expect their parameters in self.cfg.config
        handlers= {
            "add": self._add_device,
            "enable": self._enable_device,
            "disable": self._disable_device,
            "get": self._get_device,
            "list": self._list_devices
        }

        handler = handlers.get(command)
        if handler is not None:
            handler()
        else:
            logger.error("Invalid device command received: %s", command)

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

        device = Device(
            id=None,
            uuid=uuid,
            project_id=pid,
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

    def _enable_device(self) -> None:
        id = self.cfg.config["parameters"]["device_id"]
        uuid = self.cfg.config["parameters"]["device_pid"]

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
        uuid = self.cfg.config["parameters"]["device_pid"]

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
        uuid = self.cfg.config["parameters"]["device_pid"]

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
