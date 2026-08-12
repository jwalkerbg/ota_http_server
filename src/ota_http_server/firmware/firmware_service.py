# firmware_service.py

from ota_http_server.core.config import Config
from ota_http_server.core.data_models import User, Project, Device, Firmware
from ota_http_server.database.database_service import DatabaseService
from ota_http_server.core.formatters import FirmwareFormatter, FirmwareListItemFormatter
from ota_http_server.logger import get_app_logger

logger = get_app_logger(__name__)

class FirmwareService:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    # CLI command handler for user operations

    def command_handler(self) -> None:
        command = self.cfg.config.get('firmware_command')
        logger.info("Handling firmware command: %s", command)

        # these handlers expect their parameters in self.cfg.config
        handlers= {
            "add": self._add_firmware,
            "enable": self._enable_firmware,
            "disable": self._disable_firmware,
            "get": self._get_firmware,
            "list": self._list_firmware
        }

        handler = handlers.get(command)
        if handler is not None:
            handler()
        else:
            logger.debug("Invalid firmware command received: %s", command)

    def _add_firmware(self) -> None:
        pid = self.cfg.config["parameters"]["firmware_pid"]
        version = self.cfg.config["parameters"]["firmware_version"]
        file_path = self.cfg.config["parameters"]["firmware_file"]
        release_notes = self.cfg.config["parameters"]["firmware_release_notes"]
        release_channel = self.cfg.config["parameters"]["firmware_release_channel"]

        # must measure file_size here
        # must calculate checksum here

        firmware = Firmware(
            id=None,
            project_id=pid,
            version=version,
            filename=file_path,
            file_size=0,
            checksum="",
            release_notes=release_notes,
            channel=release_channel,
            is_active=True,
            created_at=None,
            updated_at=None
        )

        db_service: DatabaseService = self.cfg.config["db_service"]
        db_service.add_firmware(firmware)

    def _enable_firmware(self) -> None:
        id = self.cfg.config["parameters"]["firmware_id"]
        pid = self.cfg.config["parameters"]["firmware_pid"]
        version = self.cfg.config["parameters"]["firmware_version"]

        db_service: DatabaseService = self.cfg.config["db_service"]

        if id is not None:

            db_service.enable_firmware_by_id(id)
            return

        if pid is not None and version is not None:
            db_service.enable_firmware_by_project_version(pid, version)
            return

        raise ValueError(
            "Firmware id or project id plus version must be provided"
        )

    def _disable_firmware(self) -> None:
        id = self.cfg.config["parameters"]["firmware_id"]
        pid = self.cfg.config["parameters"]["firmware_pid"]
        version = self.cfg.config["parameters"]["firmware_version"]

        db_service: DatabaseService = self.cfg.config["db_service"]

        if id is not None:
            db_service.disable_firmware_by_id(id)
            return

        if pid is not None and version is not None:
            db_service.disable_firmware_by_project_version(pid, version)
            return

        raise ValueError(
            "Firmware id or project id plus version must be provided"
        )

    def _get_firmware(self) -> None:
        id = self.cfg.config["parameters"]["firmware_id"]
        pid = self.cfg.config["parameters"]["firmware_pid"]
        version = self.cfg.config["parameters"]["firmware_version"]

        db_service: DatabaseService = self.cfg.config["db_service"]

        if id is not None:
            firmware = db_service.get_firmware_by_id(id)
            if firmware:
                logger.verbose("Firmware found: %s", firmware)
            else:
                logger.verbose("Firmware with ID = %d not found", id)
            return

        if pid is not None and version is not None:
            firmware = db_service.firmware_get_by_project_version(project_id=pid, version=version)
            if firmware:
                logger.verbose("Firmware found: %s", firmware)
            else:
                logger.verbose("Firmware with pid = %d and version = %s not found", pid, version)
            return

        raise ValueError(
            "Firmware id or project id plus version must be provided"
        )

    def _list_firmware(self) -> None:
        db_service: DatabaseService = self.cfg.config["db_service"]

        if self.cfg.config["parameters"]["firmware_record"] == True:
            firmware = db_service.firmware_get_record()
            if firmware:
                logger.verbose("\n%s",FirmwareFormatter.format_list(firmware))
            else:
                logger.info("No firmware found.")

        else:
            firmware = db_service.firmware_get_list()
            if firmware:
                logger.verbose("\n%s\n",FirmwareListItemFormatter.format_list(firmware))
            else:
                logger.info("No firmware found.")

