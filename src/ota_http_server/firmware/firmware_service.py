# firmware_service.py

from ota_http_server.core.config import Config
from ota_http_server.core.data_models import User, Project, Device, Firmware
from ota_http_server.database.database_service import DatabaseService
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
            logger.debug("Invalid user command received: %s", command)

    def _add_firmware(self) -> None:
        pass

    def _enable_firmware(self) -> None:
        pass

    def _disable_firmware(self) -> None:
        pass

    def _get_firmware(self) -> None:
        pass

    def _list_firmware(self) -> None:
        pass

