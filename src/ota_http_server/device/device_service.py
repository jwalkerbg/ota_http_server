# device_service.py

from ota_http_server.core.config import Config
from ota_http_server.core.data_models import User, Project, Device
from ota_http_server.database.database_service import DatabaseService
from ota_http_server.logger import get_app_logger

logger = get_app_logger(__name__)

class DeviceService:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    # CLI command handler for user operations

    def command_handler(self) -> None:
        command = self.cfg.config.get('device_command')
        logger.info("Handling device command: %s", command)

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
            logger.debug("Invalid user command received: %s", command)

    def _add_device(self) -> None:
        pass

    def _enable_device(self) -> None:
        pass

    def _disable_device(self) -> None:
        pass

    def _get_device(self) -> None:
        pass

    def _list_devices(self) -> None:
        pass

