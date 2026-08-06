# project_service.py

from ota_http_server.core.config import Config
from ota_http_server.core.data_models import User, Project
from ota_http_server.database.database_service import DatabaseService
from ota_http_server.logger import get_app_logger

logger = get_app_logger(__name__)

class ProjectService:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    # CLI command handler for user operations

    def command_handler(self) -> None:
        command = self.cfg.config.get('project_command')
        logger.info("Handling project command: %s", command)

        # these handlers expect their parameters in self.cfg.config
        handlers= {
            "add": self._add_project,
            "enable": self._enable_project,
            "disable": self._disable_project,
            "get": self._get_project,
            "list": self._list_projects
        }

        handler = handlers.get(command)
        if handler is not None:
            handler()
        else:
            logger.debug("Invalid project command received: %s", command)

    def _add_project(self) -> None:
        pass

    def _enable_project(self) -> None:
        pass

    def _disable_project(self) -> None:
        pass

    def _get_project(self) -> None:
        pass

    def _list_projects(self) -> None:
        pass

