# project_service.py

from ota_http_server.core.config import Config
from ota_http_server.core.data_models import User, Project
from ota_http_server.core.formatters import ProjectFormatter,ProjectListItemFormatter
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
        name = self.cfg.config["parameters"]["project_name"]
        display_name = self.cfg.config["parameters"]["project_display_name"]
        if display_name is None:
            display_name = name
        description = self.cfg.config["parameters"]["project_description"]
        if description is None:
            description = ""
        created_by = self.cfg.config["parameters"]["created_by"]

        project = Project(id=None, name=name, display_name=display_name, description=description, created_by=created_by, is_active=True, created_at=None, updated_at=None)

        db_service: DatabaseService = self.cfg.config["db_service"]
        db_service.project_add(project)

    def _enable_project(self) -> None:
        db_service: DatabaseService = self.cfg.config["db_service"]
        project_id = self.cfg.config["parameters"]['project_id']
        project_name = self.cfg.config['parameters']['project_name']
        if project_id is not None:
            db_service.project_enable_by_id(project_id)
            return
        if project_name is not None:
            db_service.project_enable_by_name(project_name)
            return

        raise ValueError(
            "Project id or name must be provided"
        )

    def _disable_project(self) -> None:
        db_service: DatabaseService = self.cfg.config["db_service"]
        project_id = self.cfg.config["parameters"]['project_id']
        project_name = self.cfg.config['parameters']['project_name']
        if project_id is not None:
            db_service.project_disable_by_id(project_id)
            return
        if project_name is not None:
            db_service.project_disable_by_name(project_name)
            return

        raise ValueError(
            "Project id or name must be provided"
        )

    def _get_project(self) -> None:
        db_service: DatabaseService = self.cfg.config["db_service"]
        project_id = self.cfg.config["parameters"]['project_id']
        project_name = self.cfg.config['parameters']['project_name']
        if project_id is not None:
            project = db_service.project_get_by_id(project_id)
            if project:
                logger.verbose("Project found: %s", project)
            else:
                logger.verbose("Project with ID %d not found.", project_id)
            return
        if project_name is not None:
            project = db_service.project_get_by_name(project_name)
            if project:
                logger.verbose("Project found: %s", project)
            else:
                logger.verbose("Project with name '%s' not found.", project_name)
            return

        raise ValueError(
            "Project id or name must be provided"
        )

    def _list_projects(self) -> None:
        db_service: DatabaseService = self.cfg.config["db_service"]
        project_record = self.cfg.config["parameters"].get("project_record", False)
        if project_record:
            projects = db_service.project_get_record()
            if projects:
                logger.verbose("\n%s", ProjectFormatter.format_list(projects))
            else:
                logger.info("No projects found.")
        else:
            projects = db_service.project_get_list()
            if projects:
                logger.verbose("\n%s", ProjectListItemFormatter.format_list(projects))
            else:
                logger.info("No projects found.")
