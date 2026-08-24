from ota_http_server.core.config import Config
from ota_http_server.core.data_formatters import TargetFormatter
from ota_http_server.core.data_models import Target
from ota_http_server.database.database_service import DatabaseService
from ota_http_server.logger import get_app_logger
from ota_http_server.logger.admin_activity_logger import normalize_admin_activity_action

logger = get_app_logger(__name__)

DEFAULT_TARGET_NAME = "Not defined"


class TargetService:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.admin_activity_logger = self.cfg.config.get("admin_activity_logger")

    def command_handler(self) -> None:
        command = self.cfg.config.get("target_command")
        logger.verbose("Handling target command: %s", command)

        handlers = {
            "add": self._add_target,
            "get": self._get_target,
            "list": self._list_targets,
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
            logger.error("Invalid target command received: %s", command)

    def _log_admin_activity(self, command: str | None, outcome: str, error: str | None = None) -> None:
        if command is None or self.admin_activity_logger is None:
            return
        self.admin_activity_logger.log_activity(
            interface="cli",
            entity="target",
            action=command,
            outcome=outcome,
            target={
                "target_id": self.cfg.config["parameters"].get("target_id"),
                "target_name": self.cfg.config["parameters"].get("target_name"),
            },
            error=error,
        )

    def _add_target(self) -> None:
        db_service: DatabaseService = self.cfg.config["db_service"]
        target = Target(
            id=None,
            name=self.cfg.config["parameters"]["target_name"],
        )
        db_service.target_add(target)

    def _get_target(self) -> None:
        db_service: DatabaseService = self.cfg.config["db_service"]
        target_id = self.cfg.config["parameters"].get("target_id")
        target_name = self.cfg.config["parameters"].get("target_name")

        if target_id is not None:
            target = db_service.target_get_by_id(target_id)
            if target:
                logger.info("Target found: %s", target)
            else:
                logger.info("Target with ID %d not found.", target_id)
            return

        if target_name is not None:
            target = db_service.target_get_by_name(target_name)
            if target:
                logger.info("Target found: %s", target)
            else:
                logger.info("Target with name '%s' not found.", target_name)
            return

        raise ValueError("Target id or name must be provided")

    def _list_targets(self) -> None:
        db_service: DatabaseService = self.cfg.config["db_service"]
        targets = db_service.target_get_list()
        if targets:
            logger.info("\n%s", TargetFormatter.format_list(targets))
        else:
            logger.info("No targets found.")
