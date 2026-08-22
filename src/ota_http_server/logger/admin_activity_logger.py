import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ota_http_server.logger.rotation import RotationPolicy, create_rotating_file_handler

SUPPORTED_ADMIN_ACTIVITY_ACTIONS = {"add", "enable", "disable", "remove", "list", "get"}
ADMIN_ACTIVITY_ACTION_ALIASES = {
    "delete": "remove",
}


def normalize_admin_activity_action(action: str | None) -> str | None:
    if action is None:
        return None
    normalized = ADMIN_ACTIVITY_ACTION_ALIASES.get(action, action)
    if normalized in SUPPORTED_ADMIN_ACTIVITY_ACTIONS:
        return normalized
    return None


class AdminActivityLogger:
    def __init__(self, log_file_path: Path, rotation_policy: RotationPolicy):
        self.log_file_path = log_file_path
        self.rotation_policy = rotation_policy
        self._logger_name = f"ota_http_server.admin_activity.{self.log_file_path}"
        self._logger = logging.getLogger(self._logger_name)
        self._configure_logger()

    def _configure_logger(self) -> None:
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False

        if self._logger.handlers:
            return

        handler = create_rotating_file_handler(self.log_file_path, self.rotation_policy)
        handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(handler)

    def log_activity(
        self,
        *,
        interface: str,
        entity: str,
        action: str,
        outcome: str,
        target: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        event: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "interface": interface,
            "entity": entity,
            "action": action,
            "outcome": outcome,
            "target": target or {},
        }
        if error is not None:
            event["error"] = error

        self._logger.info(json.dumps(event, separators=(",", ":"), sort_keys=True))


def build_admin_activity_logger(cfg: Any) -> AdminActivityLogger:
    app_paths = cfg.config["parameters"]["app_paths"]

    log_name = cfg.config["parameters"]["admin_activity_log"]
    log_name_path = Path(log_name)
    if log_name_path.name != log_name:
        raise ValueError(
            f"Admin activity log must be a file name inside logs directory. Received: {log_name}"
        )

    log_file_path = (app_paths.logs_dir / log_name_path).resolve()
    rotation_policy = RotationPolicy(
        strategy=str(cfg.config["parameters"]["log_rotation_strategy"]),
        max_bytes=int(cfg.config["parameters"]["log_rotation_max_bytes"]),
        backup_count=int(cfg.config["parameters"]["log_rotation_backup_count"]),
        when=str(cfg.config["parameters"]["log_rotation_when"]),
        interval=int(cfg.config["parameters"]["log_rotation_interval"]),
        utc=True,
    )
    return AdminActivityLogger(log_file_path=log_file_path, rotation_policy=rotation_policy)
