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


class JsonFileLogger:
    def __init__(self, log_file_path: Path, rotation_policy: RotationPolicy, *, logger_name: str):
        self.log_file_path = log_file_path
        self.rotation_policy = rotation_policy
        self._logger_name = logger_name
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

    def log_event(
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


class AdminActivityLogger(JsonFileLogger):
    def __init__(self, log_file_path: Path, rotation_policy: RotationPolicy):
        super().__init__(
            log_file_path,
            rotation_policy,
            logger_name=f"ota_http_server.admin_activity.{log_file_path.name}",
        )

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
        self.log_event(
            interface=interface,
            entity=entity,
            action=action,
            outcome=outcome,
            target=target,
            error=error,
        )


class ServerOtaLogger(JsonFileLogger):
    def __init__(self, log_file_path: Path, rotation_policy: RotationPolicy):
        super().__init__(
            log_file_path,
            rotation_policy,
            logger_name=f"ota_http_server.ota_download.{log_file_path.name}",
        )

    def log_activity(
        self,
        *,
        interface: str,
        action: str,
        outcome: str,
        target: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        self.log_download(
            interface=interface,
            action=action,
            outcome=outcome,
            target=target,
            error=error,
        )

    def log_download(
        self,
        *,
        interface: str,
        action: str,
        outcome: str,
        target: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        self.log_event(
            interface=interface,
            entity="firmware",
            action=action,
            outcome=outcome,
            target=target,
            error=error,
        )


def _resolve_log_path(cfg: Any, *, log_key: str, default_log_name: str) -> Path:
    app_paths = cfg.config["parameters"]["app_paths"]
    settings = cfg.config["parameters"]
    log_name = settings.get(log_key)
    if log_name is None and log_key == "ota_download_log":
        log_name = settings.get("ota_audit_log") or default_log_name
    if log_name is None:
        log_name = default_log_name
    log_name_path = Path(log_name)
    if log_name_path.name != log_name:
        raise ValueError(
            f"Log file must be a file name inside logs directory. Received: {log_name}"
        )
    return (app_paths.logs_dir / log_name_path).resolve()


def _rotation_policy_from_cfg(cfg: Any) -> RotationPolicy:
    return RotationPolicy(
        strategy=str(cfg.config["parameters"]["log_rotation_strategy"]),
        max_bytes=int(cfg.config["parameters"]["log_rotation_max_bytes"]),
        backup_count=int(cfg.config["parameters"]["log_rotation_backup_count"]),
        when=str(cfg.config["parameters"]["log_rotation_when"]),
        interval=int(cfg.config["parameters"]["log_rotation_interval"]),
        utc=True,
    )


def build_admin_activity_logger(cfg: Any) -> AdminActivityLogger:
    log_file_path = _resolve_log_path(cfg, log_key="admin_activity_log", default_log_name="admin_activity.log")
    return AdminActivityLogger(log_file_path=log_file_path, rotation_policy=_rotation_policy_from_cfg(cfg))


def build_ota_download_logger(cfg: Any) -> ServerOtaLogger:
    log_file_path = _resolve_log_path(cfg, log_key="ota_download_log", default_log_name="ota_download.log")
    return ServerOtaLogger(log_file_path=log_file_path, rotation_policy=_rotation_policy_from_cfg(cfg))
