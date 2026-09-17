from datetime import UTC, datetime

from ota_http_server.core.config import Config
from ota_http_server.core.data_models import UserDevice
from ota_http_server.core.formatters import UserDeviceFormatter
from ota_http_server.database.database_service import DatabaseService
from ota_http_server.logger import get_app_logger
from ota_http_server.logger.admin_activity_logger import normalize_admin_activity_action

logger = get_app_logger(__name__)


class UserDeviceService:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.admin_activity_logger = self.cfg.config.get("admin_activity_logger")

    def command_handler(self) -> None:
        command = self.cfg.config.get("userdev_command")
        handlers = {
            "add": self._add,
            "get": self._get,
            "isexp": self._is_expired,
            "setexp": self._set_expiry,
            "delete": self._delete,
        }
        handler = handlers.get(command)
        if handler is None:
            raise ValueError(f"Invalid userdev command received: {command}")
        action = normalize_admin_activity_action(command)
        try:
            handler()
            self._log_admin_activity(action, "success")
        except Exception as exc:
            self._log_admin_activity(action, "failed", str(exc))
            raise

    def _log_admin_activity(self, command: str, outcome: str, error: str | None = None) -> None:
        if self.admin_activity_logger is None:
            return
        parameters = self.cfg.config["parameters"]
        self.admin_activity_logger.log_activity(
            interface="cli",
            entity="user_device",
            action=command,
            outcome=outcome,
            target={
                "user_id": parameters.get("userdev_user_id"),
                "username": parameters.get("userdev_username"),
                "device_id": parameters.get("userdev_device_id"),
                "device_uuid": parameters.get("userdev_device_uuid"),
            },
            error=error,
        )

    @staticmethod
    def _parse_timestamp(value: str | None) -> datetime | None:
        if value is None:
            return None
        normalized = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
        try:
            timestamp = datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise ValueError(
                "--expires must be an ISO 8601 timestamp, for example "
                "2026-09-18T12:30:00+00:00"
            ) from exc
        return timestamp.replace(tzinfo=UTC) if timestamp.tzinfo is None else timestamp

    def _resolve_ids(self) -> tuple[int, int]:
        parameters = self.cfg.config["parameters"]
        db_service: DatabaseService = self.cfg.config["db_service"]

        user_id = parameters.get("userdev_user_id")
        if user_id is None:
            user = db_service.user_get_by_username(parameters.get("userdev_username"))
            if user is None or user.id is None:
                raise ValueError(f"User '{parameters.get('userdev_username')}' was not found")
            user_id = user.id
        elif db_service.user_get_by_id(user_id) is None:
            raise ValueError(f"User with ID {user_id} was not found")

        device_id = parameters.get("userdev_device_id")
        if device_id is None:
            device = db_service.device_get_by_name(parameters.get("userdev_device_uuid"))
            if device is None or device.id is None:
                raise ValueError(f"Device '{parameters.get('userdev_device_uuid')}' was not found")
            device_id = device.id
        elif db_service.device_get_by_id(device_id) is None:
            raise ValueError(f"Device with ID {device_id} was not found")

        return user_id, device_id

    def _add(self) -> None:
        user_id, device_id = self._resolve_ids()
        expires_at = self._parse_timestamp(self.cfg.config["parameters"].get("userdev_expires"))
        assignment = UserDevice(user_id, device_id, None, expires_at)
        db_service: DatabaseService = self.cfg.config["db_service"]
        logger.info("User-device assignment created: %s", db_service.user_device_add(assignment))

    def _get(self) -> None:
        user_id, device_id = self._resolve_ids()
        db_service: DatabaseService = self.cfg.config["db_service"]
        assignment = db_service.user_device_get(user_id, device_id)
        if assignment is None:
            logger.info("User-device assignment not found")
        else:
            logger.info("\n%s", UserDeviceFormatter.format_list([assignment]))

    def _is_expired(self) -> None:
        user_id, device_id = self._resolve_ids()
        db_service: DatabaseService = self.cfg.config["db_service"]
        logger.info(
            "User %d can operate device %d: %s",
            user_id,
            device_id,
            "no (assignment expired)" if db_service.user_device_is_expired(user_id, device_id) else "yes",
        )

    def _set_expiry(self) -> None:
        user_id, device_id = self._resolve_ids()
        expires_at = self._parse_timestamp(self.cfg.config["parameters"].get("userdev_expires"))
        db_service: DatabaseService = self.cfg.config["db_service"]
        logger.info(
            "User-device assignment updated: %s",
            db_service.user_device_set_expiry(user_id, device_id, expires_at),
        )

    def _delete(self) -> None:
        user_id, device_id = self._resolve_ids()
        db_service: DatabaseService = self.cfg.config["db_service"]
        db_service.user_device_delete(user_id, device_id)
        logger.info("User-device assignment deleted: user=%d, device=%d", user_id, device_id)
