# firmware_service.py

import hashlib
import shutil
from pathlib import Path

from ota_http_server.core.config import Config
from ota_http_server.core.data_models import Firmware, AppPaths
from ota_http_server.database.database_service import DatabaseService
from ota_http_server.database.db_mysql_service import FirmwareNotFoundError as MySQLFirmwareNotFoundError
from ota_http_server.database.db_sqlite_service import FirmwareNotFoundError as SqliteFirmwareNotFoundError
from ota_http_server.core.formatters import FirmwareFormatter, FirmwareListItemFormatter
from ota_http_server.firmware.filename_validation import validate_firmware_filename
from ota_http_server.logger import get_app_logger
from ota_http_server.logger.admin_activity_logger import normalize_admin_activity_action
from ota_http_server.target.target_service import DEFAULT_TARGET_NAME

logger = get_app_logger(__name__)

class FirmwareService:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.admin_activity_logger = self.cfg.config.get("admin_activity_logger")

    def _sha256_file(self, file_path: Path) -> str:
        digest = hashlib.sha256()
        with file_path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    # CLI command handler for user operations

    def command_handler(self) -> None:
        command = self.cfg.config.get('firmware_command')
        logger.verbose("Handling firmware command: %s", command)

        # these handlers expect their parameters in self.cfg.config
        handlers= {
            "add": self._add_firmware,
            "change-target": self._change_target,
            "replace": self._replace_firmware,
            "delete": self._delete_firmware,
            "enable": self._enable_firmware,
            "disable": self._disable_firmware,
            "get": self._get_firmware,
            "list": self._list_firmware
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
            logger.error("Invalid firmware command received: %s", command)

    def _log_admin_activity(self, command: str | None, outcome: str, error: str | None = None) -> None:
        if command is None or self.admin_activity_logger is None:
            return
        self.admin_activity_logger.log_activity(
            interface="cli",
            entity="firmware",
            action=command,
            outcome=outcome,
            target={
                "firmware_id": self.cfg.config["parameters"].get("firmware_id"),
                "project_id": self.cfg.config["parameters"].get("firmware_pid"),
                "version": self.cfg.config["parameters"].get("firmware_version"),
                "target_id": self.cfg.config["parameters"].get("target_id"),
                "target_name": self.cfg.config["parameters"].get("target_name"),
            },
            error=error,
        )

    def _add_firmware(self) -> None:
        pid = self.cfg.config["parameters"]["firmware_pid"]
        version = self.cfg.config["parameters"]["firmware_version"]
        source_file = self.cfg.config["parameters"]["firmware_file"]
        release_notes = self.cfg.config["parameters"]["firmware_release_notes"]
        release_channel = self.cfg.config["parameters"]["firmware_release_channel"]
        target_id = self._resolve_target_id()

        validate_firmware_filename(source_file)

        firmware = Firmware(
            id=None,
            project_id=pid,
            target_id=target_id,
            version=version,
            filename="",
            file_size=0,
            checksum="",
            release_notes=release_notes,
            channel=release_channel,
            is_active=True,
            created_at=None,
            updated_at=None
        )

        db_service: DatabaseService = self.cfg.config["db_service"]
        app_paths: AppPaths = self.cfg.config["parameters"]["app_paths"]

        project = db_service.project_get_by_id(pid)
        if project is None:
            raise ValueError(f"Project with ID {pid} does not exist")

        source_path = Path(source_file).expanduser().resolve(strict=True)
        if not source_path.is_file():
            raise ValueError(f"Firmware file path must point to a file: {source_path}")

        duplicate = next(
            (
                record for record in db_service.firmware_get_record()
                if record.project_id == pid
                and record.version == version
                and record.target_id == target_id
            ),
            None,
        )
        if duplicate is not None:
            raise ValueError(
                f"Firmware already exists for project_id={pid}, version={version}, target_id={target_id}"
            )

        project_dir = app_paths.ensure_project_dir(project.name)
        destination_path = (project_dir / source_path.name).resolve()

        if destination_path.exists() and source_path != destination_path:
            raise FileExistsError(
                f"Destination firmware file already exists: {destination_path}"
            )

        if source_path != destination_path:
            shutil.copy2(source_path, destination_path)
            logger.info("Uploaded firmware file '%s' to '%s'", source_path, destination_path)
        else:
            logger.info("Firmware file '%s' already in target project directory", source_path)

        firmware.filename = destination_path.name
        firmware.file_size = destination_path.stat().st_size
        firmware.checksum = self._sha256_file(destination_path)

        db_service.firmware_add(firmware)

    def _resolve_target_id(self) -> int:
        db_service: DatabaseService = self.cfg.config["db_service"]
        target_id = self.cfg.config["parameters"].get("target_id")
        target_name = self.cfg.config["parameters"].get("target_name")

        if target_id is not None:
            target = db_service.target_get_by_id(target_id)
            if target is None:
                raise ValueError(f"Target with ID {target_id} does not exist")
            if target.id is None:
                raise ValueError(f"Target with ID {target_id} is missing its database identifier")
            return target.id

        if target_name is not None:
            target = db_service.target_get_by_name(target_name)
            if target is None:
                raise ValueError(f"Target with name '{target_name}' does not exist")
            if target.id is None:
                raise ValueError(f"Target with name '{target_name}' is missing its database identifier")
            return target.id

        target = db_service.target_get_by_name(DEFAULT_TARGET_NAME)
        if target is None:
            raise ValueError(f"Target with name '{DEFAULT_TARGET_NAME}' does not exist")
        if target.id is None:
            raise ValueError(f"Target with name '{DEFAULT_TARGET_NAME}' is missing its database identifier")
        return target.id

    def _change_target(self) -> None:
        id = self.cfg.config["parameters"]["firmware_id"]
        pid = self.cfg.config["parameters"]["firmware_pid"]
        version = self.cfg.config["parameters"]["firmware_version"]
        target_id = self._resolve_target_id()

        db_service: DatabaseService = self.cfg.config["db_service"]

        if id is not None:
            db_service.firmware_change_target_by_id(id, target_id)
            return

        if pid is not None and version is not None:
            db_service.firmware_change_target_by_project_version(pid, version, target_id)
            return

        raise ValueError("Firmware id or project id plus version must be provided")

    def _replace_firmware(self) -> None:
        firmware_id = self.cfg.config["parameters"].get("firmware_id")
        pid = self.cfg.config["parameters"].get("firmware_pid")
        version = self.cfg.config["parameters"].get("firmware_version")
        source_file = self.cfg.config["parameters"]["firmware_file"]

        db_service: DatabaseService = self.cfg.config["db_service"]

        if firmware_id is not None:
            existing = db_service.firmware_get_by_id(firmware_id)
            if existing is None:
                logger.info("No uploaded firmware found for firmware_id=%s. Nothing to replace.", firmware_id)
                return
            project = db_service.project_get_by_id(existing.project_id)
            if project is None:
                raise ValueError(f"Project with ID {existing.project_id} does not exist")
            pid = existing.project_id
            version = existing.version
        else:
            if pid is None or version is None:
                raise ValueError("Firmware id or project id plus version must be provided")
            project = db_service.project_get_by_id(pid)
            if project is None:
                raise ValueError(f"Project with ID {pid} does not exist")
            existing = db_service.firmware_get_by_project_version(project_id=pid, version=version)
            if existing is None:
                logger.info("No uploaded firmware found for project_id=%s and version=%s. Nothing to replace.", pid, version)
                return

        source_path = Path(source_file).expanduser().resolve(strict=True)
        if not source_path.is_file():
            raise ValueError(f"Firmware file path must point to a file: {source_path}")

        project_dir = self.cfg.config["parameters"]["app_paths"].ensure_project_dir(project.name)
        destination_path = (project_dir / source_path.name).resolve()
        old_path = project_dir / existing.filename
        old_path = old_path.resolve(strict=False)

        if source_path != destination_path:
            if destination_path.exists() and destination_path != old_path:
                destination_path.unlink()
            shutil.copy2(source_path, destination_path)
            logger.info("Replaced firmware file '%s' with '%s' in project '%s'", existing.filename, destination_path.name, project.name)
        else:
            logger.info("Firmware file '%s' already in target project directory", source_path)

        if old_path.exists() and old_path != destination_path:
            old_path.unlink()

        replacement = db_service.firmware_replace(
            firmware_id=existing.id,
            filename=destination_path.name,
            file_size=destination_path.stat().st_size,
            checksum=self._sha256_file(destination_path),
        )
        logger.info("Updated firmware record %s", replacement)

    def _delete_firmware(self) -> None:
        firmware_id = self.cfg.config["parameters"].get("firmware_id")
        pid = self.cfg.config["parameters"].get("firmware_pid")
        version = self.cfg.config["parameters"].get("firmware_version")

        db_service: DatabaseService = self.cfg.config["db_service"]
        app_paths: AppPaths = self.cfg.config["parameters"]["app_paths"]

        try:
            if firmware_id is not None:
                deleted = db_service.firmware_delete_by_id(firmware_id)
            elif pid is not None and version is not None:
                deleted = db_service.firmware_delete_by_project_version(
                    project_id=pid,
                    version=version,
                )
            else:
                raise ValueError("Firmware id or project id plus version must be provided")
        except (SqliteFirmwareNotFoundError, MySQLFirmwareNotFoundError):
            if firmware_id is not None:
                logger.info("No uploaded firmware found for firmware_id=%s. Nothing to delete.", firmware_id)
            else:
                logger.info("No uploaded firmware found for project_id=%s and version=%s. Nothing to delete.", pid, version)
            return

        validate_firmware_filename(deleted.filename)
        project_dir = app_paths.project_dir(deleted.project_name).resolve(strict=False)
        firmware_file_path = (project_dir / deleted.filename).resolve(strict=False)
        if firmware_file_path.parent != project_dir:
            raise ValueError(
                f"Refusing to delete firmware file outside project directory: {firmware_file_path}"
            )

        if firmware_file_path.exists():
            firmware_file_path.unlink()
            logger.info("Deleted firmware file '%s'", firmware_file_path)
        else:
            logger.info(
                "Firmware file '%s' does not exist on disk; database record has been deleted.",
                firmware_file_path,
            )
        logger.info("Deleted firmware record id=%s", deleted.id)

    def _enable_firmware(self) -> None:
        id = self.cfg.config["parameters"]["firmware_id"]
        pid = self.cfg.config["parameters"]["firmware_pid"]
        version = self.cfg.config["parameters"]["firmware_version"]

        db_service: DatabaseService = self.cfg.config["db_service"]

        if id is not None:

            db_service.firmware_enable_by_id(id)
            return

        if pid is not None and version is not None:
            db_service.firmware_enable_by_project_version(pid, version)
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
            db_service.firmware_disable_by_id(id)
            return

        if pid is not None and version is not None:
            db_service.firmware_disable_by_project_version(pid, version)
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
            firmware = db_service.firmware_get_by_id(id)
            if firmware:
                logger.info("Firmware found: %s", firmware)
            else:
                logger.info("Firmware with ID = %d not found", id)
            return

        if pid is not None and version is not None:
            firmware = db_service.firmware_get_by_project_version(project_id=pid, version=version)
            if firmware:
                logger.info("Firmware found: %s", firmware)
            else:
                logger.info("Firmware with pid = %d and version = %s not found", pid, version)
            return

        raise ValueError(
            "Firmware id or project id plus version must be provided"
        )

    def _list_firmware(self) -> None:
        db_service: DatabaseService = self.cfg.config["db_service"]

        firmware_status = self.cfg.config["parameters"].get("firmware_status")
        is_active = None if firmware_status is None else firmware_status == "enabled"
        project_id = self.cfg.config["parameters"].get("firmware_pid")

        if self.cfg.config["parameters"]["firmware_record"] == True:
            firmware = db_service.firmware_get_record(is_active=is_active, project_id=project_id)
            if firmware:
                logger.info("\n%s",FirmwareFormatter.format_list(firmware))
            else:
                logger.info("No firmware found.")

        else:
            firmware = db_service.firmware_get_list(is_active=is_active, project_id=project_id)
            if firmware:
                logger.info("\n%s\n",FirmwareListItemFormatter.format_list(firmware))
            else:
                logger.info("No firmware found.")
