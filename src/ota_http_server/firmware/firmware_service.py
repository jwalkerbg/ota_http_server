# firmware_service.py

import hashlib
import shutil
from pathlib import Path

from ota_http_server.core.config import Config
from ota_http_server.core.data_models import Firmware, AppPaths
from ota_http_server.database.database_service import DatabaseService
from ota_http_server.core.formatters import FirmwareFormatter, FirmwareListItemFormatter
from ota_http_server.logger import get_app_logger

logger = get_app_logger(__name__)

class FirmwareService:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    def _sha256_file(self, file_path: Path) -> str:
        digest = hashlib.sha256()
        with file_path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    # CLI command handler for user operations

    def command_handler(self) -> None:
        command = self.cfg.config.get('firmware_command')
        logger.info("Handling firmware command: %s", command)

        # these handlers expect their parameters in self.cfg.config
        handlers= {
            "add": self._add_firmware,
            "replace": self._replace_firmware,
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
        source_file = self.cfg.config["parameters"]["firmware_file"]
        release_notes = self.cfg.config["parameters"]["firmware_release_notes"]
        release_channel = self.cfg.config["parameters"]["firmware_release_channel"]

        firmware = Firmware(
            id=None,
            project_id=pid,
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
                and record.channel == release_channel
            ),
            None,
        )
        if duplicate is not None:
            raise ValueError(
                f"Firmware already exists for project_id={pid}, version={version}, channel={release_channel}"
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

    def _replace_firmware(self) -> None:
        pid = self.cfg.config["parameters"]["firmware_pid"]
        version = self.cfg.config["parameters"]["firmware_version"]
        source_file = self.cfg.config["parameters"]["firmware_file"]

        db_service: DatabaseService = self.cfg.config["db_service"]
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
