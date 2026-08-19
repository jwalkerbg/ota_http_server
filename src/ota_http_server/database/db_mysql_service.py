# core/db_mysql_service.py

from typing import NoReturn

from ota_http_server.core.config import Config
from ota_http_server.database.migration_mysql_runner import MigrationMySQLRunner
from ota_http_server.core.data_models import (
    User,
    Project,
    ProjectListItem,
    Device,
    DeviceListItem,
    Firmware,
    FirmwareListItem,
)


class DatabaseMySQLService:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.migration_runner = MigrationMySQLRunner(cfg)

    def _unsupported(self, action: str) -> NoReturn:
        raise NotImplementedError(
            f"MySQL database support is not implemented for {action}"
        )

    def init_db(self) -> None:
        self.migration_runner.migrate_up()

    def migrate(self) -> None:
        self.migration_runner.migrate_up()

    def rollback(self) -> None:
        self.migration_runner.migrate_down()

    def user_add(self, user: User) -> User:
        self._unsupported("user_add")

    def user_enable_by_id(self, user_id: int) -> None:
        self._unsupported("user_enable_by_id")

    def user_enable_by_username(self, username: str) -> None:
        self._unsupported("user_enable_by_username")

    def user_disable_by_id(self, user_id: int) -> None:
        self._unsupported("user_disable_by_id")

    def user_disable_by_username(self, username: str) -> None:
        self._unsupported("user_disable_by_username")

    def user_get_by_id(self, user_id: int) -> User | None:
        self._unsupported("user_get_by_id")

    def user_get_by_username(self, username: str) -> User | None:
        self._unsupported("user_get_by_username")

    def user_is_active(self, user_id: int) -> bool:
        self._unsupported("user_is_active")

    def user_get_list(self, is_active: bool | None = None) -> list[User]:
        self._unsupported("user_get_list")

    def user_get_record(self, is_active: bool | None = None) -> list[User]:
        self._unsupported("user_get_record")

    def project_add(self, project: Project) -> Project:
        self._unsupported("project_add")

    def project_enable_by_id(self, id: int) -> None:
        self._unsupported("project_enable_by_id")

    def project_enable_by_name(self, name: str) -> None:
        self._unsupported("project_enable_by_name")

    def project_disable_by_id(self, id: int) -> None:
        self._unsupported("project_disable_by_id")

    def project_disable_by_name(self, name: str) -> None:
        self._unsupported("project_disable_by_name")

    def project_get_by_id(self, id: int) -> Project | None:
        self._unsupported("project_get_by_id")

    def project_get_by_name(self, name: str) -> Project | None:
        self._unsupported("project_get_by_name")

    def project_is_active(self, project_id: int) -> bool:
        self._unsupported("project_is_active")

    def project_get_record(self) -> list[Project]:
        self._unsupported("project_get_record")

    def project_get_list(self) -> list[ProjectListItem]:
        self._unsupported("project_get_list")

    def device_add(self, device: Device) -> Device:
        self._unsupported("device_add")

    def device_enable_by_id(self, id: int) -> None:
        self._unsupported("device_enable_by_id")

    def device_enable_by_name(self, name: str) -> None:
        self._unsupported("device_enable_by_name")

    def device_disable_by_id(self, id: int) -> None:
        self._unsupported("device_disable_by_id")

    def device_disable_by_name(self, name: str) -> None:
        self._unsupported("device_disable_by_name")

    def device_get_by_id(self, id: int) -> Device | None:
        self._unsupported("device_get_by_id")

    def device_get_by_name(self, name: str) -> Device | None:
        self._unsupported("device_get_by_name")

    def device_is_active(self, device_id: int) -> bool:
        self._unsupported("device_is_active")

    def device_get_record(
        self,
        is_active: bool | None = None,
        project_id: int | None = None,
    ) -> list[Device]:
        self._unsupported("device_get_record")

    def device_get_list(
        self,
        is_active: bool | None = None,
        project_id: int | None = None,
    ) -> list[DeviceListItem]:
        self._unsupported("device_get_list")

    def firmware_add(self, firmware: Firmware) -> Firmware:
        self._unsupported("firmware_add")

    def firmware_replace(self, firmware_id: int, filename: str, file_size: int, checksum: str) -> Firmware:
        self._unsupported("firmware_replace")

    def firmware_enable_by_id(self, id: int) -> None:
        self._unsupported("firmware_enable_by_id")

    def firmware_enable_by_project_version(self, project_id: int, version: str) -> None:
        self._unsupported("firmware_enable_by_project_version")

    def firmware_disable_by_id(self, id: int) -> None:
        self._unsupported("firmware_disable_by_id")

    def firmware_disable_by_project_version(self, project_id: int, version: str) -> None:
        self._unsupported("firmware_disable_by_project_version")

    def firmware_get_by_id(self, id: int) -> Firmware | None:
        self._unsupported("firmware_get_by_id")

    def firmware_get_by_project_version(
        self,
        project_id: int,
        version: str,
    ) -> Firmware | None:
        self._unsupported("firmware_get_by_project_version")

    def firmware_is_active(self, firmware_id: int) -> bool:
        self._unsupported("firmware_is_active")

    def firmware_get_record(
        self,
        is_active: bool | None = None,
        project_id: int | None = None,
    ) -> list[Firmware]:
        self._unsupported("firmware_get_record")

    def firmware_get_list(
        self,
        is_active: bool | None = None,
        project_id: int | None = None,
    ) -> list[FirmwareListItem]:
        self._unsupported("firmware_get_list")
