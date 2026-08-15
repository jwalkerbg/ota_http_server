# core/db.py

from ota_http_server.core.config import Config
from ota_http_server.database.database_interface import DatabaseInterface
from ota_http_server.core.data_models import User, Project, ProjectListItem, Device, DeviceListItem, Firmware, FirmwareListItem
from ota_http_server.logger import get_app_logger

logger = get_app_logger(__name__)

class DatabaseService:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        if self.cfg.config['database']['dbtype'] == 'sqlite':
            from ota_http_server.database.db_sqlite_service import DatabaseSqliteService
            self._database: DatabaseInterface = DatabaseSqliteService(cfg)
        elif self.cfg.config['database']['dbtype'] == 'mysql':
            from ota_http_server.database.db_mysql_service import DatabaseMySQLService
            self._database: DatabaseInterface = DatabaseMySQLService(cfg)
        else:
            raise ValueError(f"Unsupported database type: {self.cfg.config['database']['dbtype']}")

    def db_command_handler(self) -> None:
        logger.info("Handling database command: %s", self.cfg.config.get('db_command'))
        db_command = self.cfg.config.get('db_command')

        if db_command == 'init-db':
            self.init_db()
        elif db_command == "migrate":
            self.migrate()
        elif db_command == "rollback":
            self.rollback()

    def init_db(self) -> None:
        self._database.init_db()

    def migrate(self) -> None:
        self._database.migrate()

    def rollback(self) -> None:
        self._database.rollback()

    def user_add(self, user: User) -> User:
        return self._database.user_add(user)

    def user_enable_by_id(self, user_id: int) -> None:
        self._database.user_enable_by_id(user_id)

    def user_enable_by_username(self, username: str) -> None:
        self._database.user_enable_by_username(username)

    def user_disable_by_id(self, user_id: int) -> None:
        self._database.user_disable_by_id(user_id)

    def user_disable_by_username(self, username: str) -> None:
        self._database.user_disable_by_username(username)

    def user_get_by_id(self, user_id: int) -> User | None:
        return self._database.user_get_by_id(user_id)

    def user_get_by_username(self, username: str) -> User | None:
        return self._database.user_get_by_username(username)

    def user_is_active(self, user_id: int) -> bool:
        return self._database.user_is_active(user_id)

    def user_get_list(self, is_active: bool | None = None) -> list[User]:
        return self._database.user_get_list(is_active=is_active)

    def user_get_record(self, is_active: bool | None = None) -> list[User]:
        return self._database.user_get_record(is_active=is_active)

    def project_add(self, project: Project) -> Project:
        return self._database.project_add(project)

    def project_enable_by_id(self, id: int) -> None:
        return self._database.project_enable_by_id(id)

    def project_enable_by_name(self, name: str) -> None:
        return self._database.project_enable_by_name(name)

    def project_disable_by_id(self, id: int) -> None:
        return self._database.project_disable_by_id(id)

    def project_disable_by_name(self, name: str) -> None:
        return self._database.project_disable_by_name(name)

    def project_get_by_id(self, id: int) -> Project | None:
        return self._database.project_get_by_id(id)

    def project_get_by_name(self, name: str) -> Project | None:
        return self._database.project_get_by_name(name)

    def project_is_active(self, project_id: int) -> bool:
        return self._database.project_is_active(project_id)

    def project_get_record(self) -> list[Project]:
        return self._database.project_get_record()

    def project_get_list(self) -> list[ProjectListItem]:
        return self._database.project_get_list()

    def device_add(self, device: Device) -> Device:
        return self._database.device_add(device=device)

    def device_enable_by_id(self, id: int) -> None:
        return self._database.device_enable_by_id(id=id)

    def device_enable_by_name(self, name: str) -> None:
        return self._database.device_enable_by_name(name=name)

    def device_disable_by_id(self, id: int) -> None:
        return self._database.device_disable_by_id(id=id)

    def device_disable_by_name(self, name: str) -> None:
        return self._database.device_disable_by_name(name=name)

    def device_get_by_id(self, id: int) -> Device | None:
        return self._database.device_get_by_id(id=id)

    def device_get_by_name(self, name: str) -> Device | None:
        return self._database.device_get_by_name(name=name)

    def device_is_active(self, device_id: int) -> bool:
        return self._database.device_is_active(device_id)

    def device_get_record(
        self,
        is_active: bool | None = None,
        project_id: int | None = None,
    ) -> list[Device]:
        return self._database.device_get_record(
            is_active=is_active,
            project_id=project_id,
        )

    def device_get_list(
        self,
        is_active: bool | None = None,
        project_id: int | None = None,
    ) -> list[DeviceListItem]:
        return self._database.device_get_list(
            is_active=is_active,
            project_id=project_id,
        )

    def firmware_add(self, firmware: Firmware) -> Firmware:
        return self._database.firmware_add(firmware=firmware)

    def firmware_replace(self, firmware_id: int, filename: str, file_size: int, checksum: str) -> Firmware:
        return self._database.firmware_replace(firmware_id=firmware_id, filename=filename, file_size=file_size, checksum=checksum)

    def firmware_enable_by_id(self, id: int) -> None:
        return self._database.firmware_enable_by_id(id=id)

    def firmware_enable_by_project_version(self, project_id: int, version: str) -> None:
        return self._database.firmware_enable_by_project_version(project_id=project_id, version=version)

    def firmware_disable_by_id(self, id: int) -> None:
        return self._database.firmware_disable_by_id(id=id)

    def firmware_disable_by_project_version(self, project_id: int, version: str) -> None:
        return self._database.firmware_disable_by_project_version(project_id=project_id, version=version)

    def firmware_get_by_id(self, id: int) -> Firmware | None:
        return self._database.firmware_get_by_id(id=id)

    def firmware_get_by_project_version(
            self,
            project_id: int,
            version: str,
        ) -> Firmware | None:
        return self._database.firmware_get_by_project_version(project_id=project_id, version=version)

    def firmware_is_active(self, firmware_id: int) -> bool:
        return self._database.firmware_is_active(firmware_id)

    def firmware_get_record(
        self,
        is_active: bool | None = None,
        project_id: int | None = None,
    ) -> list[Firmware]:
        return self._database.firmware_get_record(is_active=is_active, project_id=project_id)

    def firmware_get_list(
        self,
        is_active: bool | None = None,
        project_id: int | None = None,
    ) -> list[FirmwareListItem]:
        return self._database.firmware_get_list(is_active=is_active, project_id=project_id)
