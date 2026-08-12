# core/db.py

from ota_http_server.core.config import Config
from ota_http_server.database.database_interface import DatabaseInterface
from ota_http_server.core.data_models import User, Project, Device, Firmware, FirmwareListItem
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

    def add_user(self, user: User) -> User:
        return self._database.add_user(user)

    def enable_user_by_id(self, user_id: int) -> None:
        self._database.user_enable_by_id(user_id)

    def enable_user_by_username(self, username: str) -> None:
        self._database.user_enable_by_username(username)

    def disable_user_by_id(self, user_id: int) -> None:
        self._database.user_disable_by_id(user_id)

    def disable_user_by_username(self, username: str) -> None:
        self._database.user_disable_by_username(username)

    def user_get_by_id(self, user_id: int) -> User | None:
        return self._database.user_get_by_id(user_id)

    def user_get_by_username(self, username: str) -> User | None:
        return self._database.user_get_by_username(username)

    def user_get_list(self) -> list[User]:
        return self._database.user_get_list()

    def add_project(self, project: Project) -> Project:
        return self._database.add_project(project)

    def enable_project_by_id(self, id: int) -> None:
        return self._database.enable_project_by_id(id)

    def enable_project_by_name(self, name: str) -> None:
        return self._database.enable_project_by_name()

    def disable_project_by_id(self, id: int) -> None:
        return self._database.disable_project_by_id(id)

    def disable_project_by_name(self, name: str) -> None:
        return self._database.disable_project_by_name(name)

    def get_project_by_id(self, id: int) -> Project | None:
        return self._database.get_project_by_id(id)

    def get_project_by_name(self, name: str) -> Project | None:
        return self._database.get_project_by_name(name)

    def project_get_list(self) -> list[Project]:
        return self._database.project_get_list()

    def add_device(self, device: Device) -> Device:
        return self._database.add_device(device=device)

    def enable_device_by_id(self, id: int) -> None:
        return self._database.enable_device_by_id(id=id)

    def enable_device_by_name(self, name: str) -> None:
        return self._database.enable_device_by_name(name=name)

    def disable_device_by_id(self, id: int) -> None:
        return self._database.disable_device_by_id(id=id)

    def disable_device_by_name(self, name: str) -> None:
        return self._database.disable_device_by_name(name=name)

    def get_device_by_id(self, id: int) -> Device | None:
        return self._database.get_device_by_id(id=id)

    def get_device_by_name(self, name: str) -> Device | None:
        return self._database.get_device_by_name(name=name)

    def device_get_list(self) -> list[Device]:
        return self._database.device_get_list()

    def add_firmware(self, firmware: Firmware) -> Firmware:
        return self._database.add_firmware(firmware=firmware)

    def enable_firmware_by_id(self, id: int) -> None:
        return self._database.enable_firmware_by_id(id=id)

    def enable_firmware_by_project_version(self, project_id: int, version: str) -> None:
        return self._database.enable_firmware_by_project_version(project_id=project_id, version=version)

    def disable_firmware_by_id(self, id: int) -> None:
        return self._database.disable_firmware_by_id(id=id)

    def disable_firmware_by_project_version(self, project_id: int, version: str) -> None:
        return self._database.disable_firmware_by_project_version(project_id=project_id, version=version)

    def get_firmware_by_id(self, id: int) -> Firmware | None:
        return self._database.get_firmware_by_id(id=id)

    def firmware_get_by_project_version(
            self,
            project_id: int,
            version: str,
        ) -> Firmware | None:
        return self._database.firmware_get_by_project_version(project_id=project_id, version=version)

    def firmware_get_record(self) -> list[Firmware]:
        return self._database.firmware_get_record()

    def firmware_get_list(self) -> list[FirmwareListItem]:
        return self._database.firmware_get_list()
