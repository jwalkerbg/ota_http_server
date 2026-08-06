# core/db.py

from ota_http_server.core.config import Config
from ota_http_server.database.database_interface import DatabaseInterface
from ota_http_server.core.data_models import User, Project, Device, Firmware
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
