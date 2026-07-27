# core/db.py

import traceback
from typing import Protocol

from ota_http_server.core.config import Config
from ota_http_server.database.database_interface import DatabaseInterface
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
            db_file = self.cfg.config['database']['sqlite']['db_file']
            self.init_db()
        elif db_command == "migrate":
            self.migrate()
        elif db_command == 'create-user':
            email = self.cfg.config['parameters']['email']
            self.create_user(email)
        elif db_command == 'create-device':
            device_name = self.cfg.config['parameters']['device_name']
            device_uuid = self.cfg.config['parameters']['device_uuid']
            self.create_device(device_name, device_uuid)
        elif db_command == 'create-project':
            project_name = self.cfg.config['parameters']['project_name']
            project_uuid = self.cfg.config['parameters']['project_uuid']
            project_path = self.cfg.config['parameters']['project_path']
            self.create_project(project_name, project_uuid, project_path)

    def init_db(self) -> None:
        self._database.init_db()

    def migrate(self) -> None:
        self._database.migrate()

    def create_user(self, email:str) -> None:
        self._database.add_user(name=email.split('@')[0], email=email)

