# db_sqlite_service.py

import sqlite3
from pathlib import Path
from datetime import datetime

from ota_http_server.core.config import Config
from ota_http_server.database.migration_sqlite3_runner import MigrationRunner
from ota_http_server.core.data_models import User, Project, Device, Firmware
from ota_http_server.core.data_models import AppPaths
from ota_http_server.logger import get_app_logger

logger = get_app_logger(__name__)

class UserAlreadyExistsError(Exception):
    pass

class DatabaseError(Exception):
    pass

class DatabaseSqliteService:
    def __init__(self, cfg:Config):
        self.cfg = cfg
        self.migration_runner = MigrationRunner(cfg)
        self.app_paths:AppPaths = self.cfg.config['parameters']['app_paths']

    def _connect(self):
        conn = sqlite3.connect(self.app_paths.database_sqlite)
        conn.execute("PRAGMA foreign_keys = ON;")
        if self.cfg.config["parameters"]["trace_sql"]:
            conn.set_trace_callback(lambda sql: logger.debug("SQL: %s", sql))
        return conn

    def init_db(self):
        self.migration_runner.migrate_up()

    def migrate(self):
        self.migration_runner.migrate_up()

    def rollback(self):
        self.migration_runner.migrate_down()

    def add_user(self, name: str, email: str):
        logger.info('add_user executed')

    def add_user(self, user: User) -> User:
        """
        Add a new user to the database.

        Args:
            user: User dataclass instance. password_hash must already be generated.

        Returns:
            User object with assigned database id.

        Raises:
            UserAlreadyExistsError:
                If username or email already exists.
            DatabaseError:
                For unexpected database errors.
        """

        sql = """
            INSERT INTO users (
                username,
                password_hash,
                email,
                role,
                is_active,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """

        now = datetime.now().isoformat()

        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    sql,
                    (
                        user.username,
                        user.password_hash,
                        user.email,
                        user.role,
                        1 if user.is_active else 0,
                        now,
                        now,
                    )
                )

                user.id = cursor.lastrowid
                user.created_at = datetime.fromisoformat(now)
                user.updated_at = datetime.fromisoformat(now)

                conn.commit()

                return user

        except sqlite3.IntegrityError as e:

            message = str(e)
            if "users.username" in message:
                raise UserAlreadyExistsError(
                    f"Username '{user.username}' already exists"
                ) from e
            if "users.email" in message:
                raise UserAlreadyExistsError(
                    f"Email '{user.email}' already exists"
                ) from e
            raise DatabaseError(
                f"Database integrity error while adding user: {message}"
            ) from e

        except sqlite3.Error as e:

            raise DatabaseError(
                f"Database error while adding user '{user.username}'"
            ) from e
