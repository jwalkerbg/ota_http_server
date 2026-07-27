# db_sqlite_service.py

import sqlite3
from pathlib import Path

from ota_http_server.core.config import Config
from ota_http_server.database.migration_sqlite3_runner import MigrationRunner
from ota_http_server.logger import get_app_logger

logger = get_app_logger(__name__)

class DatabaseSqliteService:
    def __init__(self, cfg:Config):
        self.cfg = cfg
        self.migration_runner = MigrationRunner(cfg)

    def init_db(self):
        logger.info("init_db executed")
        self.migration_runner.migrate_up()
        return 0

    def add_user(self, name: str, email: str) -> int:
        logger.info('add_user executed')
        return 0



DB_FILE = Path("ota_server.db")


def init_database(db_file: Path = DB_FILE):
    """
    Initialize SQLite database.

    Creates all tables, indexes, and enables foreign key support.
    """

    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()

        # Enable foreign key constraints in SQLite.
        # SQLite disables them by default.
        cursor.execute("PRAGMA foreign_keys = ON;")

        # ---------------------------------------------------------
        # Users table
        # ---------------------------------------------------------
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT
        );
        """)


        # ---------------------------------------------------------
        # Projects table
        # ---------------------------------------------------------
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            description TEXT,
            created_by INTEGER NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT,

            FOREIGN KEY(created_by)
                REFERENCES users(id)
                ON DELETE RESTRICT
        );
        """)


        # ---------------------------------------------------------
        # Devices table
        # ---------------------------------------------------------
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            device_id TEXT NOT NULL UNIQUE,

            project_id INTEGER NOT NULL,

            model TEXT NOT NULL,

            serial_number TEXT,

            current_version TEXT NOT NULL,

            last_seen TEXT,

            is_active INTEGER NOT NULL DEFAULT 1,

            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

            updated_at TEXT,

            FOREIGN KEY(project_id)
                REFERENCES projects(id)
                ON DELETE CASCADE
        );
        """)


        # ---------------------------------------------------------
        # Firmware table
        # ---------------------------------------------------------
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS firmware (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            version TEXT NOT NULL,
            filename TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            checksum TEXT NOT NULL,
            release_notes TEXT,
            channel TEXT NOT NULL DEFAULT 'stable',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT,

            FOREIGN KEY(project_id)
                REFERENCES projects(id)
                ON DELETE CASCADE,

            UNIQUE(project_id, version, channel)
        );
        """)


        # ---------------------------------------------------------
        # Indexes for frequent lookups
        # ---------------------------------------------------------

        cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_devices_project
        ON devices(project_id);
        """)

        cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_firmware_project
        ON firmware(project_id);
        """)

        cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_firmware_version
        ON firmware(version);
        """)

        cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_devices_device_id
        ON devices(device_id);
        """)


        conn.commit()
