# 001_create_user_table

import sqlite3

from ota_http_server.database.migrations.migration import Migration

class Migration_003(Migration):
    """Create the devices table."""

    version = 3
    description = "Create devices table"

    def up(self, conn: sqlite3.Connection) -> None:
        conn.execute("""
            CREATE TABLE devices (
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

                FOREIGN KEY (project_id)
                    REFERENCES projects(id)
                    ON DELETE RESTRICT
                    ON UPDATE CASCADE
            );

        """)
        conn.execute("""
            CREATE INDEX idx_devices_project_id ON devices(project_id);
        """)

        conn.execute("""
            CREATE UNIQUE INDEX idx_devices_serial_number
            ON devices(serial_number)
            WHERE serial_number IS NOT NULL;
        """)


    def down(self, conn: sqlite3.Connection) -> None:
        conn.execute("""
            DROP TABLE IF EXISTS devices;
        """)

migration = Migration_003()