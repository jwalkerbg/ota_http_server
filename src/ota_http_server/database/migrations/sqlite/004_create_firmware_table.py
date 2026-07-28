# 001_create_user_table

import sqlite3

from ota_http_server.database.migrations.migration import Migration

class Migration_004(Migration):
    """Create the firmware table."""

    version = 4
    description = "Create firmware table"

    def up(self, conn: sqlite3.Connection) -> None:
        conn.execute("""
            CREATE TABLE firmware (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                project_id INTEGER NOT NULL,

                version TEXT NOT NULL,

                filename TEXT NOT NULL,

                file_size INTEGER NOT NULL,

                checksum TEXT NOT NULL,

                release_notes TEXT,

                channel TEXT NOT NULL
                    CHECK (channel IN ('stable', 'beta', 'dev')),

                created_at TEXT NOT NULL
                    DEFAULT CURRENT_TIMESTAMP,

                updated_at TEXT,

                FOREIGN KEY (project_id)
                    REFERENCES projects(id)
                    ON DELETE RESTRICT
                    ON UPDATE CASCADE,

                UNIQUE (project_id, version, channel)
            );
        """)

        conn.execute("""
            CREATE INDEX idx_firmware_project_id
            ON firmware(project_id);
        """)

        conn.execute("""
            CREATE INDEX idx_firmware_project_channel
            ON firmware(project_id, channel);
        """)



    def down(self, conn: sqlite3.Connection) -> None:
        conn.execute("""
            DROP TABLE IF EXISTS firmware;
        """)

migration = Migration_004()