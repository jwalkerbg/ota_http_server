# 001_create_user_table

import sqlite3

from ota_http_server.database.migrations.migration import Migration

class Migration_002(Migration):
    """Create the projects table."""

    version = 2
    description = "Create projects table"

    def up(self, conn: sqlite3.Connection) -> None:
        conn.execute("""
            CREATE TABLE projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                description TEXT,
                created_by INTEGER NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
                    DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT,
                FOREIGN KEY (created_by)
                    REFERENCES users(id)
                    ON DELETE RESTRICT
                    ON UPDATE CASCADE
            );
        """)
        conn.execute("""
            CREATE INDEX idx_projects_created_by ON projects(created_by);
        """)

    def down(self, conn: sqlite3.Connection) -> None:
        conn.execute("""
            DROP TABLE IF EXISTS projects;
        """)

migration = Migration_002()