# 001_create_user_table

import sqlite3

from ota_http_server.database.migrations.migration import Migration

class Migration_001(Migration):
    """Create the users table."""

    version = 1
    description = "Create users table"

    def up(self, conn: sqlite3.Connection) -> None:
        conn.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
                    DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT
            );
        """)

    def down(self, conn: sqlite3.Connection) -> None:
        conn.execute("""
            DROP TABLE IF EXISTS users;
        """)

migration = Migration_001()