
import sqlite3

from ota_http_server.database.migrations.migration import Migration

class Migration_006(Migration):
    """Add is_active column to firmware table"""

    version = 6
    description = "Add is_active column to firmware table"

    def up(self, conn: sqlite3.Connection) -> None:
        conn.execute("""
            ALTER TABLE firmware
            ADD COLUMN is_active INTEGER NOT NULL DEFAULT 0
        """)

    def down(self, conn: sqlite3.Connection) -> None:
        conn.execute("""
            ALTER TABLE firmware
            DROP COLUMN is_active
        """)

migration = Migration_006()
