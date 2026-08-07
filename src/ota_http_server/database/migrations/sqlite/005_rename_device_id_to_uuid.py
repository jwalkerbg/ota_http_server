
import sqlite3

from ota_http_server.database.migrations.migration import Migration

class Migration_005(Migration):
    """Rename devices.device_id to devices.uuid"""

    version = 5
    description = "Rename devices.device_id to devices.uuid"

    def up(self, conn: sqlite3.Connection) -> None:
        conn.execute("""
            ALTER TABLE devices
            RENAME COLUMN device_id TO uuid
        """)

    def down(self, conn: sqlite3.Connection) -> None:
        conn.execute("""
            ALTER TABLE devices
            RENAME COLUMN uuid TO device_id
        """)

migration = Migration_005()
