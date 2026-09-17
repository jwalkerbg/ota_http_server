import sqlite3

from ota_http_server.database.migrations.migration import Migration


class Migration_008(Migration):
    version = 8
    description = "Create users_devices table"

    def up(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE users_devices (
                user_id INTEGER NOT NULL,
                device_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                expires_at TEXT,
                PRIMARY KEY (user_id, device_id),
                FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
                    ON UPDATE CASCADE,
                FOREIGN KEY (device_id)
                    REFERENCES devices(id)
                    ON DELETE CASCADE
                    ON UPDATE CASCADE
            );
            """
        )
        conn.execute("CREATE INDEX idx_users_devices_device_id ON users_devices(device_id);")

    def down(self, conn: sqlite3.Connection) -> None:
        conn.execute("DROP TABLE users_devices;")


migration = Migration_008()
