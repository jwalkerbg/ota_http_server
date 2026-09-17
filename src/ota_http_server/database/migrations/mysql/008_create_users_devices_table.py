import typing

from ota_http_server.database.migrations.migration import Migration


class Migration_008(Migration):
    version = 8
    description = "Create users_devices table"

    def up(self, conn: typing.Any) -> None:
        conn.execute(
            """
            CREATE TABLE users_devices (
                user_id BIGINT NOT NULL,
                device_id BIGINT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NULL,
                PRIMARY KEY (user_id, device_id),
                CONSTRAINT fk_users_devices_user_id
                    FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
                    ON UPDATE CASCADE,
                CONSTRAINT fk_users_devices_device_id
                    FOREIGN KEY (device_id)
                    REFERENCES devices(id)
                    ON DELETE CASCADE
                    ON UPDATE CASCADE,
                INDEX idx_users_devices_device_id (device_id)
            )
            """
        )

    def down(self, conn: typing.Any) -> None:
        conn.execute("DROP TABLE users_devices")


migration = Migration_008()
