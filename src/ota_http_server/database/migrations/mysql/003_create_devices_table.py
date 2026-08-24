import typing

from ota_http_server.database.migrations.migration import Migration


class Migration_003(Migration):
    version = 3
    description = "Create devices table"

    def up(self, conn: typing.Any) -> None:
        conn.execute(
            """
            CREATE TABLE devices (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                device_id VARCHAR(255) NOT NULL UNIQUE,
                project_id BIGINT NOT NULL,
                model VARCHAR(255) NOT NULL,
                serial_number VARCHAR(255),
                current_version VARCHAR(255) NOT NULL,
                last_seen TIMESTAMP NULL DEFAULT NULL,
                is_active TINYINT(1) NOT NULL DEFAULT 1,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NULL DEFAULT NULL,
                CONSTRAINT fk_devices_project_id
                    FOREIGN KEY (project_id)
                    REFERENCES projects(id)
                    ON DELETE RESTRICT
                    ON UPDATE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX idx_devices_project_id
            ON devices(project_id)
            """
        )
        conn.execute(
            """
            CREATE UNIQUE INDEX idx_devices_serial_number
            ON devices(serial_number)
            """
        )

    def down(self, conn: typing.Any) -> None:
        conn.execute("DROP TABLE IF EXISTS devices")


migration = Migration_003()
