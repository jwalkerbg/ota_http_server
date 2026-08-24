import typing

from ota_http_server.database.migrations.migration import Migration


class Migration_007(Migration):
    version = 7
    description = "Add targets table and target foreign keys"

    def up(self, conn: typing.Any) -> None:
        conn.execute(
            """
            CREATE TABLE targets (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                name VARCHAR(255) NOT NULL UNIQUE
            )
            """
        )
        conn.execute(
            """
            INSERT INTO targets (name)
            VALUES ('Not defined')
            """
        )

        conn.execute("ALTER TABLE devices ADD COLUMN target_id BIGINT NULL AFTER project_id")
        conn.execute(
            """
            UPDATE devices
            SET target_id = (SELECT id FROM targets WHERE name = 'Not defined')
            """
        )
        conn.execute("ALTER TABLE devices MODIFY COLUMN target_id BIGINT NOT NULL")
        conn.execute(
            """
            ALTER TABLE devices
            ADD CONSTRAINT fk_devices_target_id
                FOREIGN KEY (target_id)
                REFERENCES targets(id)
                ON DELETE RESTRICT
                ON UPDATE CASCADE
            """
        )
        conn.execute(
            """
            CREATE INDEX idx_devices_target_id
            ON devices(target_id)
            """
        )

        conn.execute("ALTER TABLE firmware ADD COLUMN target_id BIGINT NULL AFTER project_id")
        conn.execute(
            """
            UPDATE firmware
            SET target_id = (SELECT id FROM targets WHERE name = 'Not defined')
            """
        )
        conn.execute("ALTER TABLE firmware MODIFY COLUMN target_id BIGINT NOT NULL")
        conn.execute(
            """
            ALTER TABLE firmware
            ADD CONSTRAINT fk_firmware_target_id
                FOREIGN KEY (target_id)
                REFERENCES targets(id)
                ON DELETE RESTRICT
                ON UPDATE CASCADE
            """
        )
        conn.execute(
            """
            CREATE INDEX idx_firmware_target_id
            ON firmware(target_id)
            """
        )
        conn.execute(
            """
            ALTER TABLE firmware DROP INDEX uq_firmware_project_version_channel
            """
        )
        conn.execute(
            """
            ALTER TABLE firmware
            ADD CONSTRAINT uq_firmware_project_version_target
                UNIQUE (project_id, version, target_id)
            """
        )

    def down(self, conn: typing.Any) -> None:
        conn.execute("ALTER TABLE firmware DROP INDEX uq_firmware_project_version_target")
        conn.execute(
            """
            ALTER TABLE firmware
            ADD CONSTRAINT uq_firmware_project_version_channel
                UNIQUE (project_id, version, channel)
            """
        )
        conn.execute("ALTER TABLE firmware DROP FOREIGN KEY fk_firmware_target_id")
        conn.execute("DROP INDEX idx_firmware_target_id ON firmware")
        conn.execute("ALTER TABLE firmware DROP COLUMN target_id")

        conn.execute("ALTER TABLE devices DROP FOREIGN KEY fk_devices_target_id")
        conn.execute("DROP INDEX idx_devices_target_id ON devices")
        conn.execute("ALTER TABLE devices DROP COLUMN target_id")

        conn.execute("DROP TABLE targets")


migration = Migration_007()
