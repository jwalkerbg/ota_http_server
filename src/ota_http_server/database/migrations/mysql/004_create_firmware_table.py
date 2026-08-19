import typing

from ota_http_server.database.migrations.migration import Migration


class Migration_004(Migration):
    version = 4
    description = "Create firmware table"

    def up(self, conn: typing.Any) -> None:
        conn.execute(
            """
            CREATE TABLE firmware (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                project_id BIGINT NOT NULL,
                version VARCHAR(255) NOT NULL,
                filename VARCHAR(1024) NOT NULL,
                file_size BIGINT NOT NULL,
                checksum VARCHAR(255) NOT NULL,
                release_notes TEXT,
                channel VARCHAR(16) NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NULL DEFAULT NULL,
                CONSTRAINT chk_firmware_channel
                    CHECK (channel IN ('stable', 'beta', 'dev')),
                CONSTRAINT fk_firmware_project_id
                    FOREIGN KEY (project_id)
                    REFERENCES projects(id)
                    ON DELETE RESTRICT
                    ON UPDATE CASCADE,
                UNIQUE KEY uq_firmware_project_version_channel (project_id, version, channel)
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX idx_firmware_project_id
            ON firmware(project_id)
            """
        )
        conn.execute(
            """
            CREATE INDEX idx_firmware_project_channel
            ON firmware(project_id, channel)
            """
        )

    def down(self, conn: typing.Any) -> None:
        conn.execute("DROP TABLE IF EXISTS firmware")


migration = Migration_004()
