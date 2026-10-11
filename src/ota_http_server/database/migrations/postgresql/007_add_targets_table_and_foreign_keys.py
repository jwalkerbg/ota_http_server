import typing

from ota_http_server.database.migrations.migration import Migration


class Migration_007(Migration):
    version = 7
    description = "Add targets table and target foreign keys"

    def up(self, conn: typing.Any) -> None:
        conn.execute(
            """
            CREATE TABLE targets (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
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

        for table in ("devices", "firmware"):
            conn.execute(f"ALTER TABLE {table} ADD COLUMN target_id BIGINT NULL")
            conn.execute(
                f"""
                UPDATE {table}
                SET target_id = (SELECT id FROM targets WHERE name = 'Not defined')
                """
            )
            conn.execute(f"ALTER TABLE {table} ALTER COLUMN target_id SET NOT NULL")
            conn.execute(
                f"""
                ALTER TABLE {table}
                ADD CONSTRAINT fk_{table}_target_id
                    FOREIGN KEY (target_id)
                    REFERENCES targets(id)
                    ON DELETE RESTRICT
                    ON UPDATE CASCADE
                """
            )
            conn.execute(
                f"""
                CREATE INDEX idx_{table}_target_id
                ON {table}(target_id)
                """
            )

        conn.execute(
            "ALTER TABLE firmware DROP CONSTRAINT uq_firmware_project_version_channel"
        )
        conn.execute(
            """
            ALTER TABLE firmware
            ADD CONSTRAINT uq_firmware_project_version_target
                UNIQUE (project_id, version, target_id)
            """
        )

    def down(self, conn: typing.Any) -> None:
        conn.execute(
            "ALTER TABLE firmware DROP CONSTRAINT uq_firmware_project_version_target"
        )
        conn.execute(
            """
            ALTER TABLE firmware
            ADD CONSTRAINT uq_firmware_project_version_channel
                UNIQUE (project_id, version, channel)
            """
        )

        for table in ("firmware", "devices"):
            conn.execute(f"ALTER TABLE {table} DROP CONSTRAINT fk_{table}_target_id")
            conn.execute(f"DROP INDEX idx_{table}_target_id")
            conn.execute(f"ALTER TABLE {table} DROP COLUMN target_id")

        conn.execute("DROP TABLE targets")


migration = Migration_007()
