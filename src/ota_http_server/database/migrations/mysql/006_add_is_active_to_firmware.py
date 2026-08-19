import typing

from ota_http_server.database.migrations.migration import Migration


class Migration_006(Migration):
    version = 6
    description = "Add is_active column to firmware table"

    def up(self, conn: typing.Any) -> None:
        conn.execute(
            """
            ALTER TABLE firmware
            ADD COLUMN is_active TINYINT(1) NOT NULL DEFAULT 0
            """
        )

    def down(self, conn: typing.Any) -> None:
        conn.execute(
            """
            ALTER TABLE firmware
            DROP COLUMN is_active
            """
        )


migration = Migration_006()
