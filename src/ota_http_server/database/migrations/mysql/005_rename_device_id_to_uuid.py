import typing

from ota_http_server.database.migrations.migration import Migration


class Migration_005(Migration):
    version = 5
    description = "Rename devices.device_id to devices.uuid"

    def up(self, conn: typing.Any) -> None:
        conn.execute(
            """
            ALTER TABLE devices
            RENAME COLUMN device_id TO uuid
            """
        )

    def down(self, conn: typing.Any) -> None:
        conn.execute(
            """
            ALTER TABLE devices
            RENAME COLUMN uuid TO device_id
            """
        )


migration = Migration_005()
