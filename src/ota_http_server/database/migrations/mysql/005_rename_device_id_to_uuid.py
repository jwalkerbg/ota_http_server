import typing

from ota_http_server.database.migrations.migration import Migration


class Migration_005(Migration):
    version = 5
    description = "Rename devices.device_id to devices.uuid"

    def up(self, conn: typing.Any) -> None:
        conn.execute(
            "ALTER TABLE devices CHANGE COLUMN device_id uuid VARCHAR(255) NOT NULL"
        )

    def down(self, conn: typing.Any) -> None:
        conn.execute(
            "ALTER TABLE devices CHANGE COLUMN uuid device_id VARCHAR(255) NOT NULL"
        )


migration = Migration_005()
