import typing

from ota_http_server.database.migrations.migration import Migration


class Migration_009(Migration):
    version = 9
    description = "Add user name and country"

    def up(self, conn: typing.Any) -> None:
        conn.execute("ALTER TABLE users ADD COLUMN name TEXT NOT NULL DEFAULT ''")
        conn.execute("ALTER TABLE users ADD COLUMN country VARCHAR(2) NOT NULL DEFAULT ''")

    def down(self, conn: typing.Any) -> None:
        conn.execute("ALTER TABLE users DROP COLUMN country")
        conn.execute("ALTER TABLE users DROP COLUMN name")


migration = Migration_009()
