import typing

from ota_http_server.database.migrations.migration import Migration


class Migration_001(Migration):
    version = 1
    description = "Create users table"

    def up(self, conn: typing.Any) -> None:
        conn.execute(
            """
            CREATE TABLE users (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                username VARCHAR(255) NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email VARCHAR(255) NOT NULL UNIQUE,
                role VARCHAR(32) NOT NULL,
                is_active BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMPTZ NULL DEFAULT NULL
            )
            """
        )

    def down(self, conn: typing.Any) -> None:
        conn.execute("DROP TABLE IF EXISTS users")


migration = Migration_001()
