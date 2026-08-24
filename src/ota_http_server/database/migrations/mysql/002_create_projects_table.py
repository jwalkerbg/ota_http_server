import typing

from ota_http_server.database.migrations.migration import Migration


class Migration_002(Migration):
    version = 2
    description = "Create projects table"

    def up(self, conn: typing.Any) -> None:
        conn.execute(
            """
            CREATE TABLE projects (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                name VARCHAR(255) NOT NULL UNIQUE,
                display_name VARCHAR(255) NOT NULL,
                description TEXT,
                created_by BIGINT NOT NULL,
                is_active TINYINT(1) NOT NULL DEFAULT 1,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NULL DEFAULT NULL,
                CONSTRAINT fk_projects_created_by
                    FOREIGN KEY (created_by)
                    REFERENCES users(id)
                    ON DELETE RESTRICT
                    ON UPDATE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX idx_projects_created_by
            ON projects(created_by)
            """
        )

    def down(self, conn: typing.Any) -> None:
        conn.execute("DROP TABLE IF EXISTS projects")


migration = Migration_002()
