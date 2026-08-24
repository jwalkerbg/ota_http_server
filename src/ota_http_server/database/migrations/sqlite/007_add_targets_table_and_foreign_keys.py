import sqlite3

from ota_http_server.database.migrations.migration import Migration


class Migration_007(Migration):
    version = 7
    description = "Add targets table and target foreign keys"

    def up(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE
            );
            """
        )
        conn.execute(
            """
            INSERT INTO targets (name)
            VALUES ('Not defined');
            """
        )

        conn.execute(
            """
            CREATE TABLE devices_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uuid TEXT NOT NULL UNIQUE,
                project_id INTEGER NOT NULL,
                target_id INTEGER NOT NULL,
                model TEXT NOT NULL,
                serial_number TEXT,
                current_version TEXT NOT NULL,
                last_seen TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT,
                FOREIGN KEY (project_id)
                    REFERENCES projects(id)
                    ON DELETE RESTRICT
                    ON UPDATE CASCADE,
                FOREIGN KEY (target_id)
                    REFERENCES targets(id)
                    ON DELETE RESTRICT
                    ON UPDATE CASCADE
            );
            """
        )
        conn.execute(
            """
            INSERT INTO devices_new (
                id,
                uuid,
                project_id,
                target_id,
                model,
                serial_number,
                current_version,
                last_seen,
                is_active,
                created_at,
                updated_at
            )
            SELECT
                id,
                uuid,
                project_id,
                (SELECT id FROM targets WHERE name = 'Not defined'),
                model,
                serial_number,
                current_version,
                last_seen,
                is_active,
                created_at,
                updated_at
            FROM devices;
            """
        )
        conn.execute("DROP TABLE devices;")
        conn.execute("ALTER TABLE devices_new RENAME TO devices;")
        conn.execute("CREATE INDEX idx_devices_project_id ON devices(project_id);")
        conn.execute("CREATE INDEX idx_devices_target_id ON devices(target_id);")
        conn.execute(
            """
            CREATE UNIQUE INDEX idx_devices_serial_number
            ON devices(serial_number)
            WHERE serial_number IS NOT NULL;
            """
        )

        conn.execute(
            """
            CREATE TABLE firmware_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                target_id INTEGER NOT NULL,
                version TEXT NOT NULL,
                filename TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                checksum TEXT NOT NULL,
                release_notes TEXT,
                channel TEXT NOT NULL
                    CHECK (channel IN ('stable', 'beta', 'dev')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT,
                is_active INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (project_id)
                    REFERENCES projects(id)
                    ON DELETE RESTRICT
                    ON UPDATE CASCADE,
                FOREIGN KEY (target_id)
                    REFERENCES targets(id)
                    ON DELETE RESTRICT
                    ON UPDATE CASCADE,
                UNIQUE (project_id, version, channel)
            );
            """
        )
        conn.execute(
            """
            INSERT INTO firmware_new (
                id,
                project_id,
                target_id,
                version,
                filename,
                file_size,
                checksum,
                release_notes,
                channel,
                created_at,
                updated_at,
                is_active
            )
            SELECT
                id,
                project_id,
                (SELECT id FROM targets WHERE name = 'Not defined'),
                version,
                filename,
                file_size,
                checksum,
                release_notes,
                channel,
                created_at,
                updated_at,
                is_active
            FROM firmware;
            """
        )
        conn.execute("DROP TABLE firmware;")
        conn.execute("ALTER TABLE firmware_new RENAME TO firmware;")
        conn.execute("CREATE INDEX idx_firmware_project_id ON firmware(project_id);")
        conn.execute("CREATE INDEX idx_firmware_project_channel ON firmware(project_id, channel);")
        conn.execute("CREATE INDEX idx_firmware_target_id ON firmware(target_id);")

    def down(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE devices_old (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uuid TEXT NOT NULL UNIQUE,
                project_id INTEGER NOT NULL,
                model TEXT NOT NULL,
                serial_number TEXT,
                current_version TEXT NOT NULL,
                last_seen TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT,
                FOREIGN KEY (project_id)
                    REFERENCES projects(id)
                    ON DELETE RESTRICT
                    ON UPDATE CASCADE
            );
            """
        )
        conn.execute(
            """
            INSERT INTO devices_old (
                id,
                uuid,
                project_id,
                model,
                serial_number,
                current_version,
                last_seen,
                is_active,
                created_at,
                updated_at
            )
            SELECT
                id,
                uuid,
                project_id,
                model,
                serial_number,
                current_version,
                last_seen,
                is_active,
                created_at,
                updated_at
            FROM devices;
            """
        )
        conn.execute("DROP TABLE devices;")
        conn.execute("ALTER TABLE devices_old RENAME TO devices;")
        conn.execute("CREATE INDEX idx_devices_project_id ON devices(project_id);")
        conn.execute(
            """
            CREATE UNIQUE INDEX idx_devices_serial_number
            ON devices(serial_number)
            WHERE serial_number IS NOT NULL;
            """
        )

        conn.execute(
            """
            CREATE TABLE firmware_old (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                version TEXT NOT NULL,
                filename TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                checksum TEXT NOT NULL,
                release_notes TEXT,
                channel TEXT NOT NULL
                    CHECK (channel IN ('stable', 'beta', 'dev')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT,
                is_active INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (project_id)
                    REFERENCES projects(id)
                    ON DELETE RESTRICT
                    ON UPDATE CASCADE,
                UNIQUE (project_id, version, channel)
            );
            """
        )
        conn.execute(
            """
            INSERT INTO firmware_old (
                id,
                project_id,
                version,
                filename,
                file_size,
                checksum,
                release_notes,
                channel,
                created_at,
                updated_at,
                is_active
            )
            SELECT
                id,
                project_id,
                version,
                filename,
                file_size,
                checksum,
                release_notes,
                channel,
                created_at,
                updated_at,
                is_active
            FROM firmware;
            """
        )
        conn.execute("DROP TABLE firmware;")
        conn.execute("ALTER TABLE firmware_old RENAME TO firmware;")
        conn.execute("CREATE INDEX idx_firmware_project_id ON firmware(project_id);")
        conn.execute("CREATE INDEX idx_firmware_project_channel ON firmware(project_id, channel);")

        conn.execute("DROP TABLE targets;")


migration = Migration_007()
