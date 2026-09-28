import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from ota_http_server.core.config import Config
from ota_http_server.database.migration_mysql_runner import MigrationMySQLRunner, MigrationError
from ota_http_server.database.migration_sqlite3_runner import MigrationError as SQLiteMigrationError
from ota_http_server.database.migration_sqlite3_runner import MigrationRunner
from ota_http_server.database.db_sqlite_service import DatabaseSqliteService


def test_default_migration_paths_resolve_from_package_outside_repository(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = Config().config

    for backend in ("mysql", "sqlite"):
        migrations_dir = Path(cfg["database"][backend]["migrations_dir"])
        assert migrations_dir.is_dir()
        assert len(list(migrations_dir.glob("[0-9]*.py"))) == 8


def test_mysql_migration_runner_rejects_empty_migration_directory(tmp_path):
    cfg = SimpleNamespace(
        config={
            "database": {"mysql": {"migrations_dir": str(tmp_path)}},
            "parameters": {"init_db_migrate": True},
        }
    )
    runner = MigrationMySQLRunner(cfg)

    with pytest.raises(MigrationError, match="No MySQL migration files found"):
        runner.migrate_up()


def test_sqlite_migration_runner_rejects_empty_migration_directory(tmp_path):
    cfg = SimpleNamespace(
        config={
            "database": {"sqlite": {"migrations_dir": str(tmp_path)}},
            "parameters": {
                "app_paths": SimpleNamespace(database_sqlite=tmp_path / "ota.sqlite"),
                "init_db_migrate": True,
            },
        }
    )
    runner = MigrationRunner(cfg)

    with pytest.raises(SQLiteMigrationError, match="No SQLite migration files found"):
        runner.migrate_up()


def test_sqlite_connection_helpers_close_connections_on_exit(tmp_path):
    cfg = SimpleNamespace(
        config={
            "database": {"sqlite": {"migrations_dir": str(tmp_path)}},
            "parameters": {
                "app_paths": SimpleNamespace(database_sqlite=tmp_path / "ota.sqlite"),
                "trace_sql": False,
            },
        }
    )
    runners = (MigrationRunner(cfg), DatabaseSqliteService(cfg))

    for runner in runners:
        with runner._connect() as connection:
            assert connection.execute("SELECT 1").fetchone()[0] == 1

        with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
            connection.execute("SELECT 1")


def test_sqlite_migration_creates_targets_and_target_foreign_keys(tmp_path):
    cfg = SimpleNamespace()
    cfg.config = {
        "database": {
            "sqlite": {
                "migrations_dir": str(
                    Path("src")
                    / "ota_http_server"
                    / "database"
                    / "migrations"
                    / "sqlite"
                ),
            },
        },
        "parameters": {
            "app_paths": SimpleNamespace(database_sqlite=tmp_path / "ota.sqlite"),
            "init_db_migrate": True,
            "migrate_dry_run": False,
            "trace_sql": False,
        },
    }

    runner = MigrationRunner(cfg)
    runner.migrate_up()

    conn = sqlite3.connect(tmp_path / "ota.sqlite")
    try:
        target_row = conn.execute(
            "SELECT id, name FROM targets WHERE name = 'Not defined'"
        ).fetchone()
        assert target_row == (1, "Not defined")

        device_columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(devices)").fetchall()
        }
        firmware_columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(firmware)").fetchall()
        }
        assert "target_id" in device_columns
        assert "target_id" in firmware_columns

        device_foreign_keys = conn.execute("PRAGMA foreign_key_list(devices)").fetchall()
        firmware_foreign_keys = conn.execute("PRAGMA foreign_key_list(firmware)").fetchall()
        assert any(row[2] == "targets" and row[3] == "target_id" for row in device_foreign_keys)
        assert any(row[2] == "targets" and row[3] == "target_id" for row in firmware_foreign_keys)

        user_device_columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(users_devices)").fetchall()
        }
        assert user_device_columns == {"user_id", "device_id", "created_at", "expires_at"}
        user_device_foreign_keys = conn.execute(
            "PRAGMA foreign_key_list(users_devices)"
        ).fetchall()
        assert any(row[2] == "users" and row[3] == "user_id" for row in user_device_foreign_keys)
        assert any(row[2] == "devices" and row[3] == "device_id" for row in user_device_foreign_keys)

        conn.execute(
            """
            INSERT INTO users (username, password_hash, email, role, is_active)
            VALUES ('admin', 'hash', 'admin@example.com', 'admin', 1)
            """
        )
        conn.execute(
            """
            INSERT INTO projects (name, display_name, description, created_by, is_active)
            VALUES ('proj', 'Proj', '', 1, 1)
            """
        )
        conn.execute("INSERT INTO targets (name) VALUES ('ESP32-S3')")

        conn.execute(
            """
            INSERT INTO firmware (project_id, target_id, version, filename, file_size, checksum, channel, is_active)
            VALUES (1, 1, '1.2.0', 'fw-c3.bin', 10, 'sha-c3', 'stable', 1)
            """
        )
        conn.execute(
            """
            INSERT INTO firmware (project_id, target_id, version, filename, file_size, checksum, channel, is_active)
            VALUES (1, 2, '1.2.0', 'fw-s3.bin', 10, 'sha-s3', 'stable', 1)
            """
        )

        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO firmware (project_id, target_id, version, filename, file_size, checksum, channel, is_active)
                VALUES (1, 2, '1.2.0', 'fw-s3-duplicate.bin', 10, 'sha-s3-dup', 'beta', 1)
                """
            )

        conn.commit()
    finally:
        conn.close()
