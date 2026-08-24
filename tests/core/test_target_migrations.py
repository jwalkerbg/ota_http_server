import sqlite3
from pathlib import Path
from types import SimpleNamespace

from ota_http_server.database.migration_sqlite3_runner import MigrationRunner


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
    finally:
        conn.close()
