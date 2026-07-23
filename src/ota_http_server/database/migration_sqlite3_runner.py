# database/migration_sqlite3_runner.py

import sqlite3
import importlib.util
from pathlib import Path

class MigrationRunner:
    def __init__(self, db_file: str, migrations_dir: str):
        self.db_file = db_file
        self.migrations_dir = Path(migrations_dir)

    def _connect(self):
        conn = sqlite3.connect(self.db_file)
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _init_schema_table(self, conn):
        conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """)

    def _get_current_version(self, conn) -> int:
        row = conn.execute(
            "SELECT MAX(version) FROM schema_version"
        ).fetchone()
        return row[0] or 0

    def _load_migration(self, path: Path):
        spec = importlib.util.spec_from_file_location(path.stem, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def migrate_up(self):
        with self._connect() as conn:
            self._init_schema_table(conn)
            current_version = self._get_current_version(conn)

            for path in sorted(self.migrations_dir.glob("*.py")):
                version = int(path.stem.split("_")[0])

                if version <= current_version:
                    continue

                migration = self._load_migration(path)

                print(f"Applying migration {path.name}")
                migration.up(conn)

                conn.execute(
                    "INSERT INTO schema_version(version) VALUES (?)",
                    (version,)
                )

            conn.commit()

    def migrate_down(self):
        with self._connect() as conn:
            self._init_schema_table(conn)
            current_version = self._get_current_version(conn)

            if current_version == 0:
                print("No migrations to rollback")
                return

            migration_file = next(
                self.migrations_dir.glob(f"{current_version:03d}_*.py")
            )

            migration = self._load_migration(migration_file)

            print(f"Rolling back {migration_file.name}")
            migration.down(conn)

            conn.execute(
                "DELETE FROM schema_version WHERE version = ?",
                (current_version,)
            )

            conn.commit()
