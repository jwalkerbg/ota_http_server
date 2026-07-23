# database/migration_sqlite3_runner.py

import sqlite3
import importlib.util
from pathlib import Path

MIGRATIONS_DIR = Path("database/migrations")

def load_migration(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def init_schema_table(conn):
    conn.execute("""
    CREATE TABLE IF NOT EXISTS schema_version (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """)


def get_current_version(conn):
    row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
    return row[0] or 0


def migrate_up(db_file: str):
    with sqlite3.connect(db_file) as conn:
        init_schema_table(conn)
        current_version = get_current_version(conn)

        for path in sorted(MIGRATIONS_DIR.glob("*.py")):
            version = int(path.stem.split("_")[0])

            if version <= current_version:
                continue

            migration = load_migration(path)

            print(f"Applying migration {path.name}")
            migration.up(conn)

            conn.execute(
                "INSERT INTO schema_version(version) VALUES (?)",
                (version,)
            )

        conn.commit()

def migrate_down(db_file: str):
    with sqlite3.connect(db_file) as conn:
        current_version = get_current_version(conn)

        if current_version == 0:
            print("No migrations to rollback")
            return

        path = MIGRATIONS_DIR / f"{current_version:03d}_*.py"
        migration_file = list(MIGRATIONS_DIR.glob(path.name))[0]

        migration = load_migration(migration_file)

        print(f"Rolling back {migration_file.name}")
        migration.down(conn)

        conn.execute(
            "DELETE FROM schema_version WHERE version = ?",
            (current_version,)
        )

        conn.commit()
